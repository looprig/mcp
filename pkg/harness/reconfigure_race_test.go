package mcpharness

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/looprig/mcp/pkg/client"
)

// The probes below pin the two halves of the client-set lifecycle bug in
// applyReplace: a replacement whose dial completes after its install was
// abandoned must be CLOSED, never leaked, and a slow replacement must never
// resurrect a binding a concurrent remove revoked nor install into a closed
// Manager. Each is written so reverting the guard it targets makes it fail
// (mutation notes on each test).

// stateOf returns the bindingState currently installed under a name, or nil.
func stateOf(m *Manager, name string) *bindingState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[client.Name(name)]
}

// TestReplacementAbandonedByCallerTimeoutIsClosed is Half A, the dominant leak:
// a replacement whose dial outlives a caller that gave up (its reconfigure
// deadline expired) settles a LIVE client with no owner. It must be closed even
// though Manager.Close is never called.
//
// Mutation: neuter guardReplacement (drop the <-next.ready / cl.Close, or delete
// the whole guardian) and this fails — next.conn.closes stays 0, the exact leak
// the report showed ("replacement.dials=1 replacement.closes=0").
func TestReplacementAbandonedByCallerTimeoutIsClosed(t *testing.T) {
	t.Parallel()

	m := startedManager(t, scriptedBinding("docs", ScopeSession, okTransport("docs-v1")))
	prior := stateOf(m, "docs")

	// The replacement's dial blocks on the gate, so the caller's short deadline
	// expires while it is still connecting.
	nextTr := &scriptedTransport{conn: newScriptedConn("docs-v2"), gate: make(chan struct{}), entered: make(chan struct{})}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := m.Reconfigure(ctx, []BindingOp{ReplaceBinding(scriptedBinding("docs", ScopeSession, nextTr))})
	if err == nil {
		t.Fatal("Reconfigure() = nil, want the caller-deadline failure")
	}
	if !strings.Contains(err.Error(), "prior binding remains active") {
		t.Errorf("Reconfigure() = %v, want it to report the prior binding remains active", err)
	}

	// The prior route is untouched: a caller giving up must not cost the server.
	if got := stateOf(m, "docs"); got != prior {
		t.Errorf("docs slot changed to %p, want the prior %p: an abandoned replace must not alter the route", got, prior)
	}

	// The dial started, and is still parked on the gate.
	select {
	case <-nextTr.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the replacement never started dialing")
	}

	// Now let the abandoned dial complete on the Manager's context. It settles a
	// live client that no caller will ever install; the guardian must close it —
	// without any Manager.Close.
	close(nextTr.gate)
	waitClosed(t, nextTr)
	if got := nextTr.dials.Load(); got != 1 {
		t.Errorf("replacement dialed %d times, want 1", got)
	}
	if got := nextTr.conn.closes.Load(); got != 1 {
		t.Errorf("orphaned replacement closed %d times, want 1: a connected-after-timeout client leaked", got)
	}
}

// TestCloseRefusesAndClosesAConnectedReplacement is requirement 2's Close arm
// and requirement 3: a replacement that connected a LIVE client but whose
// Manager closed before it installed must not install into the closed Manager
// (its workers run independent of the lifetime context, so an installed-late
// client leaks), and that live client must be closed. Close waits for the
// guardian, so the client is closed before Close returns.
//
// The afterReplaceConnect hook lands the Close in the one window the install
// decision must survive: after the dial settled a live client (on the still-live
// lifetime context) and before the install decision reads it. Without it this
// race is nearly unobservable, because once Close cancels the lifetime context a
// fresh dial self-cleans on the way up — so the hook is what makes the guard
// testable at all.
//
// Mutations, each caught here:
//   - drop `!m.closed` from the install guard → next installs its live client
//     into the closed Manager after Close's snapshot; it leaks (closes==0) and
//     the docs slot becomes next rather than the prior.
//   - neuter guardReplacement → the live client is never closed (closes==0).
func TestCloseRefusesAndClosesAConnectedReplacement(t *testing.T) {
	t.Parallel()

	priorTr := okTransport("docs-v1")
	m := startedManager(t, scriptedBinding("docs", ScopeSession, priorTr))
	prior := stateOf(m, "docs")

	// The replacement dials on the gate; the test releases it so the dial settles
	// a live client while the lifetime context is still live.
	nextTr := &scriptedTransport{conn: newScriptedConn("docs-v2"), gate: make(chan struct{}), entered: make(chan struct{})}

	closeDone := make(chan error, 1)
	m.afterReplaceConnect = func() {
		// The replacement has connected a live client. Land a Close now, and do
		// not let the install decision proceed until the Manager has committed to
		// closing (closed set, lifetime context cancelled).
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			closeDone <- m.Close(ctx)
		}()
		<-m.ctx.Done()
	}

	repDone := make(chan error, 1)
	go func() {
		repDone <- m.Reconfigure(context.Background(), []BindingOp{ReplaceBinding(scriptedBinding("docs", ScopeSession, nextTr))})
	}()

	select {
	case <-nextTr.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the replacement never started dialing")
	}
	// Let the replacement connect a live client; the hook then lands the Close.
	close(nextTr.gate)

	if err := <-repDone; err == nil {
		t.Error("Reconfigure(replace) = nil, want it refused: the Manager closed before it could install")
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The replacement connected a live client (dials==1), Close refused the
	// install, and the guardian closed the live client before Close returned.
	if got := nextTr.dials.Load(); got != 1 {
		t.Fatalf("replacement dialed %d times, want 1: the probe must exercise a live connect", got)
	}
	if got := stateOf(m, "docs"); got != prior {
		t.Errorf("docs slot = %p, want the prior %p: a replacement must not install into a closed Manager", got, prior)
	}
	if got := nextTr.conn.closes.Load(); got != 1 {
		t.Errorf("connected replacement closed %d times, want 1: its live client leaked past Close", got)
	}
	if got := priorTr.conn.closes.Load(); got != 1 {
		t.Errorf("prior connection closed %d times, want 1: Close must close the installed route", got)
	}
}

// TestRemoveRacingSlowReplaceDoesNotResurrect is Half B, the security-relevant
// one: a slow ReplaceBinding racing a RemoveBinding must not undo the removal. A
// remove can be a revocation; a late replace returning success and reinstalling
// the binding silently restores a revoked authority.
//
// Mutation: drop the identity check (`m.states[op.name] == prior`) from the
// install guard and this fails exactly as the report's probe showed — the
// removed "docs" is back in m.states, and the resurrected client is not closed.
func TestRemoveRacingSlowReplaceDoesNotResurrect(t *testing.T) {
	t.Parallel()

	priorTr := okTransport("docs-v1")
	m := startedManager(t, scriptedBinding("docs", ScopeSession, priorTr))

	// The replacement dials slowly (parked on the gate) so the remove wins.
	nextTr := &scriptedTransport{conn: newScriptedConn("docs-v2"), gate: make(chan struct{}), entered: make(chan struct{})}

	repDone := make(chan error, 1)
	go func() {
		repDone <- m.Reconfigure(context.Background(), []BindingOp{ReplaceBinding(scriptedBinding("docs", ScopeSession, nextTr))})
	}()

	select {
	case <-nextTr.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the replacement never started dialing")
	}

	// The remove completes while the replacement is still dialing.
	if err := m.Reconfigure(context.Background(), []BindingOp{RemoveBinding("docs")}); err != nil {
		t.Fatalf("Reconfigure(remove): %v", err)
	}
	if got := stateOf(m, "docs"); got != nil {
		t.Fatalf("docs still present after remove: %p", got)
	}

	// Now let the replacement finish connecting. It must NOT reinstall docs.
	close(nextTr.gate)
	repErr := <-repDone
	if repErr == nil {
		t.Fatal("Reconfigure(replace) = nil, want it refused: the binding was removed while it dialed")
	}
	if !strings.Contains(repErr.Error(), "removed") {
		t.Errorf("Reconfigure(replace) = %v, want it to report the binding was removed", repErr)
	}
	if got := stateOf(m, "docs"); got != nil {
		t.Errorf("RESURRECTION: docs is back in m.states (%p) after a remove; the revocation was silently undone", got)
	}

	// The late replacement's live client is closed, not leaked.
	waitClosed(t, nextTr)
	if got := nextTr.conn.closes.Load(); got != 1 {
		t.Errorf("late replacement closed %d times, want 1", got)
	}
	// The removed prior is retired and closed.
	waitClosed(t, priorTr)
}
