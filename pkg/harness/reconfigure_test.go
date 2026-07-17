package mcpharness

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBindingOpValidate(t *testing.T) {
	t.Parallel()

	good := scriptedBinding("github", ScopeSession, okTransport("github"))
	tests := []struct {
		name    string
		op      BindingOp
		wantErr string
	}{
		{name: "add", op: AddBinding(good)},
		{name: "replace", op: ReplaceBinding(good)},
		{name: "remove", op: RemoveBinding("github")},
		{name: "enable", op: EnableBinding("github")},
		{name: "disable", op: DisableBinding("github")},
		{name: "add with an invalid binding", op: AddBinding(Binding{Name: "x"}), wantErr: "add"},
		{name: "remove with an invalid name", op: RemoveBinding("Bad Name"), wantErr: "remove"},
		// A zero BindingOp is a caller who forgot the constructor. It must not
		// quietly become "add nothing".
		{name: "zero op", op: BindingOp{}, wantErr: "uninitialized BindingOp"},
		{name: "unknown kind", op: BindingOp{kind: opKind(200), name: "github"}, wantErr: "unknown BindingOp kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.op.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validate() = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestReconfigureValidatesBeforeApplying proves a batch with one malformed op
// changes nothing: a caller who mistyped a name must not find three servers
// already reconnected.
func TestReconfigureValidatesBeforeApplying(t *testing.T) {
	t.Parallel()

	added := okTransport("new")
	m := startedManager(t, scriptedBinding("docs", ScopeSession, okTransport("docs")))

	err := m.Reconfigure(context.Background(), []BindingOp{
		AddBinding(scriptedBinding("new", ScopeSession, added)),
		BindingOp{}, // malformed
	})
	if err == nil {
		t.Fatal("Reconfigure() = nil, want an error")
	}
	if got := added.dials.Load(); got != 0 {
		t.Errorf("the valid op dialed %d times, want 0: validation must precede application", got)
	}
	if got := names(m.sessionRoutes(loopA, "researcher")); !equal(got, []string{"docs"}) {
		t.Errorf("routes = %v, want [docs]: nothing should have been added", got)
	}
}

func TestReconfigureAddAndRemove(t *testing.T) {
	t.Parallel()

	m := startedManager(t, scriptedBinding("docs", ScopeSession, okTransport("docs")))
	ctx := context.Background()

	if err := m.Reconfigure(ctx, []BindingOp{
		AddBinding(scriptedBinding("wiki", ScopeSession, okTransport("wiki"))),
	}); err != nil {
		t.Fatalf("Reconfigure(add): %v", err)
	}
	if got, want := names(m.sessionRoutes(loopA, "researcher")), []string{"docs", "wiki"}; !equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}

	if err := m.Reconfigure(ctx, []BindingOp{RemoveBinding("wiki")}); err != nil {
		t.Fatalf("Reconfigure(remove): %v", err)
	}
	if got, want := names(m.sessionRoutes(loopA, "researcher")), []string{"docs"}; !equal(got, want) {
		t.Errorf("routes = %v, want %v: a removed binding is out of future generations", got, want)
	}
}

func TestReconfigureRejectsDuplicateAddAndMissingTarget(t *testing.T) {
	t.Parallel()

	m := startedManager(t, scriptedBinding("docs", ScopeSession, okTransport("docs")))
	ctx := context.Background()

	tests := []struct {
		name    string
		op      BindingOp
		wantErr string
	}{
		{name: "add an existing name", op: AddBinding(scriptedBinding("docs", ScopeSession, okTransport("docs"))), wantErr: "binding already exists"},
		{name: "remove an absent binding", op: RemoveBinding("nope"), wantErr: "binding does not exist"},
		{name: "replace an absent binding", op: ReplaceBinding(scriptedBinding("nope", ScopeSession, okTransport("nope"))), wantErr: "binding does not exist"},
		{name: "enable an absent binding", op: EnableBinding("nope"), wantErr: "binding does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.Reconfigure(ctx, []BindingOp{tt.op})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Reconfigure() = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestReconfigureDisableAndEnable(t *testing.T) {
	t.Parallel()

	first := okTransport("docs")
	m := startedManager(t, scriptedBinding("docs", ScopeSession, first))
	ctx := context.Background()

	if err := m.Reconfigure(ctx, []BindingOp{DisableBinding("docs")}); err != nil {
		t.Fatalf("Reconfigure(disable): %v", err)
	}
	if got := names(m.sessionRoutes(loopA, "researcher")); len(got) != 0 {
		t.Errorf("routes = %v, want none: a disabled binding is out of future generations", got)
	}
	// Its configuration survives, which is the whole difference from remove.
	byName := statusByName(m)
	if _, ok := byName["docs"]; !ok {
		t.Fatal("a disabled binding vanished from Status; an operator cannot see it to re-enable it")
	}
	if byName["docs"].Enabled {
		t.Error("a disabled binding reports Enabled")
	}
	waitClosed(t, first)

	if err := m.Reconfigure(ctx, []BindingOp{EnableBinding("docs")}); err != nil {
		t.Fatalf("Reconfigure(enable): %v", err)
	}
	if got, want := names(m.sessionRoutes(loopA, "researcher")), []string{"docs"}; !equal(got, want) {
		t.Errorf("routes = %v, want %v after enable", got, want)
	}
}

// TestReconfigureReplaceConnectsBeforeRetiring is design §Binding
// reconfiguration: "Replacing ... starts a new logical client before the old
// route is retired."
func TestReconfigureReplaceConnectsBeforeRetiring(t *testing.T) {
	t.Parallel()

	old := okTransport("docs-v1")
	next := okTransport("docs-v2")
	m := startedManager(t, scriptedBinding("docs", ScopeSession, old))

	if err := m.Reconfigure(context.Background(), []BindingOp{
		ReplaceBinding(scriptedBinding("docs", ScopeSession, next)),
	}); err != nil {
		t.Fatalf("Reconfigure(replace): %v", err)
	}
	if got := next.dials.Load(); got != 1 {
		t.Errorf("replacement dialed %d times, want 1", got)
	}
	if got, want := names(m.sessionRoutes(loopA, "researcher")), []string{"docs"}; !equal(got, want) {
		t.Fatalf("routes = %v, want %v", got, want)
	}
	// New calls must reach the replacement, and the prior connection must go.
	waitClosed(t, old)
	if got := m.Status()[0].Client.Server.Name; got != "docs-v2" {
		t.Errorf("route server = %q, want the replacement %q", got, "docs-v2")
	}
}

// TestReconfigureFailedReplaceKeepsPriorBinding is the default posture: a failed
// upgrade must not cost the server that was working.
func TestReconfigureFailedReplaceKeepsPriorBinding(t *testing.T) {
	t.Parallel()

	old := okTransport("docs-v1")
	m := startedManager(t, scriptedBinding("docs", ScopeSession, old))

	err := m.Reconfigure(context.Background(), []BindingOp{
		ReplaceBinding(scriptedBinding("docs", ScopeSession, &scriptedTransport{connectErr: errors.New("dial refused")})),
	})
	if err == nil {
		t.Fatal("Reconfigure() = nil, want the replacement's failure reported")
	}
	if !strings.Contains(err.Error(), "prior binding remains active") {
		t.Errorf("Reconfigure() = %v, want it to say the prior binding remains active", err)
	}
	if got, want := names(m.sessionRoutes(loopA, "researcher")), []string{"docs"}; !equal(got, want) {
		t.Fatalf("routes = %v, want %v: the prior binding must stay usable", got, want)
	}
	if got := old.conn.closes.Load(); got != 0 {
		t.Errorf("prior connection closed %d times, want 0", got)
	}
	if got := m.Status()[0].Client.Server.Name; got != "docs-v1" {
		t.Errorf("route server = %q, want the prior %q", got, "docs-v1")
	}
}

// TestReconfigureFailClosedReplaceRetiresPrior is the deliberate opposite: when
// a replacement exists to revoke something, a failure that left the old
// authority serving would be the failure.
func TestReconfigureFailClosedReplaceRetiresPrior(t *testing.T) {
	t.Parallel()

	old := okTransport("docs-v1")
	m := startedManager(t, scriptedBinding("docs", ScopeSession, old))

	err := m.Reconfigure(context.Background(), []BindingOp{
		ReplaceBinding(scriptedBinding("docs", ScopeSession, &scriptedTransport{connectErr: errors.New("dial refused")})).FailClosed(),
	})
	if err == nil {
		t.Fatal("Reconfigure() = nil, want the failure reported")
	}
	if !strings.Contains(err.Error(), "prior binding retired") {
		t.Errorf("Reconfigure() = %v, want it to say the prior binding was retired", err)
	}
	if got := names(m.sessionRoutes(loopA, "researcher")); len(got) != 0 {
		t.Errorf("routes = %v, want none: fail-closed must not leave the revoked binding serving", got)
	}
	waitClosed(t, old)
}

// TestFailClosedOnlyAffectsReplace proves the modifier is inert where there is
// no prior binding to keep.
func TestFailClosedOnlyAffectsReplace(t *testing.T) {
	t.Parallel()

	if got := AddBinding(scriptedBinding("x", ScopeSession, okTransport("x"))).FailClosed(); got.kind != opAdd {
		t.Errorf("FailClosed changed an add's kind to %v", got.kind)
	}
}

// TestRetirementDeadlineClosesAWedgedRoute proves an unreleased route does not
// keep a revoked binding alive forever (design §Binding reconfiguration: "or the
// configured retirement deadline cancels them").
func TestRetirementDeadlineClosesAWedgedRoute(t *testing.T) {
	t.Parallel()

	old := okTransport("docs")
	m := startedManager(t, scriptedBinding("docs", ScopeSession, old))
	m.retireIn = 100 * time.Millisecond

	// A turn takes the route and never gives it back.
	m.mu.Lock()
	bs := m.states["docs"]
	m.mu.Unlock()
	if _, ok := bs.acquire(); !ok {
		t.Fatal("acquire() failed on a live route")
	}

	if err := m.Reconfigure(context.Background(), []BindingOp{RemoveBinding("docs")}); err != nil {
		t.Fatalf("Reconfigure(remove): %v", err)
	}
	// The deadline, not the release, is what closes it.
	waitClosed(t, old)
}

func TestReconfigureOnAClosedManager(t *testing.T) {
	t.Parallel()

	m := startedManager(t, scriptedBinding("docs", ScopeSession, okTransport("docs")))
	if err := m.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := m.Reconfigure(context.Background(), []BindingOp{RemoveBinding("docs")})
	if !errors.Is(err, ErrManagerClosed) {
		t.Errorf("Reconfigure after Close = %v, want ErrManagerClosed", err)
	}
}

// --- helpers ---

// startedManager builds and starts a Manager whose bindings are all required,
// so Start's return means every one of them has settled.
func startedManager(t *testing.T, bindings ...Binding) *Manager {
	t.Helper()
	required := make([]Binding, 0, len(bindings))
	for _, b := range bindings {
		required = append(required, requiredBinding(b))
	}
	m, err := NewManager(required, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return m
}

// waitClosed waits for a transport's connection to be closed. Retirement is
// asynchronous by design — it outlives the Reconfigure that asked for it — so a
// test must wait for it rather than assert immediately.
func waitClosed(t *testing.T, tr *scriptedTransport) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if tr.conn != nil && tr.conn.closes.Load() > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the retired connection was never closed")
		case <-time.After(5 * time.Millisecond):
		}
	}
}
