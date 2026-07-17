package mcpharness

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/event"
	"github.com/looprig/mcp/pkg/client"
)

// stubGates answers nothing; the manager tests never elicit.
type stubGates struct{}

func (stubGates) OpenGate(context.Context, GateRequest) (GateResponse, error) {
	return GateResponse{}, errors.New("stubGates: no gate expected")
}

// recordingEvents collects published events.
type recordingEvents struct{}

func (recordingEvents) PublishEvent(context.Context, event.Event) error { return nil }

// testDeps is the Deps every test Manager is built with. sessionID (tools_test.go)
// is the Session they all belong to.
func testDeps() Deps {
	return Deps{SessionID: sessionID, Gates: stubGates{}, Events: recordingEvents{}}
}

// okTransport returns a transport whose handshake succeeds, serving one tool
// per name.
func okTransport(server string, tools ...string) *scriptedTransport {
	conn := newScriptedConn(server)
	for _, name := range tools {
		conn.tools = append(conn.tools, fakeTool(name))
	}
	return &scriptedTransport{conn: conn}
}

func TestNewManagerValidates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		bindings []Binding
		deps     Deps
		wantErr  string
	}{
		{
			name:     "valid",
			bindings: []Binding{scriptedBinding("github", ScopeSession, okTransport("github"))},
			deps:     testDeps(),
		},
		{
			name:     "nil gates",
			bindings: nil,
			deps:     Deps{SessionID: sessionID, Events: recordingEvents{}},
			wantErr:  "Deps.Gates is nil",
		},
		{
			name:     "nil events",
			bindings: nil,
			deps:     Deps{SessionID: sessionID, Gates: stubGates{}},
			wantErr:  "Deps.Events is nil",
		},
		// An event stamped with the zero Session is one the hub delivers to the
		// wrong subscribers, or ValidateEvent refuses outright. The Manager
		// cannot derive it, so it must be given it.
		{
			name:     "zero session id",
			bindings: nil,
			deps:     Deps{Gates: stubGates{}, Events: recordingEvents{}},
			wantErr:  "Deps.SessionID is zero",
		},
		{
			name:     "invalid binding",
			bindings: []Binding{{Name: "github", Scope: ScopeSession}},
			deps:     testDeps(),
			wantErr:  "bindings[0]",
		},
		// One name, two authorities: the model would see a single qualified
		// prefix standing for two different servers.
		{
			name: "duplicate binding names",
			bindings: []Binding{
				scriptedBinding("github", ScopeSession, okTransport("a")),
				scriptedBinding("github", ScopeSession, okTransport("b")),
			},
			deps:    testDeps(),
			wantErr: "duplicate binding name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := NewManager(tt.bindings, tt.deps)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewManager() = %v, want nil", err)
				}
				t.Cleanup(func() { _ = m.Close(context.Background()) })
				return
			}
			if err == nil {
				t.Fatalf("NewManager() = nil, want an error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewManager() = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestStartReadiesBindings(t *testing.T) {
	t.Parallel()

	// Required, because that is what Start waits for: an optional binding is
	// still connecting when Start returns (see
	// TestStartDoesNotWaitForOptionalBindings), so asserting readiness on one
	// would be asserting a race.
	m, err := NewManager([]Binding{
		requiredBinding(scriptedBinding("github", ScopeSession, okTransport("github", "search"))),
		requiredBinding(loopBinding("browser", loopA, okTransport("browser", "click"))),
	}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for _, st := range m.Status() {
		if st.Client.State != client.StateReady {
			t.Errorf("binding %q state = %v, want ready", st.Name, st.Client.State)
		}
	}
}

func TestStartIsIdempotentlyGuarded(t *testing.T) {
	t.Parallel()

	m, err := NewManager([]Binding{scriptedBinding("github", ScopeSession, okTransport("github"))}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Start(ctx); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("second Start = %v, want ErrAlreadyStarted", err)
	}
}

// TestStartAggregatesEveryRequiredFailure is the guard behind design §Required
// and optional servers: a user fixing configuration must see all of it at once.
// A first-wins report would name one server and hide the other two.
func TestStartAggregatesEveryRequiredFailure(t *testing.T) {
	t.Parallel()

	broken := func() *scriptedTransport {
		return &scriptedTransport{connectErr: errors.New("dial refused")}
	}
	bindings := []Binding{
		requiredBinding(scriptedBinding("alpha", ScopeSession, broken())),
		requiredBinding(scriptedBinding("bravo", ScopeSession, broken())),
		requiredBinding(scriptedBinding("charlie", ScopeSession, broken())),
	}
	m, err := NewManager(bindings, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = m.Start(ctx)
	var se *StartupError
	if !errors.As(err, &se) {
		t.Fatalf("Start() = %v, want a *StartupError", err)
	}
	if len(se.Failures) != 3 {
		t.Fatalf("Start() reported %d failures, want 3: %v", len(se.Failures), se.Failures)
	}
	// Deterministic order: a report read twice reads the same twice.
	for i, want := range []string{"alpha", "bravo", "charlie"} {
		if se.Failures[i].Binding != want {
			t.Errorf("Failures[%d].Binding = %q, want %q", i, se.Failures[i].Binding, want)
		}
	}
	msg := se.Error()
	for _, want := range []string{"alpha", "bravo", "charlie"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to name %q", msg, want)
		}
	}
}

// TestStartOptionalFailureDegradesOnlyItself proves an optional server that
// cannot connect leaves the owner usable and marks only its own binding.
func TestStartOptionalFailureDegradesOnlyItself(t *testing.T) {
	t.Parallel()

	m, err := NewManager([]Binding{
		requiredBinding(scriptedBinding("good", ScopeSession, okTransport("good"))),
		scriptedBinding("bad", ScopeSession, &scriptedTransport{connectErr: errors.New("dial refused")}),
	}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start() = %v, want nil: an optional failure must not fail the owner", err)
	}
	// Start deliberately does not wait for an optional binding, so wait for it
	// here rather than racing its settle.
	waitSettled(t, m, "bad")
	byName := statusByName(m)
	if got := byName["good"].Client.State; got != client.StateReady {
		t.Errorf("good state = %v, want ready", got)
	}
	if got := byName["bad"].Client.State; got != client.StateFailed {
		t.Errorf("bad state = %v, want failed", got)
	}
	if byName["bad"].Client.Failure == nil {
		t.Error("bad has no failure recorded; an operator cannot see why")
	}
}

// TestStartDoesNotWaitForOptionalBindings is design §Concurrent startup's first
// claim: one slow optional server must not delay startup. The optional binding
// here never connects at all, so a Start that waited for it would time out.
func TestStartDoesNotWaitForOptionalBindings(t *testing.T) {
	t.Parallel()

	hang := &scriptedTransport{conn: newScriptedConn("slow"), gate: make(chan struct{}), entered: make(chan struct{})}
	m, err := NewManager([]Binding{
		requiredBinding(scriptedBinding("fast", ScopeSession, okTransport("fast"))),
		scriptedBinding("slow", ScopeSession, hang),
	}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() {
		close(hang.gate)
		_ = m.Close(context.Background())
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start() = %v, want nil while an optional binding is still dialing", err)
	}
	// The slow binding really was dialing, so this proves Start returned past
	// live startup rather than past a binding that had already given up.
	select {
	case <-hang.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the slow binding never started dialing")
	}
}

// TestManagerIsReachableDuringStartup is design §Concurrent startup's second
// claim, and the reason every per-binding fact lives under the binding's own
// lock: "the owner publishes a reachable client-set handle before waiting for
// required servers ... callbacks must be routable while startup is still in
// progress". Initialization may itself trigger OAuth or elicitation, so a Start
// that held the binding table's lock across its wait would deadlock the very
// callback that would let it finish.
func TestManagerIsReachableDuringStartup(t *testing.T) {
	t.Parallel()

	hang := &scriptedTransport{conn: newScriptedConn("slow"), gate: make(chan struct{}), entered: make(chan struct{})}
	m, err := NewManager([]Binding{
		requiredBinding(scriptedBinding("slow", ScopeSession, hang)),
	}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	started := make(chan error, 1)
	go func() { started <- m.Start(context.Background()) }()

	select {
	case <-hang.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the binding never started dialing")
	}

	// Start is now blocked on a required binding. The Manager must still
	// answer, on this goroutine, without the dial having finished.
	reached := make(chan []BindingStatus, 1)
	go func() { reached <- m.Status() }()
	select {
	case st := <-reached:
		if len(st) != 1 {
			t.Fatalf("Status() returned %d bindings, want 1", len(st))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Status() blocked while Start was waiting: the Manager is not reachable during startup")
	}

	close(hang.gate)
	if err := <-started; err != nil {
		t.Fatalf("Start: %v", err)
	}
}

// TestStartDeadlineIsReported proves a required binding that never settles is
// reported rather than hanging Start forever.
func TestStartDeadlineIsReported(t *testing.T) {
	t.Parallel()

	hang := &scriptedTransport{conn: newScriptedConn("slow"), gate: make(chan struct{})}
	m, err := NewManager([]Binding{requiredBinding(scriptedBinding("slow", ScopeSession, hang))}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() {
		close(hang.gate)
		_ = m.Close(context.Background())
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err = m.Start(ctx)
	var se *StartupError
	if !errors.As(err, &se) {
		t.Fatalf("Start() = %v, want a *StartupError", err)
	}
	if len(se.Failures) != 1 || se.Failures[0].Class != client.FailureStartupTimeout {
		t.Errorf("Start() failures = %v, want one startup-timeout", se.Failures)
	}
}

func TestSessionRoutesEnforcesVisibility(t *testing.T) {
	t.Parallel()

	shared := scriptedBinding("docs", ScopeSession, okTransport("docs"))
	restricted := scriptedBinding("db", ScopeSession, okTransport("db"))
	restricted.Visibility = Named("researcher")
	private := loopBinding("browser", loopA, okTransport("browser"))

	m, err := NewManager([]Binding{shared, restricted, private}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	tests := []struct {
		name     string
		loopID   uuid.UUID
		loopName string
		want     []string
	}{
		{name: "researcher sees both shared bindings", loopID: loopA, loopName: "researcher", want: []string{"db", "docs"}},
		{name: "operator sees only the unrestricted one", loopID: loopB, loopName: "operator", want: []string{"docs"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := names(m.sessionRoutes(tt.loopID, tt.loopName)); !equal(got, tt.want) {
				t.Errorf("sessionRoutes = %v, want %v", got, tt.want)
			}
		})
	}

	// A Loop-scoped binding is never a session route, whatever the Loop is
	// called: it is not shared at all.
	if got := names(m.sessionRoutes(loopA, "parent")); contains(got, "browser") {
		t.Errorf("sessionRoutes(%v) = %v, want it to exclude the loop-scoped binding", loopA, got)
	}
}

// TestLoopRoutesDoNotInherit is design §Delegation: a child does not inherit its
// parent's Loop-scoped bindings. It holds by ownership, not by filtering — the
// delegate simply is not the owner.
func TestLoopRoutesDoNotInherit(t *testing.T) {
	t.Parallel()

	parent := loopBinding("browser", loopA, okTransport("browser"))
	delegate := loopBinding("db", loopB, okTransport("db"))

	m, err := NewManager([]Binding{parent, delegate}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	if got, want := names(m.loopRoutes(loopA)), []string{"browser"}; !equal(got, want) {
		t.Errorf("loopRoutes(parent) = %v, want %v", got, want)
	}
	if got, want := names(m.loopRoutes(loopB)), []string{"db"}; !equal(got, want) {
		t.Errorf("loopRoutes(delegate) = %v, want %v; a delegate must not inherit the parent's private binding", got, want)
	}
	if got := names(m.loopRoutes(loopC)); len(got) != 0 {
		t.Errorf("loopRoutes(unrelated) = %v, want none", got)
	}
}

func TestRoutesExcludeDisabledAndRetiring(t *testing.T) {
	t.Parallel()

	m, err := NewManager([]Binding{scriptedBinding("docs", ScopeSession, okTransport("docs"))}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := names(m.sessionRoutes(loopA, "researcher")); !equal(got, []string{"docs"}) {
		t.Fatalf("sessionRoutes = %v, want [docs]", got)
	}

	m.states["docs"].mu.Lock()
	m.states["docs"].retiring = true
	m.states["docs"].mu.Unlock()
	if got := names(m.sessionRoutes(loopA, "researcher")); len(got) != 0 {
		t.Errorf("sessionRoutes = %v, want none: a retiring binding is out of future generations", got)
	}
}

// TestCloseIsIdempotent covers Close's idempotence contract: a second Close
// returns nil, the connection is closed exactly once, and the Manager stays
// closed.
//
// Honest scope note: the connection-closed-once assertion does NOT exercise the
// Manager's own m.closed guard. client.Close is idempotent on its own
// (closeOnce), so that assertion passes with the guard removed — a mutation test
// confirmed it. The guard is kept deliberately as a contract that does not rest
// on every downstream Close happening to be idempotent, and what this test
// genuinely pins is the observable behavior: nil, once, and closed-stays-closed.
func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	tr := okTransport("docs")
	m, err := NewManager([]Binding{scriptedBinding("docs", ScopeSession, tr)}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx := context.Background()
	if err := m.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := m.Close(ctx); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if got := tr.conn.closes.Load(); got != 1 {
		t.Errorf("connection closed %d times, want 1", got)
	}
	if err := m.Start(ctx); !errors.Is(err, ErrManagerClosed) {
		t.Errorf("Start after Close = %v, want ErrManagerClosed", err)
	}
}

// TestCloseCancelsStartup proves shutdown does not wait for a dial that will
// never finish (design §Shutdown: shutdown cancels startup).
func TestCloseCancelsStartup(t *testing.T) {
	t.Parallel()

	hang := &scriptedTransport{conn: newScriptedConn("slow"), gate: make(chan struct{}), entered: make(chan struct{})}
	m, err := NewManager([]Binding{requiredBinding(scriptedBinding("slow", ScopeSession, hang))}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	started := make(chan error, 1)
	go func() { started <- m.Start(context.Background()) }()
	select {
	case <-hang.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the binding never started dialing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-started:
		if err == nil {
			t.Error("Start() = nil after Close cancelled it, want a failure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start never returned: Close did not cancel startup")
	}
}

// TestCloseLoopClosesOnlyThatLoopsBindings is design §Shutdown: "Loop shutdown
// closes that Loop's clients. Closing a parent Loop does not close independent
// delegate bindings." It holds by ownership — a delegate's binding names the
// delegate as owner, so a parent's shutdown never reaches it.
func TestCloseLoopClosesOnlyThatLoopsBindings(t *testing.T) {
	t.Parallel()

	parentTr, delegateTr, sharedTr := okTransport("browser"), okTransport("db"), okTransport("docs")
	parent := loopBinding("browser", loopA, parentTr)
	delegate := loopBinding("db", loopB, delegateTr)
	shared := scriptedBinding("docs", ScopeSession, sharedTr)

	m, err := NewManager([]Binding{parent, delegate, shared}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := m.CloseLoop(context.Background(), loopA); err != nil {
		t.Fatalf("CloseLoop: %v", err)
	}
	if got := parentTr.conn.closes.Load(); got != 1 {
		t.Errorf("parent's own binding closed %d times, want 1", got)
	}
	if got := delegateTr.conn.closes.Load(); got != 0 {
		t.Errorf("delegate's binding closed %d times, want 0: closing a parent must not close an independent delegate binding", got)
	}
	if got := sharedTr.conn.closes.Load(); got != 0 {
		t.Errorf("session-scoped binding closed %d times, want 0: the Session owns it", got)
	}
	if got := names(m.loopRoutes(loopA)); len(got) != 0 {
		t.Errorf("loopRoutes(parent) = %v after CloseLoop, want none", got)
	}
}

func TestCloseLoopRejectsZeroLoop(t *testing.T) {
	t.Parallel()

	m, err := NewManager(nil, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	if err := m.CloseLoop(context.Background(), uuid.UUID{}); err == nil {
		t.Error("CloseLoop(zero) = nil, want an error: a zero Loop would match every session binding's zero owner")
	}
}

// TestCloseEventuallyClosesLoopScopedClients is design §Shutdown's last clause:
// "Session shutdown eventually closes all remaining Loop-scoped clients."
func TestCloseEventuallyClosesLoopScopedClients(t *testing.T) {
	t.Parallel()

	loopTr := okTransport("browser")
	b := loopBinding("browser", loopA, loopTr)
	m, err := NewManager([]Binding{b}, testDeps())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := loopTr.conn.closes.Load(); got != 1 {
		t.Errorf("loop-scoped connection closed %d times, want 1", got)
	}
}

// TestAcquireBlocksRetiringRoute proves a new call cannot start on a route that
// is on its way out, while one already holding it keeps it.
func TestAcquireBlocksRetiringRoute(t *testing.T) {
	t.Parallel()

	bs := newBindingState(scriptedBinding("docs", ScopeSession, okTransport("docs")))
	bs.cl = &client.Client{}

	held, ok := bs.acquire()
	if !ok || held == nil {
		t.Fatal("acquire() on a live route failed")
	}
	idle := bs.markRetiring()
	select {
	case <-idle:
		t.Fatal("markRetiring reported idle while a turn still holds the route")
	default:
	}
	if _, ok := bs.acquire(); ok {
		t.Error("acquire() succeeded on a retiring route; a new call must not start on it")
	}
	bs.release()
	select {
	case <-idle:
	case <-time.After(time.Second):
		t.Fatal("releasing the last reference did not report the route idle")
	}
}

func TestMarkRetiringOnAnIdleRouteIsImmediate(t *testing.T) {
	t.Parallel()

	bs := newBindingState(scriptedBinding("docs", ScopeSession, okTransport("docs")))
	bs.cl = &client.Client{}
	select {
	case <-bs.markRetiring():
	case <-time.After(time.Second):
		t.Fatal("a route nobody holds was not reported idle")
	}
}

// --- helpers ---

// waitSettled blocks until a binding's first connect attempt has finished. It
// exists because Start returns without waiting for optional bindings, so a test
// asserting on one must synchronize on the attempt rather than on Start.
func waitSettled(t *testing.T, m *Manager, name string) {
	t.Helper()
	m.mu.Lock()
	bs := m.states[client.Name(name)]
	m.mu.Unlock()
	if bs == nil {
		t.Fatalf("no binding %q", name)
	}
	select {
	case <-bs.ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("binding %q never settled", name)
	}
}

// loopBinding builds a loop-scoped binding owned by loopID.
func loopBinding(name string, loopID uuid.UUID, tr *scriptedTransport) Binding {
	b := scriptedBinding(name, ScopeLoop, tr)
	b.Loop = loopID
	return b
}

func requiredBinding(b Binding) Binding {
	b.Required = true
	return b
}

func names(states []*bindingState) []string {
	out := make([]string, 0, len(states))
	for _, bs := range states {
		out = append(out, bs.binding.Name)
	}
	return out
}

func statusByName(m *Manager) map[string]BindingStatus {
	out := map[string]BindingStatus{}
	for _, st := range m.Status() {
		out[st.Name] = st
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
