package mcpharness

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/event"
	"github.com/looprig/harness/pkg/identity"
	"github.com/looprig/harness/pkg/loop"
	model "github.com/looprig/inference/model"
	"github.com/looprig/mcp/pkg/client"
)

// --- host doubles ---

// fakeSubscription is an event.Subscription a test drives by hand.
type fakeSubscription struct {
	events chan event.Delivery
	// keepOpen makes Close leave the events channel open, which is what a
	// subscription whose producer outlives it looks like. The Adopter must stop
	// on its own cancellation, not on a courtesy from its host.
	keepOpen bool

	mu     sync.Mutex
	closed bool
}

func (s *fakeSubscription) Events() <-chan event.Delivery { return s.events }
func (s *fakeSubscription) Err() error                    { return nil }

func (s *fakeSubscription) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		if !s.keepOpen {
			close(s.events)
		}
	}
	return nil
}

// fakeSource is an EventSource handing out one scriptable subscription.
type fakeSource struct {
	sub *fakeSubscription
	// filter records what the adapter asked for.
	filter event.EventFilter
	err    error
}

func (s *fakeSource) SubscribeEvents(f event.EventFilter) (event.Subscription, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.filter = f
	return s.sub, nil
}

// fakeInstaller is a loop.Controller that also installs external tools — the
// optional-interface shape a real loop handle has.
type fakeInstaller struct {
	id uuid.UUID
	// err, when set, is what ReplaceExternalTools returns.
	err error

	mu sync.Mutex
	// sets records every ACCEPTED toolset, so a test can tell what a Loop is
	// actually holding from what it was merely offered.
	sets []loop.ExternalToolset
	// offers counts every call, accepted or refused.
	offers int
}

func (f *fakeInstaller) ID() uuid.UUID       { return f.id }
func (f *fakeInstaller) Mode() loop.ModeName { return "" }
func (f *fakeInstaller) Model() model.Model  { return model.Model{} }

func (f *fakeInstaller) SetMode(context.Context, loop.ModeName) error { return nil }
func (f *fakeInstaller) Change(context.Context, ...loop.Change) error { return nil }
func (f *fakeInstaller) Interrupt(context.Context) error              { return nil }

func (f *fakeInstaller) ReplaceExternalTools(_ context.Context, set loop.ExternalToolset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.offers++
	if f.err != nil {
		return f.err
	}
	f.sets = append(f.sets, set)
	return nil
}

// installed returns the model-facing tool names of the most recent accepted
// toolset, or nil when the Loop holds nothing.
func (f *fakeInstaller) installed(t *testing.T) []string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sets) == 0 {
		return nil
	}
	var names []string
	for _, def := range f.sets[len(f.sets)-1].Definitions {
		names = append(names, def.ProducedToolNames()...)
	}
	return names
}

func (f *fakeInstaller) offerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.offers
}

func (f *fakeInstaller) acceptedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sets)
}

// plainController is a loop.Controller WITHOUT the installer capability — a
// Loop this host cannot install onto.
type plainController struct{ fakeInstaller }

// fakeLoops resolves controllers by Loop ID.
type fakeLoops struct {
	mu          sync.Mutex
	controllers map[uuid.UUID]loop.Controller
}

func (l *fakeLoops) LoopController(id uuid.UUID) (loop.Controller, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.controllers[id]
	return c, ok
}

func (l *fakeLoops) remove(id uuid.UUID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.controllers, id)
}

// --- harness ---

type adoptionFixture struct {
	m        *Manager
	adopter  *Adopter
	source   *fakeSource
	loops    *fakeLoops
	reporter *recordingReporter
}

// newAdoption wires a Manager, an Adopter, and a controller per Loop.
func newAdoption(t *testing.T, bindings []Binding, loopIDs ...uuid.UUID) (*adoptionFixture, map[uuid.UUID]*fakeInstaller) {
	t.Helper()
	reporter := &recordingReporter{}
	deps := testDeps()
	deps.Reporter = reporter
	m := managerWith(t, deps, bindings...)

	installers := make(map[uuid.UUID]*fakeInstaller, len(loopIDs))
	loops := &fakeLoops{controllers: make(map[uuid.UUID]loop.Controller, len(loopIDs))}
	for _, id := range loopIDs {
		fi := &fakeInstaller{id: id}
		installers[id] = fi
		loops.controllers[id] = fi
	}
	source := &fakeSource{sub: &fakeSubscription{events: make(chan event.Delivery, 8)}}
	a, err := m.StartAdoption(source, loops)
	if err != nil {
		t.Fatalf("StartAdoption: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return &adoptionFixture{m: m, adopter: a, source: source, loops: loops, reporter: reporter}, installers
}

// idle delivers a Loop's idle boundary the way the Session does, and waits for
// the adapter to have finished with it. Waiting is what makes the assertions
// deterministic: an idle is a notification, so the delivery returns long before
// the work does.
func (f *adoptionFixture) idle(t *testing.T, loopID uuid.UUID, done func() bool) {
	t.Helper()
	f.source.sub.events <- event.Delivery{Event: event.LoopIdle{
		Header: event.Header{Coordinates: identityOf(loopID)},
	}}
	waitFor(t, "the adopter to service the idle", done)
}

// TestAdopterSubscribesToEveryLoopsEnduringEvents guards the subscription
// itself: LoopIdle is enduring and loop-scoped, and a delegate spawned later
// must reach its boundary too.
func TestAdopterSubscribesToEveryLoopsEnduringEvents(t *testing.T) {
	t.Parallel()

	f, _ := newAdoption(t, []Binding{scriptedBinding("srv", ScopeSession, okTransport("srv", "do"))}, loopA)
	if !f.source.filter.Enduring.All {
		t.Errorf("filter = %+v, want every Loop's enduring events: LoopIdle is enduring and loop-scoped", f.source.filter)
	}
}

// TestEachLoopAdoptsAtItsOwnIdle is design §Catalog model's diagram, and the
// headline property of this stage.
//
// One binding publishes a validated candidate. Loop A reaches idle and adopts
// it; Loop B is still active and MUST go on holding the generation it has. B
// adopts later, at its own idle. Neither Loop waits for the other, and no Loop
// has its toolset changed at a moment it did not choose.
func TestEachLoopAdoptsAtItsOwnIdle(t *testing.T) {
	t.Parallel()

	tr := &scriptedTransport{conn: newScriptedConn("srv", fakeTool("original"))}
	f, installers := newAdoption(t, []Binding{scriptedBinding("srv", ScopeSession, tr)}, loopA, loopB)
	a, b := installers[loopA], installers[loopB]

	// Both Loops start on generation 1.
	ctx := context.Background()
	if err := f.adopter.Install(ctx, loopA, "primary"); err != nil {
		t.Fatalf("Install(A): %v", err)
	}
	if err := f.adopter.Install(ctx, loopB, "secondary"); err != nil {
		t.Fatalf("Install(B): %v", err)
	}
	if got := a.installed(t); len(got) != 1 || got[0] != "mcp__srv__original" {
		t.Fatalf("A holds %v, want [mcp__srv__original]", got)
	}

	// The server changes its tools. A candidate is validated and waiting.
	tr.conn.setTools(fakeTool("replacement"))
	notify(t, tr)
	m := f.m
	m.mu.Lock()
	cl := m.states["srv"].client()
	m.mu.Unlock()
	waitFor(t, "a validated candidate", func() bool { _, ok := cl.Candidate(); return ok })

	// Nothing has moved yet: a candidate is not an adoption.
	if got := a.installed(t); got[0] != "mcp__srv__original" {
		t.Errorf("A holds %v before any idle, want the original generation", got)
	}

	// Loop A parks. A adopts.
	f.idle(t, loopA, func() bool { return a.acceptedCount() == 2 })
	if got := a.installed(t); len(got) != 1 || got[0] != "mcp__srv__replacement" {
		t.Errorf("A holds %v after its idle, want [mcp__srv__replacement]", got)
	}

	// Loop B is still active, and MUST NOT have been touched. This is the whole
	// claim: adoption is per-Loop, at each Loop's own boundary.
	if b.acceptedCount() != 1 {
		t.Fatalf("B was replaced %d times while it was active, want 1 (its initial install)", b.acceptedCount())
	}
	if got := b.installed(t); len(got) != 1 || got[0] != "mcp__srv__original" {
		t.Errorf("B holds %v while active, want the generation it started under", got)
	}

	// B parks later. B adopts then, at its own boundary.
	f.idle(t, loopB, func() bool { return b.acceptedCount() == 2 })
	if got := b.installed(t); len(got) != 1 || got[0] != "mcp__srv__replacement" {
		t.Errorf("B holds %v after its own idle, want [mcp__srv__replacement]", got)
	}
}

// TestIdleWithNothingToChangeInstallsNothing is the churn guard: a Loop parks
// constantly, and a replacement is a durable journal record plus a rebuild of
// every tool. An idle that changes nothing must cost nothing.
func TestIdleWithNothingToChangeInstallsNothing(t *testing.T) {
	t.Parallel()

	f, installers := newAdoption(t, []Binding{scriptedBinding("srv", ScopeSession, okTransport("srv", "do"))}, loopA)
	a := installers[loopA]
	if err := f.adopter.Install(context.Background(), loopA, "primary"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	for range 3 {
		f.source.sub.events <- event.Delivery{Event: event.LoopIdle{
			Header: event.Header{Coordinates: identityOf(loopA)},
		}}
	}
	// Drain: the adopter is sequential, so a fourth idle it has serviced proves
	// it serviced the three before it.
	f.idle(t, loopA, func() bool { return true })
	time.Sleep(50 * time.Millisecond)

	if a.offerCount() != 1 {
		t.Errorf("the Loop was offered %d replacements, want 1: an idle with nothing to change must install nothing", a.offerCount())
	}
}

// TestFailedReplacementLeavesThePriorGenerationAndRetries is the design's "a
// failed replacement leaves the prior generation installed and reports the
// failure. It never produces a partially changed toolset."
//
// Recording the failed generation as installed would be the real bug: the Loop
// would be permanently stuck on the old toolset while the adapter believed it
// was current.
func TestFailedReplacementLeavesThePriorGenerationAndRetries(t *testing.T) {
	t.Parallel()

	tr := &scriptedTransport{conn: newScriptedConn("srv", fakeTool("original"))}
	f, installers := newAdoption(t, []Binding{scriptedBinding("srv", ScopeSession, tr)}, loopA)
	a := installers[loopA]
	if err := f.adopter.Install(context.Background(), loopA, "primary"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// The Loop refuses the next replacement (a declared-tool collision, say).
	a.mu.Lock()
	a.err = &loop.ChangeError{Kind: loop.ChangeExternalToolCollision, Tool: "mcp__srv__replacement"}
	a.mu.Unlock()

	tr.conn.setTools(fakeTool("replacement"))
	notify(t, tr)
	m := f.m
	m.mu.Lock()
	cl := m.states["srv"].client()
	m.mu.Unlock()
	waitFor(t, "a validated candidate", func() bool { _, ok := cl.Candidate(); return ok })

	f.idle(t, loopA, func() bool { return a.offerCount() == 2 })
	if got := a.installed(t); len(got) != 1 || got[0] != "mcp__srv__original" {
		t.Errorf("the Loop holds %v after a refused replacement, want the prior generation", got)
	}
	var failed bool
	for _, n := range f.reporter.snapshot() {
		if n.Kind == NoticeAdoptionFailed && n.LoopID == loopA {
			failed = true
		}
	}
	if !failed {
		t.Error("a refused replacement was not reported")
	}

	// The next boundary tries again: nothing was recorded as installed, so the
	// signature still differs.
	a.mu.Lock()
	a.err = nil
	a.mu.Unlock()
	f.idle(t, loopA, func() bool { return a.acceptedCount() == 2 })
	if got := a.installed(t); len(got) != 1 || got[0] != "mcp__srv__replacement" {
		t.Errorf("the Loop holds %v after the retry succeeded, want the new generation", got)
	}
}

// TestForeignLoopIsReportedOnceAndNeverRetried is the fail-gracefully rule.
//
// A foreign loop's toolset belongs to its foreign agent, and no retry will ever
// change that (loop.ChangeExternalToolsUnsupported). It must not hang, and it
// must not be rediscovered at every idle for the life of the Session.
func TestForeignLoopIsReportedOnceAndNeverRetried(t *testing.T) {
	t.Parallel()

	f, installers := newAdoption(t, []Binding{scriptedBinding("srv", ScopeSession, okTransport("srv", "do"))}, loopA)
	a := installers[loopA]
	a.err = &loop.ChangeError{Kind: loop.ChangeExternalToolsUnsupported}

	// An explicit caller is TOLD: it asked for an install, and "this Loop can
	// never host external tools" is exactly what it needs to branch on. The
	// boundary path ignores the same return, because an idle has nobody to
	// return anything to.
	err := f.adopter.Install(context.Background(), loopA, "primary")
	var change *loop.ChangeError
	if !errors.As(err, &change) || change.Kind != loop.ChangeExternalToolsUnsupported {
		t.Fatalf("Install = %v, want a typed ChangeExternalToolsUnsupported", err)
	}
	if a.offerCount() != 1 {
		t.Fatalf("offers = %d, want 1", a.offerCount())
	}

	var notices int
	for _, n := range f.reporter.snapshot() {
		if n.Kind == NoticeAdoptionUnsupported && n.LoopID == loopA {
			notices++
		}
	}
	if notices != 1 {
		t.Errorf("unsupported notices = %d, want exactly 1", notices)
	}

	// Every later boundary is a no-op: no build, no offer, no second report.
	f.idle(t, loopA, func() bool { return true })
	time.Sleep(50 * time.Millisecond)
	if a.offerCount() != 1 {
		t.Errorf("offers = %d after a second idle, want 1: a foreign loop must not be retried forever", a.offerCount())
	}
}

// TestLoopClosedConcurrentlyIsNotAFault covers the race the design implies but
// does not name: a Loop may close between the idle it emitted and the
// replacement this adapter is about to issue.
func TestLoopClosedConcurrentlyIsNotAFault(t *testing.T) {
	t.Parallel()

	f, _ := newAdoption(t, []Binding{scriptedBinding("srv", ScopeSession, okTransport("srv", "do"))}, loopA)
	f.loops.remove(loopA)

	if err := f.adopter.Install(context.Background(), loopA, "primary"); err != nil {
		t.Errorf("Install on a closed Loop = %v, want nil: a Loop closing is ordinary, not a fault", err)
	}
	for _, n := range f.reporter.snapshot() {
		if n.Kind == NoticeAdoptionFailed {
			t.Errorf("a closed Loop was reported as a failure: %+v", n)
		}
	}
}

// TestLoopWithoutTheInstallerCapabilityIsSkipped is the optional-interface
// contract: a Controller that does not implement loop.ExternalToolInstaller is
// a Loop this host cannot install onto, and the fail-closed answer is to
// install nothing rather than to assume.
func TestLoopWithoutTheInstallerCapabilityIsSkipped(t *testing.T) {
	t.Parallel()

	f, _ := newAdoption(t, []Binding{scriptedBinding("srv", ScopeSession, okTransport("srv", "do"))}, loopA)
	plain := &plainController{fakeInstaller{id: loopA}}
	f.loops.mu.Lock()
	// The embedded fakeInstaller carries the method set, so shadow it with a
	// controller that genuinely lacks the capability.
	f.loops.controllers[loopA] = struct {
		loop.Handle
		modeSetter
	}{Handle: plain, modeSetter: plain}
	f.loops.mu.Unlock()

	if err := f.adopter.Install(context.Background(), loopA, "primary"); err != nil {
		t.Errorf("Install = %v, want nil", err)
	}
	if plain.offerCount() != 0 {
		t.Error("a replacement was issued to a Loop without the installer capability")
	}
}

// modeSetter completes loop.Controller for the capability-less fixture above.
type modeSetter interface {
	SetMode(context.Context, loop.ModeName) error
	Change(context.Context, ...loop.Change) error
	Interrupt(context.Context) error
}

// TestGenerationSignatureIsDurableIdentity checks the identity recorded in the
// durable event.LoopExternalToolsetChanged: bounded (the installer refuses more
// than 128 bytes, and a Session may have more bindings than that lists), stable
// while nothing changes, and different once a catalog does.
func TestGenerationSignatureIsDurableIdentity(t *testing.T) {
	t.Parallel()

	tr := &scriptedTransport{conn: newScriptedConn("srv", fakeTool("original"))}
	f, installers := newAdoption(t, []Binding{scriptedBinding("srv", ScopeSession, tr)}, loopA)
	a := installers[loopA]
	if err := f.adopter.Install(context.Background(), loopA, "primary"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	a.mu.Lock()
	first := a.sets[0].Generation
	source := a.sets[0].Source
	a.mu.Unlock()

	if source != ToolSource {
		t.Errorf("Source = %q, want %q: a replacement must not touch another source's slot", source, ToolSource)
	}
	if first == "" {
		t.Fatal("Generation is empty; the installer refuses an unidentified toolset")
	}
	if len(first) > 128 {
		t.Errorf("Generation is %d bytes, want it bounded to 128", len(first))
	}

	tr.conn.setTools(fakeTool("replacement"))
	notify(t, tr)
	m := f.m
	m.mu.Lock()
	cl := m.states["srv"].client()
	m.mu.Unlock()
	waitFor(t, "a validated candidate", func() bool { _, ok := cl.Candidate(); return ok })
	f.idle(t, loopA, func() bool { return a.acceptedCount() == 2 })

	a.mu.Lock()
	second := a.sets[1].Generation
	a.mu.Unlock()
	if second == first {
		t.Error("the generation identity did not change across a catalog change: an operator could not tell which catalog a turn ran under")
	}
}

// TestAdoptionInstallsOnlyWhatTheLoopMaySee joins adoption to visibility: a
// replacement is the whole of a Loop's MCP slot, so building it from anything
// but that Loop's own permitted bindings would hand it another Loop's servers.
func TestAdoptionInstallsOnlyWhatTheLoopMaySee(t *testing.T) {
	t.Parallel()

	shared := okTransport("shared", "read")
	privateA := okTransport("private", "secret")
	bindings := []Binding{
		{
			Name:       "shared",
			Scope:      ScopeSession,
			Server:     clientDefinition("shared", shared),
			Visibility: AllLoops(),
		},
		{
			Name:   "private",
			Scope:  ScopeLoop,
			Loop:   loopA,
			Server: clientDefinition("private", privateA),
		},
	}
	f, installers := newAdoption(t, bindings, loopA, loopB)

	ctx := context.Background()
	if err := f.adopter.Install(ctx, loopA, "primary"); err != nil {
		t.Fatalf("Install(A): %v", err)
	}
	if err := f.adopter.Install(ctx, loopB, "delegate"); err != nil {
		t.Fatalf("Install(B): %v", err)
	}

	gotA := installers[loopA].installed(t)
	if len(gotA) != 2 {
		t.Errorf("A holds %v, want its own private binding and the shared one", gotA)
	}
	gotB := installers[loopB].installed(t)
	if len(gotB) != 1 || gotB[0] != "mcp__shared__read" {
		t.Errorf("B holds %v, want only the shared binding: a Loop never inherits another's private servers", gotB)
	}
}

// TestStartAdoptionValidatesItsSeams fails closed at construction: a nil seam
// discovered at the first boundary is a Session whose toolsets silently never
// update.
func TestStartAdoptionValidatesItsSeams(t *testing.T) {
	t.Parallel()

	m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, okTransport("srv", "do")))
	if _, err := m.StartAdoption(nil, &fakeLoops{}); err == nil {
		t.Error("StartAdoption with a nil source succeeded")
	}
	source := &fakeSource{sub: &fakeSubscription{events: make(chan event.Delivery, 1)}}
	if _, err := m.StartAdoption(source, nil); err == nil {
		t.Error("StartAdoption with nil loops succeeded")
	}
	failing := &fakeSource{err: errors.New("no subscription for you")}
	if _, err := m.StartAdoption(failing, &fakeLoops{}); err == nil {
		t.Error("StartAdoption succeeded though the subscription failed")
	}
}

// TestAdopterCloseStopsEvenAStubbornSubscription proves Close's claim: a caller
// that returns from Close knows no further replacement will be issued.
//
// The subscription here does NOT close its channel on Close — a producer may
// outlive its subscriber, and a hub is not obliged to hang up. So the Adopter
// must stop on its own cancellation. If it only stopped when its host closed
// the channel, Close would block on a goroutine that never returns and this
// test would time out rather than fail politely.
func TestAdopterCloseStopsEvenAStubbornSubscription(t *testing.T) {
	t.Parallel()

	reporter := &recordingReporter{}
	deps := testDeps()
	deps.Reporter = reporter
	m := managerWith(t, deps, scriptedBinding("srv", ScopeSession, okTransport("srv", "do")))
	installer := &fakeInstaller{id: loopA}
	loops := &fakeLoops{controllers: map[uuid.UUID]loop.Controller{loopA: installer}}
	stubborn := &fakeSource{sub: &fakeSubscription{events: make(chan event.Delivery, 4), keepOpen: true}}
	a, err := m.StartAdoption(stubborn, loops)
	if err != nil {
		t.Fatalf("StartAdoption: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- a.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked: the Adopter only stops when its host closes the channel, not on its own cancellation")
	}
	if err := a.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
	if installer.offerCount() != 0 {
		t.Error("a replacement was issued after Close")
	}
}

// TestAdopterCloseStops covers the ordinary teardown, where the subscription
// does hang up.
func TestAdopterCloseStops(t *testing.T) {
	t.Parallel()

	f, installers := newAdoption(t, []Binding{scriptedBinding("srv", ScopeSession, okTransport("srv", "do"))}, loopA)
	if err := f.adopter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := f.adopter.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
	if installers[loopA].offerCount() != 0 {
		t.Error("a replacement was issued after Close")
	}
}

// clientDefinition is scriptedBinding's Server, for the tests that build a
// Binding by hand.
func clientDefinition(name string, tr *scriptedTransport) client.Definition {
	return client.Definition{Name: client.Name(name), Transport: tr}
}

// identityOf builds the coordinates of a loop-scoped event.
func identityOf(loopID uuid.UUID) identity.Coordinates {
	return identity.Coordinates{SessionID: sessionID, LoopID: loopID}
}

// compile-time proof the fixture's controller really is one, in both the
// required and the optional half of what the adapter asserts at runtime.
var (
	_ loop.Controller            = (*fakeInstaller)(nil)
	_ loop.ExternalToolInstaller = (*fakeInstaller)(nil)
)
