// These tests exercise the scheduler through the Client, at the boundary that
// matters: the connection. internal/sched's own tests prove the admission logic;
// these prove the client actually routes its requests through it, with the class
// each one deserves. A client that dropped the scheduler entirely passes every
// test in internal/sched and fails every test here.

package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
)

// probeWindow is how long a probing CallTool lingers waiting for a concurrent
// sibling. It is paid once per call that really is alone, and not at all by
// calls that really do overlap — so a correct-by-parallelism test is instant and
// a correct-by-serialization test costs the window per call.
const probeWindow = 25 * time.Millisecond

// probingConn returns a conn whose CallTool waits for n calls to be in flight
// together (up to window), so that a client which fails to serialize — or fails
// to bound — is observed doing it rather than merely permitted to.
func probingConn(n int32, window time.Duration) *fakeConn {
	conn := okConn()
	conn.callProbeN = n
	conn.callProbeWindow = window
	return conn
}

// callTool runs a tool call and reports its error, for tests that only care that
// it happened.
func callTool(t *testing.T, c *Client) error {
	t.Helper()
	_, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
	return err
}

// TestCallToolsSerializeByDefault: the design's default for a shared connection.
// Two Loops calling one binding do not get two concurrent tool calls unless the
// application said the server can take them.
func TestCallToolsSerializeByDefault(t *testing.T) {
	t.Parallel()

	const calls = 4

	// Each call lingers, waiting for a sibling to join it. A client with no
	// serialization would let all four in at once and be caught; a client that
	// serializes leaves each one waiting alone.
	conn := probingConn(2, probeWindow)
	tr := newFakeTransport(conn)
	def := okDefinition(tr) // AllowParallelCalls is not set
	// A budget well above the call count, so that anything observed here is the
	// serialization and not the bound.
	def.Limits.MaxConcurrentRequests = 8

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	var wg sync.WaitGroup
	for range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := callTool(t, c); err != nil {
				t.Errorf("CallTool() error = %v", err)
			}
		}()
	}
	wg.Wait()

	if got := conn.maxLive.Load(); got != 1 {
		t.Errorf("concurrent tool calls on the connection = %d, want 1: calls must serialize by default", got)
	}
	if got := len(conn.callNames()); got != calls {
		t.Errorf("tool calls that reached the server = %d, want %d: serializing must not drop calls", got, calls)
	}
}

// TestAllowParallelCallsOptsIn: the flag is the application's, and it works.
// The barrier makes this fail (on its deadline) rather than pass vacuously if
// the client serialized the calls anyway.
func TestAllowParallelCallsOptsIn(t *testing.T) {
	t.Parallel()

	const parallel = 4

	// A generous window: it is only ever paid by a client that fails to run
	// these in parallel, and such a client fails the assertion below anyway.
	conn := probingConn(parallel, 2*time.Second)
	tr := newFakeTransport(conn)
	def := okDefinition(tr)
	def.AllowParallelCalls = true
	def.Limits.MaxConcurrentRequests = parallel

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	var wg sync.WaitGroup
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := c.CallTool(ctx, "echo", nil, CallOpts{}); err != nil {
				t.Errorf("CallTool() error = %v (a serialized client cannot clear the barrier)", err)
			}
		}()
	}
	wg.Wait()

	if got := conn.maxLive.Load(); got != parallel {
		t.Errorf("concurrent tool calls = %d, want %d with AllowParallelCalls", got, parallel)
	}
}

// TestMaxConcurrentRequestsBoundsParallelCalls: the design's rule that the
// per-binding limit applies even when parallelism is enabled. Opting in raises
// the serialization constraint, never the budget.
func TestMaxConcurrentRequestsBoundsParallelCalls(t *testing.T) {
	t.Parallel()

	const budget = 2

	// Each call waits for a third concurrent sibling: one more than the budget
	// permits, so it never arrives on a client that honors the bound — and
	// arrives at once on a client that does not.
	conn := probingConn(budget+1, probeWindow)
	tr := newFakeTransport(conn)
	def := okDefinition(tr)
	def.AllowParallelCalls = true
	def.Limits.MaxConcurrentRequests = budget

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := callTool(t, c); err != nil {
				t.Errorf("CallTool() error = %v", err)
			}
		}()
	}
	wg.Wait()

	if got := conn.maxLive.Load(); got > budget {
		t.Errorf("concurrent tool calls = %d, want at most MaxConcurrentRequests (%d)", got, budget)
	}
}

// TestCancelOneCallLeavesOthersRunning is the design's isolation rule at the
// client's own boundary: cancelling one request must not cancel unrelated calls
// on the same connection.
func TestCancelOneCallLeavesOthersRunning(t *testing.T) {
	t.Parallel()

	conn := okConn()
	// Every call blocks until the test releases it, so both are genuinely in
	// flight when one is cancelled.
	conn.callReleased = make(chan struct{})
	tr := newFakeTransport(conn)
	def := okDefinition(tr)
	def.AllowParallelCalls = true
	def.Limits.MaxConcurrentRequests = 4

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	victimCtx, cancelVictim := context.WithCancel(context.Background())
	victim := make(chan error, 1)
	go func() {
		_, err := c.CallTool(victimCtx, "echo", nil, CallOpts{})
		victim <- err
	}()

	bystander := make(chan error, 1)
	go func() {
		_, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
		bystander <- err
	}()

	// Both are inside the conn's CallTool.
	waitFor(t, "both calls to be in flight", func() bool { return conn.live.Load() == 2 })

	cancelVictim()
	select {
	case err := <-victim:
		if class, ok := ClassOf(err); !ok || class != FailureCancelled {
			t.Errorf("the cancelled call: error = %v (class %v), want FailureCancelled", err, class)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled call never returned")
	}

	// The bystander is untouched: still in flight, and it completes normally
	// once the server answers.
	select {
	case err := <-bystander:
		t.Fatalf("an unrelated call returned (error = %v) when another was cancelled", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(conn.callReleased)
	select {
	case err := <-bystander:
		if err != nil {
			t.Errorf("the unrelated call: error = %v, want it to complete normally", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the unrelated call never completed")
	}
}

// TestCancelOneCallReleasesItsSlot: a cancelled call must not leave its slot
// behind. A binding that leaked a slot per cancellation would strangle itself
// silently — the failure would show up much later, as calls that mysteriously
// queue.
func TestCancelOneCallReleasesItsSlot(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.callReleased = make(chan struct{})
	tr := newFakeTransport(conn)
	def := okDefinition(tr)
	def.Limits.MaxConcurrentRequests = 1

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	// Occupy the binding's only slot, then cancel it.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := c.CallTool(ctx, "echo", nil, CallOpts{}); err == nil {
			t.Error("the cancelled call reported success")
		}
	}()
	waitFor(t, "the call to be in flight", func() bool { return conn.live.Load() == 1 })
	cancel()
	<-done

	// The slot is back: a later call gets it rather than waiting forever.
	close(conn.callReleased)
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	if _, err := c.CallTool(callCtx, "echo", nil, CallOpts{}); err != nil {
		t.Errorf("a call after a cancellation: error = %v, want the slot to have been released", err)
	}
}

// TestRefreshDoesNotBlockCalls: a catalog refresh is a control operation, not a
// tool call, so it is serialized against other control work and not against the
// binding's calls. A binding that stopped serving while refetching its catalog
// would turn every server notification into a stall.
func TestRefreshDoesNotBlockCalls(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.listEntered = make(chan struct{})
	conn.listGate = make(chan struct{})
	tr := newFakeTransport(conn)
	def := okDefinition(tr)
	def.Limits.MaxConcurrentRequests = 4

	// Let startup's own discovery through.
	go func() {
		<-conn.listEntered
		conn.listGate <- struct{}{}
	}()

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	// Hold a refresh open inside its fetch.
	notify(t, tr, protocol.ListFamilyTools)
	<-conn.listEntered

	// A tool call must still go through.
	callCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.CallTool(callCtx, "echo", nil, CallOpts{}); err != nil {
		t.Errorf("CallTool() while a refresh is in flight: error = %v, want it to proceed", err)
	}

	conn.listGate <- struct{}{}
}

// TestCloseRejectsNewWorkAndCancelsInFlight is the design's shutdown rule:
// reject, then cancel. Neither half is optional — rejecting without cancelling
// leaves Close waiting on a call that may never end, and cancelling without
// rejecting leaves a call admitted after the teardown.
func TestCloseRejectsNewWorkAndCancelsInFlight(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.callReleased = make(chan struct{})
	defer close(conn.callReleased)
	tr := newFakeTransport(conn)
	def := okDefinition(tr)
	def.AllowParallelCalls = true
	def.Limits.MaxConcurrentRequests = 4

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	inflight := make(chan error, 1)
	go func() {
		_, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
		inflight <- err
	}()
	waitFor(t, "the call to be in flight", func() bool { return conn.live.Load() == 1 })

	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// The in-flight call was cancelled rather than left to hang: Close returned,
	// and the call did too.
	select {
	case err := <-inflight:
		if err == nil {
			t.Error("the in-flight call reported success across a Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel the in-flight call")
	}

	// New work is refused.
	err = callTool(t, c)
	if class, ok := ClassOf(err); !ok || class != FailureShutdown {
		t.Errorf("CallTool() after Close: error = %v (class %v), want FailureShutdown", err, class)
	}
}

// TestSchedulerAdmissionCountsAgainstTheCallDeadline: a call that spends its
// deadline queued has missed it. The alternative — starting the clock after
// admission — would let a busy binding silently outlive every deadline its
// callers set.
func TestSchedulerAdmissionCountsAgainstTheCallDeadline(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.callReleased = make(chan struct{})
	defer close(conn.callReleased)
	tr := newFakeTransport(conn)
	def := okDefinition(tr)
	def.Limits.MaxConcurrentRequests = 1

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	// Occupy the binding.
	go func() { _, _ = c.CallTool(context.Background(), "echo", nil, CallOpts{}) }()
	waitFor(t, "the binding to be occupied", func() bool { return conn.live.Load() == 1 })

	// A second call with a short deadline never gets in.
	start := time.Now()
	_, err = c.CallTool(context.Background(), "echo", nil, CallOpts{
		Deadline: time.Now().Add(50 * time.Millisecond),
	})
	if class, ok := ClassOf(err); !ok || class != FailureDeadline {
		t.Errorf("a call that queued past its deadline: error = %v (class %v), want FailureDeadline", err, class)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the queued call took %v to give up, want it bounded by its deadline", elapsed)
	}

	// The load-bearing assertion, and without it this test is vacuous: the
	// deadline class alone cannot tell "the scheduler never admitted it" from
	// "it was admitted and then expired inside a conn that is blocking anyway",
	// so a client with no scheduler at all — or one leaking slots — passes on
	// the class check. Where the call *stopped* is what distinguishes them, and
	// a call refused at admission never reaches the server.
	if got := conn.callNames(); len(got) != 1 {
		t.Errorf("calls that reached the server = %d (%v), want 1: the queued call was admitted past the binding's budget rather than waiting for it", len(got), got)
	}
}
