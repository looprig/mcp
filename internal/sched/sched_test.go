package sched

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// probe observes how many requests are in flight at once. It is the instrument
// every bound in this package is measured with: a scheduler that admitted too
// many is caught by max, and one that admitted too few is caught by the barrier
// (see overlap), which blocks until the expected number really are concurrent
// and so times out rather than passing.
type probe struct {
	live atomic.Int32
	max  atomic.Int32
}

// enter records an arrival and returns the departure func.
func (p *probe) enter() func() {
	live := p.live.Add(1)
	for {
		max := p.max.Load()
		if live <= max || p.max.CompareAndSwap(max, live) {
			break
		}
	}
	return func() { p.live.Add(-1) }
}

// barrier blocks until n goroutines have reached it, or fails the test. It is
// what makes "these ran in parallel" a falsifiable claim: under a scheduler that
// serialized them, the first arrival waits for a second that cannot start, and
// the test fails on the timeout instead of passing on a coincidence.
type barrier struct {
	n     int
	mu    sync.Mutex
	count int
	ch    chan struct{}
}

func newBarrier(n int) *barrier {
	return &barrier{n: n, ch: make(chan struct{})}
}

func (b *barrier) wait(t *testing.T) {
	t.Helper()
	b.mu.Lock()
	b.count++
	if b.count == b.n {
		close(b.ch)
	}
	b.mu.Unlock()

	select {
	case <-b.ch:
	case <-time.After(2 * time.Second):
		t.Errorf("barrier: timed out with %d of %d arrivals: the work was not admitted in parallel", b.count, b.n)
	}
}

// begin is Begin with the test's error check inlined.
func begin(t *testing.T, s *Scheduler, class Class) (context.Context, func()) {
	t.Helper()
	ctx, release, err := s.Begin(context.Background(), class)
	if err != nil {
		t.Fatalf("Begin(%v) error = %v", class, err)
	}
	return ctx, release
}

// TestToolCallsSerializedByDefault is the design's default: a tool call has
// effects, and two at once against a server that never expected them is the
// caller's problem to opt into, not the client's to assume.
func TestToolCallsSerializedByDefault(t *testing.T) {
	t.Parallel()

	// A generous budget, so that anything but the call lock would let these
	// overlap: what is being tested is the serialization, not the bound.
	s := New(Config{MaxConcurrent: 8})
	var p probe
	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, release := begin(t, s, ClassCall)
			defer release()
			done := p.enter()
			defer done()
			time.Sleep(time.Millisecond)
		}()
	}
	wg.Wait()

	if got := p.max.Load(); got != 1 {
		t.Errorf("concurrent tool calls = %d, want 1: tool calls must serialize by default", got)
	}
}

// TestReentrantCallBypassesTheSerializer is Fix #6 at the scheduler level: a
// re-entrant tool call must not queue behind the ClassCall permit an outer call
// is holding — that is the deadlock a sampling handler falls into when it calls
// back into the client — while an ordinary tool call must still serialize.
func TestReentrantCallBypassesTheSerializer(t *testing.T) {
	t.Parallel()

	// AllowParallel false, so callLock is a real cap-1 serializer; a generous
	// budget so the concurrency bound is never what admits or blocks anything.
	s := New(Config{MaxConcurrent: 8})

	// The outer tool call holds the serializer, as it would while a server it
	// called is asking the host for sampling.
	_, releaseOuter := begin(t, s, ClassCall)
	defer releaseOuter()

	// A re-entrant call admits at once despite the held permit.
	admitted := make(chan struct{})
	go func() {
		ctx, release, err := s.Begin(context.Background(), ClassReentrantCall)
		if err != nil || ctx == nil {
			return // leaves admitted unclosed → the test fails on timeout
		}
		defer release()
		close(admitted)
	}()
	select {
	case <-admitted:
	case <-time.After(2 * time.Second):
		t.Fatal("a re-entrant call queued behind the ClassCall permit: the self-deadlock Fix #6 removes")
	}

	// An ordinary tool call still serializes: it must NOT be admitted while the
	// outer call holds the permit. This is the regression guard the fix must not
	// trip — re-entrancy is the exception, not a general widening.
	blocked := make(chan struct{})
	go func() {
		ctx, release, err := s.Begin(context.Background(), ClassCall)
		if err != nil || ctx == nil {
			return
		}
		defer release()
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("an ordinary tool call was admitted while another held the permit: serialization regressed")
	case <-time.After(100 * time.Millisecond):
		// Correct: still serialized behind the outer call.
	}
}

// TestReentrantCallCountsAgainstTheBudget: bypassing the serializer is not
// bypassing the bound. A re-entrant call still consumes a concurrency slot, so a
// budget of one that is already spent blocks it.
func TestReentrantCallCountsAgainstTheBudget(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 1})

	_, release := begin(t, s, ClassRequest) // spends the only slot
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := s.Begin(ctx, ClassReentrantCall); err == nil {
		t.Fatal("a re-entrant call was admitted past a spent budget: the bound must still apply")
	}
}

// TestAllowParallelCalls: the opt-in is real, and it is bounded by the budget
// rather than unlimited.
func TestAllowParallelCalls(t *testing.T) {
	t.Parallel()

	const budget = 4

	s := New(Config{MaxConcurrent: budget, AllowParallel: true})
	var p probe
	b := newBarrier(budget)
	var wg sync.WaitGroup

	// Exactly the budget, all at once. The barrier makes each hold its slot
	// until every one of them has one, which cannot happen unless the scheduler
	// really admitted them together.
	for range budget {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, release := begin(t, s, ClassCall)
			defer release()
			done := p.enter()
			defer done()
			b.wait(t)
		}()
	}
	wg.Wait()

	if got := p.max.Load(); got != budget {
		t.Errorf("concurrent tool calls with AllowParallel = %d, want %d", got, budget)
	}
}

// TestMaxConcurrentBoundsParallelCalls: the budget bounds everything even when
// parallelism is enabled. Enabling parallel calls removes a serialization
// constraint; it does not remove the bound.
func TestMaxConcurrentBoundsParallelCalls(t *testing.T) {
	t.Parallel()

	const budget = 2

	s := New(Config{MaxConcurrent: budget, AllowParallel: true})
	var p probe
	var wg sync.WaitGroup

	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, release := begin(t, s, ClassCall)
			defer release()
			done := p.enter()
			defer done()
			time.Sleep(time.Millisecond)
		}()
	}
	wg.Wait()

	if got := p.max.Load(); got > budget {
		t.Errorf("concurrent tool calls = %d, want at most the budget of %d", got, budget)
	}
	if got := p.max.Load(); got != budget {
		t.Errorf("concurrent tool calls = %d, want the full budget of %d to be usable", got, budget)
	}
}

// TestMaxConcurrentBoundsEveryClass: the budget is shared, not per class. A
// binding whose limit is two must not run two calls and two reads and two
// refreshes.
func TestMaxConcurrentBoundsEveryClass(t *testing.T) {
	t.Parallel()

	const budget = 2

	s := New(Config{MaxConcurrent: budget, AllowParallel: true})
	var p probe
	var wg sync.WaitGroup

	for _, class := range []Class{ClassCall, ClassRequest, ClassControl} {
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, release := begin(t, s, class)
				defer release()
				done := p.enter()
				defer done()
				time.Sleep(time.Millisecond)
			}()
		}
	}
	wg.Wait()

	if got := p.max.Load(); got > budget {
		t.Errorf("concurrent requests across classes = %d, want at most %d", got, budget)
	}
}

// TestControlOperationsSerialize: lifecycle, auth and refresh have ordering that
// matters, so they run one at a time — even on a binding that allows parallel
// tool calls, because the opt-in is about tool calls and says nothing about the
// binding's own state transitions.
func TestControlOperationsSerialize(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 8, AllowParallel: true})
	var p probe
	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, release := begin(t, s, ClassControl)
			defer release()
			done := p.enter()
			defer done()
			time.Sleep(time.Millisecond)
		}()
	}
	wg.Wait()

	if got := p.max.Load(); got != 1 {
		t.Errorf("concurrent control operations = %d, want 1", got)
	}
}

// TestClassesDoNotBlockEachOther: the serialization is per class. A refresh in
// flight must not stop a tool call — a binding that refetched its catalog by
// stopping the world would turn every server notification into a stall.
func TestClassesDoNotBlockEachOther(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 8})

	// A control operation and a tool call are both held open at once. Each
	// waits for the other to arrive, so neither can pass unless the scheduler
	// admits both.
	b := newBarrier(2)
	var wg sync.WaitGroup
	for _, class := range []Class{ClassControl, ClassCall} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, release := begin(t, s, class)
			defer release()
			b.wait(t)
		}()
	}
	wg.Wait()
}

// TestCancelIsPerRequest is the design's isolation rule: cancelling one request
// does not cancel unrelated calls on the same connection.
func TestCancelIsPerRequest(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 4, AllowParallel: true})

	victimParent, cancelVictim := context.WithCancel(context.Background())
	defer cancelVictim()
	victim, releaseVictim, err := s.Begin(victimParent, ClassCall)
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	defer releaseVictim()

	bystander, releaseBystander := begin(t, s, ClassCall)
	defer releaseBystander()
	other, releaseOther := begin(t, s, ClassRequest)
	defer releaseOther()

	cancelVictim()

	select {
	case <-victim.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled request's context is still live")
	}
	// The point: nothing else moved.
	for name, ctx := range map[string]context.Context{"bystander call": bystander, "unrelated request": other} {
		select {
		case <-ctx.Done():
			t.Errorf("%s was cancelled by an unrelated request's cancellation", name)
		default:
		}
	}

	// And the cancelled request's slot comes back, so a cancellation costs the
	// binding nothing but the request it cancelled.
	releaseVictim()
	third, releaseThird := begin(t, s, ClassCall)
	defer releaseThird()
	select {
	case <-third.Done():
		t.Error("a freshly admitted request is already cancelled")
	default:
	}
}

// TestCancelWhileWaiting: a caller that gives up while queued behind the
// serialization lock consumes nothing and disturbs nobody.
func TestCancelWhileWaiting(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 4})

	// Hold the call lock.
	_, release := begin(t, s, ClassCall)

	ctx, cancel := context.WithCancel(context.Background())
	waited := make(chan error, 1)
	go func() {
		_, r, err := s.Begin(ctx, ClassCall)
		if err == nil {
			r()
		}
		waited <- err
	}()

	// Let it reach the lock, then give up.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-waited:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Begin() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled waiter never returned")
	}

	// The abandoned wait took nothing with it: the lock is still the first
	// caller's, and it still works afterwards.
	if got := s.InFlight(); got != 1 {
		t.Errorf("InFlight() = %d after an abandoned wait, want 1", got)
	}
	release()
	_, release2 := begin(t, s, ClassCall)
	release2()
}

// TestShutdownRejectsThenCancels is the design's shutdown order: new work is
// refused before in-flight work is cancelled, so nothing can slip in behind the
// teardown.
func TestShutdownRejectsThenCancels(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 4, AllowParallel: true})

	inflight, release := begin(t, s, ClassCall)
	defer release()

	s.Shutdown()

	// Cancelled.
	select {
	case <-inflight.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not cancel an in-flight request")
	}

	// Rejected — every class, not just the serialized one.
	for _, class := range []Class{ClassCall, ClassRequest, ClassControl} {
		if _, _, err := s.Begin(context.Background(), class); !errors.Is(err, ErrShutdown) {
			t.Errorf("Begin(%v) after Shutdown: error = %v, want ErrShutdown", class, err)
		}
	}

	// Releasing after a shutdown is safe, and does not reopen the door.
	release()
	if _, _, err := s.Begin(context.Background(), ClassCall); !errors.Is(err, ErrShutdown) {
		t.Errorf("Begin() after a post-shutdown release: error = %v, want ErrShutdown", err)
	}
}

// TestShutdownReleasesWaiters: a caller queued behind a bound when shutdown
// begins is refused, not left holding the binding open forever.
func TestShutdownReleasesWaiters(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 1})
	_, release := begin(t, s, ClassCall)
	defer release()

	waited := make(chan error, 1)
	go func() {
		_, r, err := s.Begin(context.Background(), ClassCall)
		if err == nil {
			r()
		}
		waited <- err
	}()
	time.Sleep(20 * time.Millisecond) // let it reach the bound

	s.Shutdown()

	select {
	case err := <-waited:
		if !errors.Is(err, ErrShutdown) {
			t.Errorf("a queued Begin at shutdown: error = %v, want ErrShutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown left a waiter queued behind a bound that will never open")
	}
}

// TestShutdownIdempotentAndConcurrent: shutdown is reachable from anywhere, so
// it must tolerate being reached from everywhere at once.
func TestShutdownIdempotentAndConcurrent(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 4, AllowParallel: true})
	for range 4 {
		_, release := begin(t, s, ClassCall)
		defer release()
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Shutdown()
		}()
	}
	wg.Wait()
}

// TestBeginRefusesUndeclaredClass: fail closed. An unknown class is refused
// rather than admitted with no serialization at all, which is what a default
// branch that fell through to "no lock" would do.
func TestBeginRefusesUndeclaredClass(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 4})
	for _, class := range []Class{0, classSentinel, Class(200)} {
		if _, _, err := s.Begin(context.Background(), class); err == nil {
			t.Errorf("Begin(%d) error = nil, want a refusal", class)
		}
		if got := s.InFlight(); got != 0 {
			t.Errorf("InFlight() = %d after a refused Begin, want 0", got)
		}
	}
}

// TestBeginRefusesDeadContext: a caller that is already gone is not admitted,
// so a dead request never consumes a slot.
func TestBeginRefusesDeadContext(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := s.Begin(ctx, ClassCall); !errors.Is(err, context.Canceled) {
		t.Errorf("Begin() with a cancelled context: error = %v, want context.Canceled", err)
	}
	// The slot is untouched, so a live caller still gets it.
	_, release := begin(t, s, ClassCall)
	release()
}

// TestReleaseIsIdempotent: release is a defer, and a defer can be reached twice
// on a path that returns early. Returning a slot twice would let the binding
// exceed its own budget, which is worse than the double call.
func TestReleaseIsIdempotent(t *testing.T) {
	t.Parallel()

	s := New(Config{MaxConcurrent: 1})
	_, release := begin(t, s, ClassCall)
	release()
	release()
	release()

	if got := s.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d, want 0", got)
	}
	// The budget is still 1, not 3: a second concurrent call must still wait.
	_, first := begin(t, s, ClassCall)
	defer first()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := s.Begin(ctx, ClassCall); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Begin() error = %v, want it to wait for the budget (DeadlineExceeded)", err)
	}
}

// TestClassStringsAreExhaustive keeps the identifiers that reach diagnostics
// honest: every declared class renders as itself, and nothing outside the
// declared range renders as anything but "unknown".
func TestClassStringsAreExhaustive(t *testing.T) {
	t.Parallel()

	want := map[Class]string{
		ClassCall:          "call",
		ClassRequest:       "request",
		ClassControl:       "control",
		ClassReentrantCall: "reentrant_call",
	}
	for c := ClassCall; c < classSentinel; c++ {
		if got := c.String(); got != want[c] {
			t.Errorf("Class(%d).String() = %q, want %q", c, got, want[c])
		}
	}
	for _, c := range []Class{0, classSentinel, Class(200)} {
		if got := c.String(); got != "unknown" {
			t.Errorf("Class(%d).String() = %q, want %q", c, got, "unknown")
		}
	}
}

// TestSchedulerUnderLoad drives every class concurrently against a small budget,
// with cancellations and a shutdown, under -race. It asserts the one invariant
// that must hold whatever the interleaving: the budget is never exceeded.
func TestSchedulerUnderLoad(t *testing.T) {
	t.Parallel()

	const budget = 3

	s := New(Config{MaxConcurrent: budget, AllowParallel: true})
	var p probe
	var wg sync.WaitGroup

	for i := range 60 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			class := []Class{ClassCall, ClassRequest, ClassControl}[i%3]

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// A third of the callers give up almost immediately, which is the
			// interesting interleaving: an abandoned wait must not lose a slot.
			if i%3 == 0 {
				go func() {
					time.Sleep(time.Duration(i%5) * time.Millisecond)
					cancel()
				}()
			}

			reqCtx, release, err := s.Begin(ctx, class)
			if err != nil {
				return
			}
			defer release()
			done := p.enter()
			defer done()
			select {
			case <-reqCtx.Done():
			case <-time.After(time.Millisecond):
			}
		}()
	}

	time.Sleep(10 * time.Millisecond)
	s.Shutdown()
	wg.Wait()

	if got := p.max.Load(); got > budget {
		t.Errorf("peak concurrency = %d, want at most the budget of %d", got, budget)
	}
	if got := s.InFlight(); got != 0 {
		t.Errorf("InFlight() = %d after every request finished, want 0", got)
	}
}
