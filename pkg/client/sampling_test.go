package client

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/internal/secrettest"
)

// recordingSampler is a sampling handler a test can script and interrogate.
type recordingSampler struct {
	// res and err are what Sample returns.
	res SampleResult
	err error
	// block, when true, makes Sample wait for ctx — a model that never answers,
	// which is what the timeout and the concurrency cap exist for.
	block bool
	// onSample, when set, runs inside Sample with the handler's own context. It
	// is how a test builds a sampling *chain*: the host calling back into the
	// client from inside its handler is the only causal link this module can
	// see, and it is a link the host makes by passing this context on.
	onSample func(ctx context.Context)

	mu   sync.Mutex
	seen []SampleRequest
}

func (s *recordingSampler) Sample(ctx context.Context, req SampleRequest) (SampleResult, error) {
	s.mu.Lock()
	s.seen = append(s.seen, req)
	s.mu.Unlock()

	if s.onSample != nil {
		s.onSample(ctx)
	}
	if s.block {
		<-ctx.Done()
		return SampleResult{}, ctx.Err()
	}
	return s.res, s.err
}

func (s *recordingSampler) requests() []SampleRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SampleRequest(nil), s.seen...)
}

func (s *recordingSampler) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// okSampler is a handler that always completes.
func okSampler() *recordingSampler {
	return &recordingSampler{res: SampleResult{Model: "test-model", Text: "hi"}}
}

// samplingClient connects a Client that serves sampling, and returns it
// alongside the transport (for the installed callback) and the event recorder.
func samplingClient(t *testing.T, h SamplingHandler, shape func(*Definition)) (*Client, *fakeTransport, *eventRecorder) {
	t.Helper()
	return samplingClientWithConn(t, h, okConn(), shape)
}

// samplingClientWithConn is samplingClient over a caller-supplied conn, for the
// tests that need to hold a tool call open.
func samplingClientWithConn(t *testing.T, h SamplingHandler, conn *fakeConn, shape func(*Definition)) (*Client, *fakeTransport, *eventRecorder) {
	t.Helper()

	tr := newFakeTransport(conn)
	rec := &eventRecorder{}
	def := okDefinition(tr)
	def.Capabilities.Sampling = true
	if shape != nil {
		shape(&def)
	}

	c, err := Connect(context.Background(), def, Handlers{Sampling: h, Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, tr, rec
}

// sampleReq is a well-formed neutral sampling request, as the protocol boundary
// would hand one over.
func sampleReq() protocol.SampleRequest {
	return protocol.SampleRequest{
		SystemPrompt: "be brief",
		Messages:     []protocol.SampleMessage{{Role: protocol.SampleRoleUser, Text: "hello"}},
		MaxTokens:    100,
	}
}

// TestSamplingCapabilityIsGated is the gate at Connect, asserted on what the
// transport actually received rather than on what the client meant.
//
// The two negative rows are the whole point of a capability-gated feature.
// "Handler, no request" must not advertise: a host that installed a handler has
// not thereby agreed to let servers spend its money. "Request, no handler" must
// not connect at all: it is a configuration error, and downgrading it silently
// would leave an application believing it had sampling.
func TestSamplingCapabilityIsGated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		request       bool
		handler       SamplingHandler
		wantErr       bool
		wantAdvertise bool
		wantCallback  bool
	}{
		{
			name:          "requested and handled is advertised",
			request:       true,
			handler:       okSampler(),
			wantAdvertise: true,
			wantCallback:  true,
		},
		{
			name:    "requested with no handler is a configuration error",
			request: true,
			handler: nil,
			wantErr: true,
		},
		{
			name:          "handler with no request is not advertised",
			request:       false,
			handler:       okSampler(),
			wantAdvertise: false,
			// The callback is installed but the capability is not advertised, so
			// internal/protocol registers nothing with the SDK and no server can
			// ever call it. See TestSamplingAdvertisement there.
			wantCallback: true,
		},
		{
			name:          "neither is not advertised",
			request:       false,
			handler:       nil,
			wantAdvertise: false,
			wantCallback:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr := newFakeTransport(okConn())
			def := okDefinition(tr)
			def.Capabilities.Sampling = tt.request

			c, err := Connect(context.Background(), def, Handlers{Sampling: tt.handler})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Connect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				var e *Error
				if !errors.As(err, &e) || e.Class != FailureInvalidConfig {
					t.Fatalf("Connect() error = %v, want class FailureInvalidConfig", err)
				}
				return
			}
			t.Cleanup(func() { _ = c.Close(context.Background()) })

			cfg := tr.lastConfig()
			if got := cfg.Capabilities.Sampling; got != tt.wantAdvertise {
				t.Errorf("transport received Capabilities.Sampling = %v, want %v", got, tt.wantAdvertise)
			}
			if got := cfg.OnSample != nil; got != tt.wantCallback {
				t.Errorf("transport received OnSample != nil = %v, want %v", got, tt.wantCallback)
			}
		})
	}
}

// TestSamplingReachesTheHandler is the producer itself, driven through the
// callback the client actually installed — so a client that installed nothing
// fails here rather than passing on a technicality.
func TestSamplingReachesTheHandler(t *testing.T) {
	t.Parallel()

	h := okSampler()
	_, tr, _ := samplingClient(t, h, nil)

	onSample := tr.lastConfig().OnSample
	if onSample == nil {
		t.Fatal("the client installed no OnSample callback, so no server request can reach a handler")
	}

	got, err := onSample(context.Background(), sampleReq())
	if err != nil {
		t.Fatalf("OnSample() error = %v", err)
	}
	if got.Model != "test-model" || got.Text != "hi" {
		t.Errorf("OnSample() = %+v, want the handler's completion", got)
	}

	reqs := h.requests()
	if len(reqs) != 1 {
		t.Fatalf("handler saw %d requests, want 1", len(reqs))
	}
	if reqs[0].Binding != "srv" {
		t.Errorf("handler got Binding = %q, want %q", reqs[0].Binding, "srv")
	}
	if reqs[0].SystemPrompt != "be brief" || len(reqs[0].Messages) != 1 {
		t.Errorf("handler got %+v, want the server's conversation", reqs[0])
	}
}

// TestSamplingTokenBudgetIsCapped: a server's maxTokens is a request, and the
// host's limit is the ceiling. A server can lower it and never raise it.
func TestSamplingTokenBudgetIsCapped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		limit     int
		asked     int
		wantGiven int
	}{
		{name: "under the limit is honored", limit: 1000, asked: 100, wantGiven: 100},
		{name: "exactly the limit is honored", limit: 1000, asked: 1000, wantGiven: 1000},
		{name: "one over the limit is capped", limit: 1000, asked: 1001, wantGiven: 1000},
		{name: "far over the limit is capped", limit: 1000, asked: 1 << 30, wantGiven: 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := okSampler()
			_, tr, _ := samplingClient(t, h, func(d *Definition) {
				d.Limits.MaxSamplingTokens = tt.limit
			})

			req := sampleReq()
			req.MaxTokens = tt.asked
			if _, err := tr.lastConfig().OnSample(context.Background(), req); err != nil {
				t.Fatalf("OnSample() error = %v", err)
			}

			reqs := h.requests()
			if len(reqs) != 1 {
				t.Fatalf("handler saw %d requests, want 1", len(reqs))
			}
			if reqs[0].MaxTokens != tt.wantGiven {
				t.Errorf("handler was granted MaxTokens = %d, want %d (server asked %d, limit %d)",
					reqs[0].MaxTokens, tt.wantGiven, tt.asked, tt.limit)
			}
		})
	}
}

// TestSamplingConcurrencyIsCapped holds the cap's worth of requests open and
// checks the next one is refused rather than queued.
//
// The blocked handlers are what make this a test: with a handler that returns
// at once, nothing overlaps and the assertion would pass against a client with
// no cap at all.
func TestSamplingConcurrencyIsCapped(t *testing.T) {
	t.Parallel()

	const limit = 2
	h := &recordingSampler{block: true}
	_, tr, _ := samplingClient(t, h, func(d *Definition) {
		d.Limits.MaxSamplingConcurrency = limit
		// Long enough that the timeout is never what refuses anything here.
		d.Timeouts.Request = time.Minute
	})
	onSample := tr.lastConfig().OnSample

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range limit {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = onSample(ctx, sampleReq())
		}()
	}

	// Wait for the cap's worth to actually be inside the handler. Without this
	// the next request might arrive before any slot is taken and be admitted
	// legitimately, which would make the test flaky rather than wrong.
	waitFor(t, "the cap's worth of requests to reach the handler", func() bool { return h.calls() == limit })

	_, err := onSample(context.Background(), sampleReq())
	if err == nil {
		t.Fatal("OnSample() error = nil, want a refusal: the concurrency cap is full")
	}
	var e *Error
	if !errors.As(err, &e) || e.Class != FailureSamplingDenied {
		t.Fatalf("OnSample() error = %v, want class FailureSamplingDenied", err)
	}
	if h.calls() != limit {
		t.Errorf("the handler was called %d times, want %d: a refused request must not reach the handler", h.calls(), limit)
	}

	cancel()
	wg.Wait()

	// And the slot comes back: the cap bounds what is in flight, it is not a
	// budget that runs out. The handler is unblocked first — every goroutine
	// that reads it has returned, so this is ordered, not raced.
	h.block = false
	h.res = SampleResult{Model: "test-model"}
	if _, err := onSample(context.Background(), sampleReq()); err != nil {
		t.Errorf("OnSample() after the in-flight requests finished: error = %v, want admission", err)
	}
}

// TestSamplingDepthIsCapped builds a real sampling chain and checks the client
// refuses the link past the cap.
//
// The chain is the one this module can see, and it is built the way a host
// builds one: the handler calls back into the client with the context it was
// given. While that call is in flight the binding is doing work *because of*
// sampling, so a sampling request arriving meanwhile is that call's child.
//
// Concurrency is set wide open so that only the depth cap can refuse anything.
// That is what makes this a test of depth rather than of the other cap: with the
// chain hook removed the second request is depth 1, and it is admitted.
func TestSamplingDepthIsCapped(t *testing.T) {
	t.Parallel()

	conn := okConn()
	// Buffered: the entry signal must never be what blocks a call, only the
	// release gate. An unbuffered one would make a call with no test goroutine
	// waiting on it hang until the request timeout.
	conn.callEntered = make(chan struct{}, 8)
	conn.callReleased = make(chan struct{})

	var c *Client
	h := &recordingSampler{
		res: SampleResult{Model: "test-model"},
		onSample: func(ctx context.Context) {
			// Only the first (outermost) request calls back in; a nested one
			// returns at once, so the chain is exactly one link long.
			if sampleDepthOf(ctx) != 1 {
				return
			}
			_, _ = c.CallTool(ctx, "echo", nil, CallOpts{})
		},
	}

	var tr *fakeTransport
	c, tr, _ = samplingClientWithConn(t, h, conn, func(d *Definition) {
		d.Limits.MaxSamplingDepth = 1
		d.Limits.MaxSamplingConcurrency = 8
		d.Timeouts.Request = time.Minute
	})
	onSample := tr.lastConfig().OnSample

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = onSample(context.Background(), sampleReq())
	}()

	// The outer handler's tool call is now in flight and registered, so the
	// binding is demonstrably doing work caused by sampling.
	select {
	case <-conn.callEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler's tool call never reached the connection")
	}

	// This request is caused by that call, so it is depth 2, over the cap of 1.
	_, err := onSample(context.Background(), sampleReq())
	if err == nil {
		t.Fatal("OnSample() error = nil, want a refusal: this request is one level deeper than the cap allows")
	}
	var e *Error
	if !errors.As(err, &e) || e.Class != FailureSamplingDenied {
		t.Fatalf("OnSample() error = %v, want class FailureSamplingDenied", err)
	}

	close(conn.callReleased)
	<-done

	// With the chain finished, the binding is not doing sampling-caused work
	// any more, so a fresh request is depth 1 again and admitted. This is what
	// separates a depth cap from a latch.
	if _, err := onSample(context.Background(), sampleReq()); err != nil {
		t.Errorf("OnSample() after the chain unwound: error = %v, want admission at depth 1", err)
	}
}

// TestSamplingDepthIgnoresUnchainedCalls is the other side of the depth cap: a
// tool call that no sampling handler issued is not a link, so a sampling request
// arriving while one is in flight is not nested.
//
// Without it, "depth" would just be a second name for "the binding is busy", and
// an ordinary caller's tool call would lock a host out of sampling entirely.
func TestSamplingDepthIgnoresUnchainedCalls(t *testing.T) {
	t.Parallel()

	conn := okConn()
	// Buffered: the entry signal must never be what blocks a call, only the
	// release gate. An unbuffered one would make a call with no test goroutine
	// waiting on it hang until the request timeout.
	conn.callEntered = make(chan struct{}, 8)
	conn.callReleased = make(chan struct{})

	h := okSampler()
	c, tr, _ := samplingClientWithConn(t, h, conn, func(d *Definition) {
		d.Limits.MaxSamplingDepth = 1
		d.Timeouts.Request = time.Minute
	})

	// An ordinary caller's tool call, with no sampling context on it.
	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		_, _ = c.CallTool(context.Background(), "echo", nil, CallOpts{})
	}()
	select {
	case <-conn.callEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("the tool call never reached the connection")
	}

	if _, err := tr.lastConfig().OnSample(context.Background(), sampleReq()); err != nil {
		t.Errorf("OnSample() while an unrelated tool call is in flight: error = %v, want admission at depth 1", err)
	}

	close(conn.callReleased)
	<-callDone
}

// TestNestedSamplingDoesNotDeadlock is Fix #6: a server that samples during a
// tools/call, whose handler calls back into the same client, must not deadlock
// on the tool-call serializer the outer call is holding.
//
// The shape is the probe's: AllowParallelCalls is off (the default, cap-1
// serializer), the outer tool call holds the permit, and the sampling handler
// it provokes makes a re-entrant tool call. Before the fix that inner call
// queued behind the permit its own outer call held and died on the deadline;
// after it, the re-entrant call is admitted without the serializer and
// completes at once.
func TestNestedSamplingDoesNotDeadlock(t *testing.T) {
	t.Parallel()

	conn := okConn()

	var c *Client
	var nestedErr error
	var nestedOnce sync.Once
	h := &recordingSampler{
		res: SampleResult{Model: "test-model"},
		onSample: func(ctx context.Context) {
			// The host, from inside its sampling handler, makes another tool call
			// on the same client — the reentrancy that used to self-deadlock. It
			// must pass ctx on, which is what carries the sampling depth that marks
			// the call re-entrant.
			nestedOnce.Do(func() {
				_, nestedErr = c.CallTool(ctx, "echo", nil, CallOpts{})
			})
		},
	}

	var tr *fakeTransport
	c, tr, _ = samplingClientWithConn(t, h, conn, func(d *Definition) {
		// Serialized tool calls — the default and the whole precondition for the
		// deadlock. A finite request deadline so a regression fails fast, as a
		// timeout, rather than hanging the suite.
		d.AllowParallelCalls = false
		d.Timeouts.Request = 700 * time.Millisecond
		d.Limits.MaxSamplingDepth = 4
		d.Limits.MaxSamplingConcurrency = 4
	})

	onSample := tr.lastConfig().OnSample
	// The server samples while the outer tool call (index 1) is in flight and
	// holding the serializer.
	conn.onCallTool = func(ctx context.Context, index int) {
		if index == 1 {
			_, _ = onSample(ctx, sampleReq())
		}
	}

	start := time.Now()
	res, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("outer CallTool() error = %v, want it to complete", err)
	}
	if res.IsError {
		t.Error("outer CallTool() returned a tool error, want success")
	}
	if nestedErr != nil {
		t.Errorf("nested CallTool() error = %v, want it to complete rather than deadlock on the serializer", nestedErr)
	}
	// A deadlocked reentrant call only unblocks when its deadline fires (~700ms);
	// a working one returns in microseconds. The threshold is well clear of both.
	if elapsed > 400*time.Millisecond {
		t.Errorf("the exchange took %v, near the request deadline: the reentrant call is deadlocking", elapsed)
	}
}

// TestSamplingGate covers the gate's arithmetic directly, including the
// boundaries a client-level test cannot easily sit on.
func TestSamplingGate(t *testing.T) {
	t.Parallel()

	t.Run("depth counts from one", func(t *testing.T) {
		t.Parallel()
		g := newSampleGate(2, 8)
		depth, release, err := g.enter()
		if err != nil {
			t.Fatalf("enter() error = %v, want admission", err)
		}
		defer release()
		if depth != 1 {
			t.Errorf("depth = %d, want 1: a request with no live chain is not nested", depth)
		}
	})

	t.Run("a live chain link deepens the next request", func(t *testing.T) {
		t.Parallel()
		g := newSampleGate(2, 8)
		leave := g.enterChain(1)
		depth, release, err := g.enter()
		if err != nil {
			t.Fatalf("enter() error = %v, want admission at depth 2", err)
		}
		defer release()
		if depth != 2 {
			t.Errorf("depth = %d, want 2", depth)
		}
		leave()
		if got, release2, err := g.enter(); err != nil || got != 1 {
			t.Errorf("after the link left: depth = %d, err = %v, want depth 1 admitted", got, err)
		} else {
			release2()
		}
	})

	t.Run("depth at the cap is admitted and over it is refused", func(t *testing.T) {
		t.Parallel()
		g := newSampleGate(2, 8)
		defer g.enterChain(1)()
		if _, release, err := g.enter(); err != nil {
			t.Errorf("depth 2 with cap 2: error = %v, want admission", err)
		} else {
			release()
		}

		defer g.enterChain(2)()
		depth, _, err := g.enter()
		if !errors.Is(err, errSampleDepth) {
			t.Errorf("depth 3 with cap 2: error = %v, want errSampleDepth", err)
		}
		if depth != 3 {
			t.Errorf("depth = %d, want 3 reported even on refusal: it is what the audit record carries", depth)
		}
	})

	t.Run("the deepest live link wins", func(t *testing.T) {
		t.Parallel()
		g := newSampleGate(9, 8)
		defer g.enterChain(1)()
		defer g.enterChain(4)()
		defer g.enterChain(2)()
		depth, release, err := g.enter()
		if err != nil {
			t.Fatalf("enter() error = %v", err)
		}
		defer release()
		if depth != 5 {
			t.Errorf("depth = %d, want 5: an ambiguous chain is attributed to the deepest link", depth)
		}
	})

	t.Run("concurrency at the cap is admitted and over it is refused", func(t *testing.T) {
		t.Parallel()
		g := newSampleGate(9, 2)
		_, r1, err := g.enter()
		if err != nil {
			t.Fatalf("first enter() error = %v", err)
		}
		_, r2, err := g.enter()
		if err != nil {
			t.Fatalf("second enter() error = %v", err)
		}
		if _, _, err := g.enter(); !errors.Is(err, errSampleConcurrency) {
			t.Errorf("third enter() with cap 2: error = %v, want errSampleConcurrency", err)
		}
		r1()
		if _, r3, err := g.enter(); err != nil {
			t.Errorf("after a release: error = %v, want admission", err)
		} else {
			r3()
		}
		r2()
	})

	t.Run("release is idempotent", func(t *testing.T) {
		t.Parallel()
		g := newSampleGate(9, 1)
		_, release, err := g.enter()
		if err != nil {
			t.Fatalf("enter() error = %v", err)
		}
		release()
		release()
		// A second release that decremented again would leave inflight negative
		// and let the cap be exceeded forever after. So: take the one slot the
		// cap allows, and hold it — the next enter must still be refused.
		_, held, err := g.enter()
		if err != nil {
			t.Fatalf("enter() after a double release: error = %v", err)
		}
		defer held()
		if _, _, err := g.enter(); !errors.Is(err, errSampleConcurrency) {
			t.Errorf("the cap survived a double release: error = %v, want errSampleConcurrency", err)
		}
	})

	t.Run("a zero cap refuses everything", func(t *testing.T) {
		t.Parallel()
		// Unreachable through a normalized Definition, and asserted anyway: a
		// limit that failed open when misconfigured would be no limit.
		if _, _, err := newSampleGate(0, 8).enter(); !errors.Is(err, errSampleDepth) {
			t.Errorf("zero depth cap: error = %v, want errSampleDepth", err)
		}
		if _, _, err := newSampleGate(9, 0).enter(); !errors.Is(err, errSampleConcurrency) {
			t.Errorf("zero concurrency cap: error = %v, want errSampleConcurrency", err)
		}
	})
}

// TestSamplingHandlerFailureIsRefused checks a handler's error becomes a refusal
// the server is told about, and that the handler's own words do not travel.
func TestSamplingHandlerFailureIsRefused(t *testing.T) {
	t.Parallel()

	const secret = "sk-super-secret-key"
	h := &recordingSampler{err: errors.New("provider rejected " + secret)}
	_, tr, _ := samplingClient(t, h, nil)

	_, err := tr.lastConfig().OnSample(context.Background(), sampleReq())
	if err == nil {
		t.Fatal("OnSample() error = nil, want the handler's failure reported")
	}
	var e *Error
	if !errors.As(err, &e) || e.Class != FailureSamplingDenied {
		t.Fatalf("OnSample() error = %v, want class FailureSamplingDenied", err)
	}
	// Error.Error does not render a wrapped cause when Msg is set, which is what
	// keeps a handler's error text — which may name anything at all — on this
	// side of the wire.
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the error rendered to the server carries the handler's own text: %q", err.Error())
	}
}

// TestSamplingHandlerWithNoModelIsRefused: a completion has to say what produced
// it, and this client will not invent one.
func TestSamplingHandlerWithNoModelIsRefused(t *testing.T) {
	t.Parallel()

	h := &recordingSampler{res: SampleResult{Text: "hi"}}
	_, tr, _ := samplingClient(t, h, nil)

	if _, err := tr.lastConfig().OnSample(context.Background(), sampleReq()); err == nil {
		t.Fatal("OnSample() error = nil, want a refusal: the handler named no model")
	}
}

// TestSamplingIsBoundedByTheBindingsTimeout: a model that never answers must not
// pin a dispatch goroutine, a handler, and a sampling slot forever.
func TestSamplingIsBoundedByTheBindingsTimeout(t *testing.T) {
	t.Parallel()

	h := &recordingSampler{block: true}
	_, tr, _ := samplingClient(t, h, func(d *Definition) {
		d.Timeouts.Request = 50 * time.Millisecond
	})

	start := time.Now()
	_, err := tr.lastConfig().OnSample(context.Background(), sampleReq())
	if err == nil {
		t.Fatal("OnSample() error = nil, want the timeout to refuse it")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("OnSample() took %v, want the binding's 50ms timeout to end it", elapsed)
	}

	// And the slot came back: a timed-out request that kept its slot would
	// starve the binding of sampling for good.
	h.block = false
	h.res = SampleResult{Model: "m"}
	if _, err := tr.lastConfig().OnSample(context.Background(), sampleReq()); err != nil {
		t.Errorf("OnSample() after a timeout: error = %v, want admission", err)
	}
}

// TestSamplingRequestWithBadRoleIsRefused is the client's own defence in depth:
// internal/protocol already refuses an unattributable message, and the client
// re-checks because it is what promises Handlers.Sampling a role it can switch
// on.
func TestSamplingRequestWithBadRoleIsRefused(t *testing.T) {
	t.Parallel()

	h := okSampler()
	_, tr, _ := samplingClient(t, h, nil)

	req := sampleReq()
	req.Messages = []protocol.SampleMessage{{Role: 99, Text: "hello"}}
	if _, err := tr.lastConfig().OnSample(context.Background(), req); err == nil {
		t.Fatal("OnSample() error = nil, want a refusal: the message has no declared role")
	}
	if h.calls() != 0 {
		t.Error("the handler was called with an unattributable message")
	}
}

// TestSamplingEventsAuditWithoutSecrets: every sampling request and outcome is
// audited, and none of it carries what the server sent or what the model said.
//
// A server's prompt may contain anything it has been told — including a secret a
// tool handed it — and a completion is the host's own model output. Neither
// belongs in an event stream that a host will log.
func TestSamplingEventsAuditWithoutSecrets(t *testing.T) {
	t.Parallel()

	const secret = "sk-live-abcdef123456"
	h := &recordingSampler{res: SampleResult{Model: "test-model", Text: "the answer is " + secret}}
	_, tr, rec := samplingClient(t, h, nil)

	req := sampleReq()
	req.SystemPrompt = "the key is " + secret
	req.Messages = []protocol.SampleMessage{{Role: protocol.SampleRoleUser, Text: secret}}
	if _, err := tr.lastConfig().OnSample(context.Background(), req); err != nil {
		t.Fatalf("OnSample() error = %v", err)
	}

	var requested, resolved int
	for _, e := range rec.snapshot() {
		switch e.(type) {
		case SamplingRequested, SamplingResolved:
			if dump := secrettest.Dump(e); strings.Contains(dump, secret) {
				t.Errorf("a sampling event carries content:\n%s", dump)
			}
		}
		switch ev := e.(type) {
		case SamplingRequested:
			requested++
			if ev.Messages != 1 || ev.MaxTokens <= 0 || ev.Depth != 1 {
				t.Errorf("SamplingRequested = %+v, want the request's shape", ev)
			}
		case SamplingResolved:
			resolved++
			if ev.Outcome != SampleCompleted || ev.Model != "test-model" {
				t.Errorf("SamplingResolved = %+v, want a completed outcome naming the model", ev)
			}
		}
	}
	if requested != 1 || resolved != 1 {
		t.Errorf("audit recorded %d requested / %d resolved, want 1 / 1", requested, resolved)
	}
}

// TestSamplingRefusalIsAudited: the requests the gate refuses are the ones an
// operator most wants to see, so they are audited like any other — a
// SamplingRequested with a matching SamplingResolved, not a gap.
func TestSamplingRefusalIsAudited(t *testing.T) {
	t.Parallel()

	h := &recordingSampler{block: true}
	_, tr, rec := samplingClient(t, h, func(d *Definition) {
		d.Limits.MaxSamplingConcurrency = 1
		d.Timeouts.Request = time.Minute
	})
	onSample := tr.lastConfig().OnSample

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = onSample(ctx, sampleReq())
	}()
	waitFor(t, "the first request to reach the handler", func() bool { return h.calls() == 1 })

	if _, err := onSample(context.Background(), sampleReq()); err == nil {
		t.Fatal("OnSample() error = nil, want a refusal")
	}
	cancel()
	<-done

	var denied int
	for _, e := range rec.snapshot() {
		if ev, ok := e.(SamplingResolved); ok && ev.Outcome == SampleDenied {
			denied++
			if ev.Model != "" {
				t.Errorf("SamplingResolved.Model = %q, want empty: no model ran", ev.Model)
			}
		}
	}
	if denied != 1 {
		t.Errorf("recorded %d denied outcomes, want 1", denied)
	}
	// Every refusal still announced itself first.
	var requested int
	for _, e := range rec.snapshot() {
		if _, ok := e.(SamplingRequested); ok {
			requested++
		}
	}
	if requested != 2 {
		t.Errorf("recorded %d SamplingRequested, want 2: a refused request is still a request", requested)
	}
}

// TestSampleRequestCarriesNoAuthority is the design's "sampling never receives a
// Harness Session controller or unrestricted tool registry", asserted
// structurally rather than trusted.
//
// The rule is kept by there being nowhere to put one: every field a handler
// receives is a string, a number, or a slice of the same. An interface, a
// pointer, a func, or a channel appearing here would be a field through which a
// controller could arrive — so the sweep fails on the *kind*, and a future field
// has to argue with this test rather than slip past a reviewer.
func TestSampleRequestCarriesNoAuthority(t *testing.T) {
	t.Parallel()

	for _, typ := range []reflect.Type{
		reflect.TypeOf(SampleRequest{}),
		reflect.TypeOf(SampleResult{}),
		reflect.TypeOf(SampleMessage{}),
	} {
		t.Run(typ.Name(), func(t *testing.T) {
			t.Parallel()
			for i := range typ.NumField() {
				f := typ.Field(i)
				if !inert(f.Type) {
					t.Errorf("%s.%s is %s: a sampling handler must receive only inert data, and this field could carry authority",
						typ.Name(), f.Name, f.Type)
				}
			}
		})
	}
}

// inert reports whether t can only ever hold data — never a reference to
// something a handler could act through.
func inert(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.String, reflect.Int, reflect.Int64, reflect.Uint8, reflect.Bool:
		return true
	case reflect.Slice:
		return inert(t.Elem())
	case reflect.Struct:
		for i := range t.NumField() {
			if !inert(t.Field(i).Type) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
