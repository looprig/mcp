// Test doubles shared by the client tests. They live in package client (not
// client_test) because they implement TransportFactory, whose Connect signature
// names internal/protocol types — a sealed, module-internal boundary.

package client

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/looprig/mcp/internal/protocol"
)

// fakeConn is an in-memory protocol.Conn.
type fakeConn struct {
	initResult protocol.InitializeResult
	initErr    error
	// initBlock, when true, makes Initialize wait for ctx to be done and then
	// return ctx.Err().
	initBlock bool
	// beforeInit runs at the top of Initialize, before any blocking.
	beforeInit func()

	closeErr error
	closes   atomic.Int32
	inits    atomic.Int32
}

func (c *fakeConn) Initialize(ctx context.Context) (protocol.InitializeResult, error) {
	c.inits.Add(1)
	if c.beforeInit != nil {
		c.beforeInit()
	}
	if c.initBlock {
		<-ctx.Done()
		return protocol.InitializeResult{}, ctx.Err()
	}
	if c.initErr != nil {
		return protocol.InitializeResult{}, c.initErr
	}
	return c.initResult, nil
}

func (c *fakeConn) Close(_ context.Context) error {
	c.closes.Add(1)
	return c.closeErr
}

// closeCount reports how many times Close reached the conn.
func (c *fakeConn) closeCount() int { return int(c.closes.Load()) }

// fakeTransport is an in-memory TransportFactory. It records the ConnectConfig
// it was handed, which is what the capability-advertisement tests assert on.
type fakeTransport struct {
	kind   string
	origin string

	conn *fakeConn
	err  error
	// block, when true, makes Connect wait for ctx to be done and then return
	// ctx.Err().
	block bool
	// beforeConnect runs at the top of Connect, before any blocking.
	beforeConnect func()

	mu    sync.Mutex
	cfg   protocol.ConnectConfig
	calls int
}

func newFakeTransport(c *fakeConn) *fakeTransport {
	return &fakeTransport{kind: "fake", origin: "fake://server", conn: c}
}

func (t *fakeTransport) Kind() string { return t.kind }

func (t *fakeTransport) RedactedOrigin() string { return t.origin }

func (t *fakeTransport) Connect(ctx context.Context, cfg protocol.ConnectConfig) (protocol.Conn, error) {
	t.mu.Lock()
	t.cfg = cfg
	t.calls++
	t.mu.Unlock()

	if t.beforeConnect != nil {
		t.beforeConnect()
	}
	if t.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if t.err != nil {
		return nil, t.err
	}
	if t.conn == nil {
		// A broken transport: success with no connection. Returned as an
		// untyped nil, which is the only nil a Conn interface can be checked
		// for — a transport handing back a typed nil pointer would panic
		// inside its own code long before the client saw it.
		return nil, nil
	}
	return t.conn, nil
}

// lastConfig returns the ConnectConfig of the most recent Connect call.
func (t *fakeTransport) lastConfig() protocol.ConnectConfig {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg
}

// connectCalls reports how many times Connect was called.
func (t *fakeTransport) connectCalls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

// okConn returns a conn whose Initialize succeeds with a representative result.
func okConn() *fakeConn {
	return &fakeConn{initResult: protocol.InitializeResult{
		Server:          protocol.ServerIdentity{Name: "srv", Version: "1.2.3", Title: "Test Server"},
		ProtocolVersion: "2025-06-18",
		Capabilities:    protocol.ServerCapabilities{Tools: true},
	}}
}

// okDefinition returns a minimal valid Definition wired to tr.
func okDefinition(tr TransportFactory) Definition {
	return Definition{Name: "srv", Transport: tr}
}

// stub handlers. Each is the smallest type that satisfies its interface; the
// behaviour behind them is implemented in later tasks.

type stubElicitation struct{}

func (stubElicitation) Elicit(context.Context, ElicitRequest) (ElicitResult, error) {
	return ElicitResult{Action: ElicitDecline}, nil
}

type stubSampling struct{}

func (stubSampling) Sample(context.Context, SampleRequest) (SampleResult, error) {
	return SampleResult{}, nil
}

type stubRoots struct{}

func (stubRoots) Roots(context.Context) ([]Root, error) { return nil, nil }

// eventRecorder collects events emitted to a Handlers.Event callback.
type eventRecorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *eventRecorder) handle(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *eventRecorder) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	copy(out, r.events)
	return out
}

// states returns the To state of every StateChanged event, in order.
func (r *eventRecorder) states() []State {
	var out []State
	for _, e := range r.snapshot() {
		if sc, ok := e.(StateChanged); ok {
			out = append(out, sc.To)
		}
	}
	return out
}

// watcherCancelled reports whether Close has deregistered the client's
// lifecycle watcher. It reads an internal detail deliberately: once the machine
// is terminal no transition can prove the watcher is gone, and a leaked watcher
// is exactly what would keep a closed binding alive.
func (c *Client) watcherCancelled() bool { return c.unwatch == nil }

// Compile-time proof that the test stubs satisfy the handler interfaces, so a
// change to one is a build failure here rather than a runtime surprise.
var (
	_ ElicitationHandler = stubElicitation{}
	_ SamplingHandler    = stubSampling{}
	_ RootsProvider      = stubRoots{}
	_ Event              = StateChanged{}
)

// shortStartup returns a Definition with a startup timeout small enough to make
// a blocking transport fail fast.
func shortStartup(d Definition, dur time.Duration) Definition {
	d.Timeouts.Startup = dur
	return d
}
