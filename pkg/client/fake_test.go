// Test doubles shared by the client tests. They live in package client (not
// client_test) because they implement TransportFactory, whose Connect signature
// names internal/protocol types — a sealed, module-internal boundary.

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
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

	// The catalog this conn serves. Each family is a single page unless
	// toolPages is set, which scripts tools/list page by page (indexed by the
	// cursor "p<n>", as the discovery tests do).
	tools     []protocol.ToolSpec
	prompts   []protocol.PromptSpec
	resources []protocol.ResourceSpec
	templates []protocol.ResourceTemplateSpec
	toolPages []protocol.ToolPage

	// listErr, when set, fails tools/list — the discovery failure a Client has
	// to unwind from.
	listErr error
	// lists counts every list call.
	lists atomic.Int32

	// The call surface. callResult is returned by CallTool unless callErr is
	// set; callBlock makes it wait for ctx instead, which is how a deadline or
	// a cancellation is exercised without a real slow server.
	callResult protocol.ToolResult
	callErr    error
	callBlock  bool
	// callProgress, when set, is emitted to the call's progress callback before
	// CallTool blocks or returns.
	callProgress []protocol.ProgressUpdate

	promptResult   protocol.PromptResult
	promptErr      error
	resourceResult protocol.ResourceResult
	resourceErr    error
	subscribeErr   error

	logLevelErr error

	mu sync.Mutex
	// calls records the raw name of every CallTool, and logLevel the level the
	// client asked for, so a test can assert on what reached the wire.
	calls     []string
	logLevel  string
	logLevels int
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

func (c *fakeConn) ListTools(_ context.Context, cursor string) (protocol.ToolPage, error) {
	c.lists.Add(1)
	if c.listErr != nil {
		return protocol.ToolPage{}, c.listErr
	}
	if c.toolPages != nil {
		i := 0
		if cursor != "" {
			if _, err := fmt.Sscanf(cursor, "p%d", &i); err != nil {
				return protocol.ToolPage{}, fmt.Errorf("fake: unroutable cursor %q", cursor)
			}
		}
		if i >= len(c.toolPages) {
			return protocol.ToolPage{}, fmt.Errorf("fake: no page %d", i)
		}
		return c.toolPages[i], nil
	}
	return protocol.ToolPage{Tools: c.tools}, nil
}

func (c *fakeConn) CallTool(ctx context.Context, rawName string, _ json.RawMessage, opts protocol.CallOptions) (protocol.ToolResult, error) {
	c.mu.Lock()
	c.calls = append(c.calls, rawName)
	c.mu.Unlock()

	for _, u := range c.callProgress {
		if opts.Progress != nil {
			opts.Progress(u)
		}
	}
	if c.callBlock {
		<-ctx.Done()
		return protocol.ToolResult{}, ctx.Err()
	}
	if c.callErr != nil {
		return protocol.ToolResult{}, c.callErr
	}
	return c.callResult, nil
}

func (c *fakeConn) GetPrompt(_ context.Context, _ string, _ map[string]string) (protocol.PromptResult, error) {
	if c.promptErr != nil {
		return protocol.PromptResult{}, c.promptErr
	}
	return c.promptResult, nil
}

func (c *fakeConn) ReadResource(_ context.Context, _ string) (protocol.ResourceResult, error) {
	if c.resourceErr != nil {
		return protocol.ResourceResult{}, c.resourceErr
	}
	return c.resourceResult, nil
}

func (c *fakeConn) Subscribe(_ context.Context, _ string) error { return c.subscribeErr }

func (c *fakeConn) SetLogLevel(_ context.Context, level string) error {
	c.mu.Lock()
	c.logLevel = level
	c.logLevels++
	c.mu.Unlock()
	return c.logLevelErr
}

// callNames returns the raw names CallTool was asked for, in order.
func (c *fakeConn) callNames() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// requestedLogLevel returns the level the client asked the server for, and how
// many times it asked.
func (c *fakeConn) requestedLogLevel() (string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.logLevel, c.logLevels
}

func (c *fakeConn) ListPrompts(context.Context, string) (protocol.PromptPage, error) {
	c.lists.Add(1)
	return protocol.PromptPage{Prompts: c.prompts}, nil
}

func (c *fakeConn) ListResources(context.Context, string) (protocol.ResourcePage, error) {
	c.lists.Add(1)
	return protocol.ResourcePage{Resources: c.resources}, nil
}

func (c *fakeConn) ListResourceTemplates(context.Context, string) (protocol.ResourceTemplatePage, error) {
	c.lists.Add(1)
	return protocol.ResourceTemplatePage{Templates: c.templates}, nil
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
	// untypedNil, when true, makes Connect report success with a plain nil
	// Conn, as opposed to the typed nil a nil conn field produces.
	untypedNil bool
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
	if t.untypedNil {
		return nil, nil
	}
	// A nil t.conn is returned as the typed nil it is, yielding a NON-nil Conn
	// interface holding a nil *fakeConn: the harder of the two "transport
	// reported success with no connection" bugs, which a bare `conn == nil`
	// check misses and which then panics inside Connect on the caller's
	// goroutine.
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

// okConn returns a conn whose Initialize succeeds with a representative result
// and which serves a small, valid catalog — enough for startup to get through
// discovery and reach ready.
func okConn() *fakeConn {
	return &fakeConn{
		initResult: protocol.InitializeResult{
			Server:          protocol.ServerIdentity{Name: "srv", Version: "1.2.3", Title: "Test Server"},
			ProtocolVersion: "2025-06-18",
			Capabilities:    protocol.ServerCapabilities{Tools: true},
		},
		tools: []protocol.ToolSpec{fakeTool("echo")},
	}
}

// fakeTool is a minimal well-formed tool spec.
func fakeTool(name string) protocol.ToolSpec {
	return protocol.ToolSpec{
		RawName:     name,
		Description: name + " tool",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}
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

// watcherCancelled reports whether the client's lifecycle watcher is actually
// deregistered from the machine. It asks the machine rather than reading
// c.unwatch, which would only prove the field was nilled next to the call and
// not that the cancel ran. Nothing observable proves this otherwise: the
// machine is terminal after Close, so no transition can be made to reveal a
// surviving watcher, and a watcher spawns no goroutine for a leak check to
// count.
func (c *Client) watcherCancelled() bool { return c.machine.WatcherCount() == 0 }

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
