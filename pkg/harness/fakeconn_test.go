// A scriptable in-memory MCP connection for the adapter's unit tests.
//
// It lives in package mcpharness because it implements client.TransportFactory
// and protocol.Conn, both of which name internal/protocol types — a sealed,
// module-internal boundary. The tagged integration tests drive real subprocess
// servers instead (internal/mcptest); this exists so a unit test can make a
// server hang, fail, or answer on command without a process to schedule.

package mcpharness

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/client"
)

// scriptedTransport is a TransportFactory whose connection a test scripts.
type scriptedTransport struct {
	conn *scriptedConn
	// connectErr, when set, fails the dial itself rather than the handshake.
	connectErr error
	// gate, when non-nil, blocks Connect until it is closed or ctx is done.
	// It is how a test holds a binding in "starting" for as long as it likes.
	gate chan struct{}
	// entered, when non-nil, is closed once Connect has been called, so a test
	// can observe that a dial started rather than sleeping and hoping.
	entered chan struct{}

	enteredOnce sync.Once
	dials       atomic.Int32

	mu  sync.Mutex
	cfg protocol.ConnectConfig
}

// lastConfig returns the ConnectConfig of the most recent Connect. It is how a
// test reaches the callbacks the client installed — a notification must arrive
// the way a real one does, through the connection, not by poking the client.
func (t *scriptedTransport) lastConfig() protocol.ConnectConfig {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg
}

func (t *scriptedTransport) Kind() string           { return "scripted" }
func (t *scriptedTransport) RedactedOrigin() string { return "scripted://fixture" }

func (t *scriptedTransport) Connect(ctx context.Context, cfg protocol.ConnectConfig) (protocol.Conn, error) {
	t.dials.Add(1)
	t.mu.Lock()
	t.cfg = cfg
	t.mu.Unlock()
	if t.entered != nil {
		t.enteredOnce.Do(func() { close(t.entered) })
	}
	if t.gate != nil {
		select {
		case <-t.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if t.connectErr != nil {
		return nil, t.connectErr
	}
	return t.conn, nil
}

// scriptedConn is an in-memory protocol.Conn serving one fixed catalog.
type scriptedConn struct {
	mu sync.Mutex

	server  protocol.ServerIdentity
	version protocol.ProtocolVersion
	caps    protocol.ServerCapabilities
	tools   []protocol.ToolSpec

	// initErr fails the handshake.
	initErr error
	// callResult and callErr script CallTool.
	callResult protocol.ToolResult
	callErr    error

	// calledName and calledArgs record the last CallTool, so a routing test can
	// assert what actually went on the wire rather than what a name suggests.
	calledName string
	calledArgs json.RawMessage

	closes atomic.Int32
	calls  atomic.Int32
}

func newScriptedConn(name string, tools ...protocol.ToolSpec) *scriptedConn {
	return &scriptedConn{
		server:  protocol.ServerIdentity{Name: name, Version: "1.0.0"},
		version: protocol.ProtocolVersion("2025-06-18"),
		caps:    protocol.ServerCapabilities{Tools: true},
		tools:   tools,
	}
}

// tool builds a minimal valid tool spec.
func fakeTool(rawName string) protocol.ToolSpec {
	return protocol.ToolSpec{
		RawName:     rawName,
		Description: "a fixture tool",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
	}
}

// setTools replaces the served catalog. A refresh triggered afterwards sees the
// new one, which is how a test makes a server remove or change a tool.
func (c *scriptedConn) setTools(tools ...protocol.ToolSpec) {
	c.mu.Lock()
	c.tools = tools
	c.mu.Unlock()
}

// setCall scripts the next CallTool outcome.
func (c *scriptedConn) setCall(res protocol.ToolResult, err error) {
	c.mu.Lock()
	c.callResult, c.callErr = res, err
	c.mu.Unlock()
}

// lastCall reports the raw name and arguments of the most recent CallTool.
func (c *scriptedConn) lastCall() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calledName, string(c.calledArgs)
}

func (c *scriptedConn) Initialize(context.Context) (protocol.InitializeResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.initErr != nil {
		return protocol.InitializeResult{}, c.initErr
	}
	return protocol.InitializeResult{
		Server:          c.server,
		ProtocolVersion: c.version,
		Capabilities:    c.caps,
	}, nil
}

func (c *scriptedConn) ListTools(_ context.Context, _ string) (protocol.ToolPage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return protocol.ToolPage{Tools: append([]protocol.ToolSpec(nil), c.tools...)}, nil
}

func (c *scriptedConn) ListPrompts(context.Context, string) (protocol.PromptPage, error) {
	return protocol.PromptPage{}, nil
}

func (c *scriptedConn) ListResources(context.Context, string) (protocol.ResourcePage, error) {
	return protocol.ResourcePage{}, nil
}

func (c *scriptedConn) ListResourceTemplates(context.Context, string) (protocol.ResourceTemplatePage, error) {
	return protocol.ResourceTemplatePage{}, nil
}

func (c *scriptedConn) CallTool(ctx context.Context, rawName string, args json.RawMessage, _ protocol.CallOptions) (protocol.ToolResult, error) {
	c.calls.Add(1)
	c.mu.Lock()
	c.calledName, c.calledArgs = rawName, args
	res, err := c.callResult, c.callErr
	c.mu.Unlock()
	if err != nil {
		return protocol.ToolResult{}, err
	}
	select {
	case <-ctx.Done():
		return protocol.ToolResult{}, ctx.Err()
	default:
	}
	return res, nil
}

func (c *scriptedConn) GetPrompt(context.Context, string, map[string]string) (protocol.PromptResult, error) {
	return protocol.PromptResult{}, fmt.Errorf("scriptedConn: GetPrompt is not scripted")
}

func (c *scriptedConn) ReadResource(context.Context, string) (protocol.ResourceResult, error) {
	return protocol.ResourceResult{}, fmt.Errorf("scriptedConn: ReadResource is not scripted")
}

func (c *scriptedConn) Subscribe(context.Context, string) error   { return nil }
func (c *scriptedConn) SetLogLevel(context.Context, string) error { return nil }

func (c *scriptedConn) Close(context.Context) error {
	c.closes.Add(1)
	return nil
}

// scriptedBinding builds a binding whose server is a scripted transport.
func scriptedBinding(name string, scope Scope, t *scriptedTransport) Binding {
	b := Binding{
		Name:   name,
		Scope:  scope,
		Server: client.Definition{Name: client.Name(name), Transport: t},
	}
	if scope == ScopeSession {
		b.Visibility = AllLoops()
	}
	return b
}
