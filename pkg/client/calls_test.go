package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
)

// connectTo brings up a Client over conn and closes it when the test ends.
func connectTo(t *testing.T, conn *fakeConn, shape func(*Definition)) *Client {
	t.Helper()
	def := okDefinition(newFakeTransport(conn))
	if shape != nil {
		shape(&def)
	}
	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// allCapsConn serves every family, so a test opts out of a capability rather
// than forgetting to opt in.
func allCapsConn() *fakeConn {
	c := okConn()
	c.initResult.Capabilities = protocol.ServerCapabilities{
		Tools: true, Prompts: true, Resources: true, ResourcesSubscribe: true, Logging: true,
	}
	c.prompts = []protocol.PromptSpec{{RawName: "greet"}}
	c.resources = []protocol.ResourceSpec{{URI: "x://a"}}
	return c
}

func TestCallToolHappyPath(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.callResult = protocol.ToolResult{
		Content: []protocol.Content{protocol.TextContent{Text: "hi"}},
	}
	c := connectTo(t, conn, nil)

	res, err := c.CallTool(context.Background(), "echo", json.RawMessage(`{"text":"hi"}`), CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if res.IsError {
		t.Error("IsError is set on a successful call")
	}
	if len(res.Content) != 1 {
		t.Fatalf("Content = %+v, want one item", res.Content)
	}
	text, ok := res.Content[0].(Text)
	if !ok {
		t.Fatalf("Content[0] = %T, want client.Text", res.Content[0])
	}
	if text.Text != "hi" {
		t.Errorf("Text = %q, want %q", text.Text, "hi")
	}
	// The raw name is what reaches the wire — never the model-facing one.
	if got := conn.callNames(); len(got) != 1 || got[0] != "echo" {
		t.Errorf("calls = %v, want the raw name echo", got)
	}
}

// TestCallToolProtocolErrorIsAResult is the design's rule: an expected remote
// failure becomes a structured result the model can react to, not a
// control-plane error the host has to handle.
func TestCallToolProtocolErrorIsAResult(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.callResult = protocol.ToolResult{
		IsError: true,
		Content: []protocol.Content{protocol.TextContent{Text: "no such file"}},
	}
	c := connectTo(t, conn, nil)

	res, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v: a tool error must be a result, not an error", err)
	}
	if !res.IsError {
		t.Error("IsError is not set: the caller cannot tell the tool failed")
	}
	if len(res.Content) != 1 {
		t.Errorf("Content = %+v, want the tool's explanation", res.Content)
	}
}

// TestCallToolGates covers the three gates in order, each with the class a
// caller branches on.
func TestCallToolGates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		conn    func() *fakeConn
		shape   func(*Definition)
		rawName string
		want    FailureClass
	}{
		{
			name:    "a tool the filter denies",
			conn:    okConn,
			shape:   func(d *Definition) { d.ToolFilter = ToolFilter{Deny: []string{"echo"}} },
			rawName: "echo",
			want:    FailureToolUnavailable,
		},
		{
			name:    "a tool outside an allow list",
			conn:    okConn,
			shape:   func(d *Definition) { d.ToolFilter = ToolFilter{Allow: []string{"other"}} },
			rawName: "echo",
			want:    FailureToolUnavailable,
		},
		{
			name:    "a tool not in the catalog",
			conn:    okConn,
			rawName: "nonexistent",
			want:    FailureToolUnavailable,
		},
		{
			name: "a server that does not advertise tools",
			conn: func() *fakeConn {
				c := okConn()
				c.initResult.Capabilities = protocol.ServerCapabilities{}
				c.tools = nil
				return c
			},
			rawName: "echo",
			want:    FailureUnsupportedProtocol,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := tt.conn()
			c := connectTo(t, conn, tt.shape)

			_, err := c.CallTool(context.Background(), tt.rawName, nil, CallOpts{})
			if err == nil {
				t.Fatalf("CallTool(%q) succeeded, want it refused", tt.rawName)
			}
			class, ok := ClassOf(err)
			if !ok || class != tt.want {
				t.Errorf("class = %v (ok=%v), want %v", class, ok, tt.want)
			}
			// A refused call never reaches the wire. That is the whole point of
			// gating: a denied tool must not be invoked and then discarded.
			if got := conn.callNames(); len(got) != 0 {
				t.Errorf("a refused call still reached the server: %v", got)
			}
		})
	}
}

// TestCallToolFilterDeniesBeforeLookup: a denied tool is refused whether or not
// it exists, so the error cannot be used to enumerate a filtered server.
func TestCallToolFilterDeniesBeforeLookup(t *testing.T) {
	t.Parallel()

	c := connectTo(t, okConn(), func(d *Definition) {
		d.ToolFilter = ToolFilter{Allow: []string{"nothing"}}
	})

	_, realErr := c.CallTool(context.Background(), "echo", nil, CallOpts{})       // exists, denied
	_, fakeErr := c.CallTool(context.Background(), "not_a_tool", nil, CallOpts{}) // does not exist, denied

	if realErr == nil || fakeErr == nil {
		t.Fatal("a denied call succeeded")
	}
	realClass, _ := ClassOf(realErr)
	fakeClass, _ := ClassOf(fakeErr)
	if realClass != fakeClass {
		t.Errorf("classes differ (%v vs %v): the error distinguishes a real tool from an imaginary one", realClass, fakeClass)
	}
}

// TestCallToolDeadline covers the deadline default and the per-call override.
func TestCallToolDeadline(t *testing.T) {
	t.Parallel()

	t.Run("the binding's request timeout applies by default", func(t *testing.T) {
		t.Parallel()
		conn := okConn()
		conn.callBlock = true
		c := connectTo(t, conn, func(d *Definition) { d.Timeouts.Request = 30 * time.Millisecond })

		start := time.Now()
		_, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
		if err == nil {
			t.Fatal("a blocked call succeeded")
		}
		if class, _ := ClassOf(err); class != FailureDeadline {
			t.Errorf("class = %v, want %v", class, FailureDeadline)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("the call took %v: the request timeout was not applied", elapsed)
		}
	})

	t.Run("an explicit deadline overrides it", func(t *testing.T) {
		t.Parallel()
		conn := okConn()
		conn.callBlock = true
		// A generous binding timeout the per-call deadline must beat.
		c := connectTo(t, conn, func(d *Definition) { d.Timeouts.Request = time.Hour })

		start := time.Now()
		_, err := c.CallTool(context.Background(), "echo", nil, CallOpts{
			Deadline: time.Now().Add(30 * time.Millisecond),
		})
		if err == nil {
			t.Fatal("a blocked call succeeded")
		}
		if class, _ := ClassOf(err); class != FailureDeadline {
			t.Errorf("class = %v, want %v", class, FailureDeadline)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("the call took %v: the per-call deadline was ignored", elapsed)
		}
	})

	t.Run("a cancelled caller is a cancellation, not a deadline", func(t *testing.T) {
		t.Parallel()
		conn := okConn()
		conn.callBlock = true
		c := connectTo(t, conn, nil)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
		_, err := c.CallTool(ctx, "echo", nil, CallOpts{})
		if err == nil {
			t.Fatal("a cancelled call succeeded")
		}
		if class, _ := ClassOf(err); class != FailureCancelled {
			t.Errorf("class = %v, want %v: a caller giving up is not a deadline", class, FailureCancelled)
		}
	})
}

// TestProgressDoesNotExtendTheDeadline is the trap the design names. A server
// that keeps talking must not be able to hold a call open past its deadline:
// otherwise any chatty or hostile server extends its own budget indefinitely,
// and the deadline belongs to the server rather than the host.
func TestProgressDoesNotExtendTheDeadline(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.callBlock = true
	// Progress arrives before the block, and would reset an activity-based
	// timer if one existed.
	conn.callProgress = []protocol.ProgressUpdate{
		{Progress: 1, Total: 10, Message: "working"},
		{Progress: 2, Total: 10, Message: "still working"},
	}

	const deadline = 50 * time.Millisecond
	c := connectTo(t, conn, func(d *Definition) { d.Timeouts.Request = deadline })

	var mu sync.Mutex
	var seen []Progress
	start := time.Now()
	_, err := c.CallTool(context.Background(), "echo", nil, CallOpts{
		Progress: func(p Progress) {
			mu.Lock()
			seen = append(seen, p)
			mu.Unlock()
		},
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a call that only ever reported progress succeeded")
	}
	if class, _ := ClassOf(err); class != FailureDeadline {
		t.Errorf("class = %v, want %v", class, FailureDeadline)
	}
	// The margin is generous: what is being proven is that the deadline still
	// fires at all, not its precision.
	if elapsed > 20*deadline {
		t.Errorf("the call ran for %v against a %v deadline: progress extended it", elapsed, deadline)
	}

	// And the progress genuinely reached the caller — otherwise this test would
	// pass against a client that silently dropped it, which is a different bug.
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("progress callbacks = %d, want 2", len(seen))
	}
	if seen[0].Message != "working" || seen[0].Progress != 1 || seen[0].Total != 10 {
		t.Errorf("progress[0] = %+v, want the server's report", seen[0])
	}
	if seen[0].Binding != "srv" {
		t.Errorf("progress[0].Binding = %q, want the binding tagged", seen[0].Binding)
	}
}

// TestCallToolWithoutProgressAsksForNone: a nil Progress must not attach a
// token, because a token is what invites the notifications.
func TestCallToolWithoutProgressAsksForNone(t *testing.T) {
	t.Parallel()

	var gotOpts protocol.CallOptions
	conn := okConn()
	c := connectTo(t, conn, nil)

	// Reach the conn through the client's own path, capturing what it passed.
	orig := c.conn
	c.conn = &optionCapturingConn{Conn: orig, capture: func(o protocol.CallOptions) { gotOpts = o }}

	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if gotOpts.Progress != nil {
		t.Error("a call with no Progress still registered a progress callback, which asks the server to send notifications nobody wants")
	}

	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{Progress: func(Progress) {}}); err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if gotOpts.Progress == nil {
		t.Error("a call with Progress did not register a callback")
	}
}

// optionCapturingConn records the CallOptions a call was made with.
type optionCapturingConn struct {
	protocol.Conn
	capture func(protocol.CallOptions)
}

func (c *optionCapturingConn) CallTool(ctx context.Context, name string, args json.RawMessage, opts protocol.CallOptions) (protocol.ToolResult, error) {
	c.capture(opts)
	return c.Conn.CallTool(ctx, name, args, opts)
}

func TestGetPrompt(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		conn := allCapsConn()
		conn.promptResult = protocol.PromptResult{
			Description: "a greeting",
			Messages: []protocol.PromptMessage{
				{Role: "user", Content: protocol.TextContent{Text: "Hello, Ada!"}},
			},
		}
		c := connectTo(t, conn, nil)

		got, err := c.GetPrompt(context.Background(), "greet", map[string]string{"name": "Ada"})
		if err != nil {
			t.Fatalf("GetPrompt() error = %v", err)
		}
		if got.Description != "a greeting" {
			t.Errorf("Description = %q", got.Description)
		}
		if len(got.Messages) != 1 || got.Messages[0].Role != "user" {
			t.Fatalf("Messages = %+v", got.Messages)
		}
		text, ok := got.Messages[0].Content.(Text)
		if !ok || text.Text != "Hello, Ada!" {
			t.Errorf("Messages[0].Content = %+v, want the greeting text", got.Messages[0].Content)
		}
	})

	t.Run("a server that does not advertise prompts", func(t *testing.T) {
		t.Parallel()
		c := connectTo(t, okConn(), nil) // tools only
		_, err := c.GetPrompt(context.Background(), "greet", nil)
		if err == nil {
			t.Fatal("GetPrompt() succeeded against a server with no prompts capability")
		}
		if class, _ := ClassOf(err); class != FailureUnsupportedProtocol {
			t.Errorf("class = %v, want %v", class, FailureUnsupportedProtocol)
		}
	})
}

func TestReadResource(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		conn := allCapsConn()
		conn.resourceResult = protocol.ResourceResult{
			Contents: []protocol.ResourceContent{
				{URI: "x://a", MIMEType: "text/plain", Text: "body"},
			},
		}
		c := connectTo(t, conn, nil)

		got, err := c.ReadResource(context.Background(), "x://a")
		if err != nil {
			t.Fatalf("ReadResource() error = %v", err)
		}
		if len(got.Contents) != 1 || got.Contents[0].Text != "body" {
			t.Fatalf("Contents = %+v", got.Contents)
		}
		if got.Contents[0].URI != "x://a" {
			t.Errorf("URI = %q, want the resource's own URI preserved", got.Contents[0].URI)
		}
	})

	t.Run("a server that does not advertise resources", func(t *testing.T) {
		t.Parallel()
		c := connectTo(t, okConn(), nil)
		_, err := c.ReadResource(context.Background(), "x://a")
		if err == nil {
			t.Fatal("ReadResource() succeeded against a server with no resources capability")
		}
		if class, _ := ClassOf(err); class != FailureUnsupportedProtocol {
			t.Errorf("class = %v, want %v", class, FailureUnsupportedProtocol)
		}
	})
}

// TestSubscribe covers the capability gate that is easiest to get wrong:
// subscribing is separate from reading, so a resources server has not thereby
// promised resources/subscribe.
func TestSubscribe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		caps    protocol.ServerCapabilities
		wantErr bool
	}{
		{
			name: "negotiated",
			caps: protocol.ServerCapabilities{Tools: true, Resources: true, ResourcesSubscribe: true},
		},
		{
			name:    "resources without subscribe",
			caps:    protocol.ServerCapabilities{Tools: true, Resources: true},
			wantErr: true,
		},
		{
			name:    "no resources at all",
			caps:    protocol.ServerCapabilities{Tools: true},
			wantErr: true,
		},
		{
			name:    "subscribe advertised without resources",
			caps:    protocol.ServerCapabilities{Tools: true, ResourcesSubscribe: true},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := okConn()
			conn.initResult.Capabilities = tt.caps
			if tt.caps.Resources {
				conn.resources = []protocol.ResourceSpec{{URI: "x://a"}}
			}
			c := connectTo(t, conn, nil)

			err := c.Subscribe(context.Background(), "x://a")
			if (err != nil) != tt.wantErr {
				t.Fatalf("Subscribe() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if class, _ := ClassOf(err); class != FailureUnsupportedProtocol {
					t.Errorf("class = %v, want %v", class, FailureUnsupportedProtocol)
				}
			}
		})
	}
}

// TestCallsAfterCloseAreRefused: every call path must refuse a closed binding,
// which is what makes it safe for Catalog to keep reporting the last catalog.
func TestCallsAfterCloseAreRefused(t *testing.T) {
	t.Parallel()

	conn := allCapsConn()
	c := connectTo(t, conn, nil)
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	tests := []struct {
		name string
		call func() error
	}{
		{"CallTool", func() error { _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); return err }},
		{"GetPrompt", func() error { _, err := c.GetPrompt(context.Background(), "greet", nil); return err }},
		{"ReadResource", func() error { _, err := c.ReadResource(context.Background(), "x://a"); return err }},
		{"Subscribe", func() error { return c.Subscribe(context.Background(), "x://a") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatalf("%s() succeeded on a closed binding", tt.name)
			}
			if class, _ := ClassOf(err); class != FailureShutdown {
				t.Errorf("class = %v, want %v", class, FailureShutdown)
			}
		})
	}
	if got := conn.callNames(); len(got) != 0 {
		t.Errorf("a call on a closed binding reached the server: %v", got)
	}
}

// TestCallFailureClassification checks that a transport's own typed error wins
// over this layer's guess: only the transport can tell a dead process from a
// bad reply.
func TestCallFailureClassification(t *testing.T) {
	t.Parallel()

	t.Run("a transport's typed error passes through", func(t *testing.T) {
		t.Parallel()
		conn := okConn()
		conn.callErr = NewError(FailureTransportClosed, "srv", "call_tool", "the process exited", nil)
		c := connectTo(t, conn, nil)

		_, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
		if class, _ := ClassOf(err); class != FailureTransportClosed {
			t.Errorf("class = %v, want the transport's own %v", class, FailureTransportClosed)
		}
	})

	t.Run("an untyped error becomes a server protocol failure", func(t *testing.T) {
		t.Parallel()
		conn := okConn()
		conn.callErr = errors.New("something went wrong")
		c := connectTo(t, conn, nil)

		_, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
		if class, _ := ClassOf(err); class != FailureServerProtocol {
			t.Errorf("class = %v, want %v", class, FailureServerProtocol)
		}
	})
}

// TestCallToolStructuredPassesThrough checks the structured result reaches the
// caller as raw JSON.
func TestCallToolStructuredPassesThrough(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.callResult = protocol.ToolResult{
		Structured: json.RawMessage(`{"count":3}`),
		Warnings:   []string{"a warning"},
	}
	c := connectTo(t, conn, nil)

	res, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if string(res.Structured) != `{"count":3}` {
		t.Errorf("Structured = %s", res.Structured)
	}
	if len(res.Warnings) != 1 {
		t.Errorf("Warnings = %v, want the conversion's warning carried through", res.Warnings)
	}
}

// TestLogLevelIsRequestedOnlyWhenUsable: an MCP server sends no logs until a
// level is set, but asking for one with no handler installed invites traffic
// nobody reads.
func TestLogLevelIsRequestedOnlyWhenUsable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		logging   bool
		handler   LogHandler
		level     LogLevel
		wantAsked bool
		wantLevel string
	}{
		{
			name:    "handler and a logging server: asked, at the default level",
			logging: true, handler: func(LogMessage) {},
			wantAsked: true, wantLevel: string(DefaultLogLevel),
		},
		{
			name:    "an explicit level is honored",
			logging: true, handler: func(LogMessage) {}, level: LogWarning,
			wantAsked: true, wantLevel: string(LogWarning),
		},
		{
			name:    "no handler: not asked, however loud the server is",
			logging: true, handler: nil,
			wantAsked: false,
		},
		{
			name:    "a server that does not advertise logging: not asked",
			logging: false, handler: func(LogMessage) {},
			wantAsked: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := okConn()
			conn.initResult.Capabilities.Logging = tt.logging

			def := okDefinition(newFakeTransport(conn))
			def.LogLevel = tt.level
			c, err := Connect(context.Background(), def, Handlers{Log: tt.handler})
			if err != nil {
				t.Fatalf("Connect() error = %v", err)
			}
			t.Cleanup(func() { _ = c.Close(context.Background()) })

			level, times := conn.requestedLogLevel()
			if tt.wantAsked {
				if times != 1 {
					t.Fatalf("SetLogLevel called %d times, want 1", times)
				}
				if level != tt.wantLevel {
					t.Errorf("level = %q, want %q", level, tt.wantLevel)
				}
			} else if times != 0 {
				t.Errorf("SetLogLevel called %d times (level %q), want never", times, level)
			}
		})
	}
}

// TestLogMessagesReachTheHandler proves the callback the client hands the
// transport actually routes to the application's handler, bounded and tagged.
func TestLogMessagesReachTheHandler(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var got []LogMessage

	conn := okConn()
	conn.initResult.Capabilities.Logging = true
	tr := newFakeTransport(conn)
	def := okDefinition(tr)

	c, err := Connect(context.Background(), def, Handlers{Log: func(m LogMessage) {
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	}})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	// The transport was handed a log callback; drive it as the SDK would.
	onLog := tr.lastConfig().OnLog
	if onLog == nil {
		t.Fatal("the client installed no log callback despite a handler and a logging server")
	}
	onLog(protocol.LogRecord{Level: "warning", Logger: "srv", Text: "careful"})

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("log messages = %d, want 1", len(got))
	}
	if got[0].Binding != "srv" || got[0].Level != LogWarning || got[0].Text != "careful" {
		t.Errorf("LogMessage = %+v, want it tagged with the binding and carrying the record", got[0])
	}
}

// TestNoLogCallbackWithoutAHandler: with no handler there is nothing to deliver
// to, so the connection is given no callback at all.
func TestNoLogCallbackWithoutAHandler(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.initResult.Capabilities.Logging = true
	tr := newFakeTransport(conn)

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	if tr.lastConfig().OnLog != nil {
		t.Error("the client installed a log callback with no handler to deliver to")
	}
}

func TestLogLevelValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level   LogLevel
		wantErr bool
	}{
		{"", false}, // selects the default
		{LogDebug, false},
		{LogEmergency, false},
		{"verbose", true},
		{"DEBUG", true}, // levels are lowercase on the wire
		{"'; DROP TABLE", true},
	}
	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			t.Parallel()
			def := okDefinition(newFakeTransport(okConn()))
			def.LogLevel = tt.level
			err := def.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if class, _ := ClassOf(err); class != FailureInvalidConfig {
					t.Errorf("class = %v, want %v", class, FailureInvalidConfig)
				}
				if !strings.Contains(err.Error(), "LogLevel") {
					t.Errorf("error = %q, want it to name the field", err)
				}
			}
		})
	}
}
