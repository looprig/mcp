// These tests prove the fixture is a working MCP server, because everything
// Phase 2 asserts about the stdio transport is only as trustworthy as the
// server on the other end of it.
//
// They drive the fixture two ways, deliberately:
//
//   - through the SDK's own client, for everything that is about protocol
//     behavior (tools, prompts, resources, cancellation, notifications); and
//   - through a hand-written JSON-RPC client over raw pipes, for the two things
//     the SDK client cannot see — what is actually on stdout, and how the
//     process dies.
//
// The raw client is a client, not a server. The fixture stays honest.
package mcptest_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testTimeout bounds every test that talks to a subprocess, so a hung fixture
// fails with a message instead of the package timing out anonymously.
const testTimeout = 60 * time.Second

// intPtr lets a table case state an expected length of zero without it being
// mistaken for "unset".
func intPtr(n int) *int { return &n }

// lockedBuffer collects a subprocess's stderr. os/exec writes to it from a
// goroutine it owns, so the test cannot read it unguarded — under -race, that
// is a failure, and without -race it is a lie.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// connect builds the fixture, runs it with args, and returns an initialized
// SDK client session plus its stderr. The session is closed when the test ends,
// which is also what stops the process.
func connect(t *testing.T, ctx context.Context, opts *mcp.ClientOptions, args ...string) (*mcp.ClientSession, *lockedBuffer) {
	t.Helper()

	bin := mcptest.BuildFixture(t)
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- bin is built by this package into the test's TempDir; args are test literals
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr

	client := mcp.NewClient(&mcp.Implementation{Name: "mcptest-client", Version: "0.0.1"}, opts)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connecting to fixture: %v\nstderr:\n%s", err, stderr.String())
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Logf("closing session: %v (stderr: %s)", err, stderr.String())
		}
	})
	return session, stderr
}

// callText calls a tool and returns the text of its single text content item.
// Everything the fixture returns has that shape, so a test that wants the text
// should not have to restate the union each time.
func callText(t *testing.T, ctx context.Context, s *mcp.ClientSession, name string, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%q): unexpected transport error: %v", name, err)
	}
	return res
}

// textOf extracts the one text item from a result, failing if the result is not
// that shape.
func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("result has %d content items, want 1: %+v", len(res.Content), res.Content)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

func TestInitialize(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	const instructions = "be excellent to each other"
	session, _ := connect(t, ctx, nil, "-instructions", instructions, "-prompts", "-resources")

	got := session.InitializeResult()
	if got.ServerInfo.Name != mcptest.ServerName {
		t.Errorf("server name = %q, want %q", got.ServerInfo.Name, mcptest.ServerName)
	}
	if got.ServerInfo.Version != mcptest.ServerVersion {
		t.Errorf("server version = %q, want %q", got.ServerInfo.Version, mcptest.ServerVersion)
	}
	if got.Instructions != instructions {
		t.Errorf("instructions = %q, want %q", got.Instructions, instructions)
	}
	if got.Capabilities == nil {
		t.Fatal("server advertised no capabilities")
	}
	if got.Capabilities.Tools == nil {
		t.Error("server did not advertise the tools capability")
	}
	if got.Capabilities.Prompts == nil {
		t.Error("-prompts did not advertise the prompts capability")
	}
	if got.Capabilities.Resources == nil {
		t.Error("-resources did not advertise the resources capability")
	}
}

func TestInitializeWithoutOptionalFeatures(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// The bare command: the flags are opt-in, and a test that asks for nothing
	// must not get prompts, resources, or instructions anyway.
	session, _ := connect(t, ctx, nil)

	got := session.InitializeResult()
	if got.Instructions != "" {
		t.Errorf("instructions = %q, want empty", got.Instructions)
	}
	if got.Capabilities.Prompts != nil {
		t.Error("prompts capability advertised without -prompts")
	}
	if got.Capabilities.Resources != nil {
		t.Error("resources capability advertised without -resources")
	}
}

func TestListTools(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	session, _ := connect(t, ctx, nil)
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	byName := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		byName[tool.Name] = tool
	}
	for _, want := range []string{mcptest.ToolEcho, mcptest.ToolSlow, mcptest.ToolFail, mcptest.ToolBig} {
		if _, ok := byName[want]; !ok {
			t.Errorf("tool %q missing; got %v", want, res.Tools)
		}
	}
	// Off by default, and the flags are the only way on.
	for _, unwanted := range []string{mcptest.ToolMutate, mcptest.ToolCrash, mcptest.ToolMutated} {
		if _, ok := byName[unwanted]; ok {
			t.Errorf("tool %q present without its flag", unwanted)
		}
	}

	// The input schemas must be well-formed, not merely present: a client that
	// can't read them can't call the tool.
	echo, ok := byName[mcptest.ToolEcho]
	if !ok {
		t.Fatal("no echo tool to check the schema of")
	}
	schema := decodeSchema(t, echo.InputSchema)
	if schema.Type != "object" {
		t.Errorf("echo input schema type = %q, want \"object\"", schema.Type)
	}
	if _, ok := schema.Properties["text"]; !ok {
		t.Errorf("echo input schema has no \"text\" property: %+v", schema.Properties)
	}
	if len(schema.Required) != 1 || schema.Required[0] != "text" {
		t.Errorf("echo input schema required = %v, want [text]", schema.Required)
	}
}

// inputSchema is the slice of JSON Schema these tests assert on. The SDK hands
// the client the schema as a map[string]any; this is the serialization boundary
// where it becomes a type again.
type inputSchema struct {
	Type       string                     `json:"type"`
	Properties map[string]json.RawMessage `json:"properties"`
	Required   []string                   `json:"required"`
}

func decodeSchema(t *testing.T, raw any) inputSchema {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshaling input schema: %v", err)
	}
	var s inputSchema
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("decoding input schema %s: %v", b, err)
	}
	return s
}

func TestTools(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	session, _ := connect(t, ctx, nil)

	tests := []struct {
		name    string
		tool    string
		args    any
		wantErr bool // the tool result carries IsError
		// Exactly one of these three says what the text must be: an exact
		// match, a substring (for messages whose exact wording is not the
		// contract), or a length (for results too big to compare).
		//
		// wantLen is a *int, not an int with a sentinel: 0 is a meaningful
		// length, so any in-band "unset" value would make a case that forgot
		// to set it silently assert len(got) == 0 instead of the text.
		wantText     string
		wantContains string
		wantLen      *int
	}{
		{
			name:     "echo round-trips",
			tool:     mcptest.ToolEcho,
			args:     mcptest.EchoInput{Text: "hello, fixture"},
			wantText: "hello, fixture",
		},
		{
			name:     "echo of empty text",
			tool:     mcptest.ToolEcho,
			args:     mcptest.EchoInput{Text: ""},
			wantText: "",
		},
		{
			name:     "fail returns a tool error result",
			tool:     mcptest.ToolFail,
			args:     mcptest.FailInput{},
			wantErr:  true,
			wantText: mcptest.DefaultFailMessage,
		},
		{
			name:     "fail reports the given message",
			tool:     mcptest.ToolFail,
			args:     mcptest.FailInput{Message: "boom"},
			wantErr:  true,
			wantText: "boom",
		},
		{
			name:    "big returns the requested size",
			tool:    mcptest.ToolBig,
			args:    mcptest.BigInput{Bytes: 100_000},
			wantLen: intPtr(100_000),
		},
		{
			name:    "big of zero bytes",
			tool:    mcptest.ToolBig,
			args:    mcptest.BigInput{Bytes: 0},
			wantLen: intPtr(0),
		},
		{
			name:         "big beyond the cap is a tool error",
			tool:         mcptest.ToolBig,
			args:         mcptest.BigInput{Bytes: mcptest.MaxBigBytes + 1},
			wantErr:      true,
			wantContains: "out of range",
		},
		{
			name:     "slow with no delay replies",
			tool:     mcptest.ToolSlow,
			args:     mcptest.SlowInput{MS: 0},
			wantText: "slept 0ms",
		},
		{
			name:         "slow with a negative delay is a tool error",
			tool:         mcptest.ToolSlow,
			args:         mcptest.SlowInput{MS: -1},
			wantErr:      true,
			wantContains: "out of range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No t.Parallel: these share one session, and the point of sharing
			// it is that the fixture serves them in sequence over one
			// connection, as a real client does.
			res := callText(t, ctx, session, tt.tool, tt.args)
			if res.IsError != tt.wantErr {
				t.Fatalf("IsError = %v, want %v (content: %+v)", res.IsError, tt.wantErr, res.Content)
			}
			got := textOf(t, res)
			switch {
			case tt.wantLen != nil:
				if len(got) != *tt.wantLen {
					t.Errorf("len(text) = %d, want %d", len(got), *tt.wantLen)
				}
			case tt.wantContains != "":
				if !strings.Contains(got, tt.wantContains) {
					t.Errorf("text = %q, want it to contain %q", got, tt.wantContains)
				}
			default:
				if got != tt.wantText {
					t.Errorf("text = %q, want %q", got, tt.wantText)
				}
			}
		})
	}
}

// TestToolErrorIsNotATransportError is the distinction the "fail" tool exists
// for, stated on its own so that a regression names itself.
func TestToolErrorIsNotATransportError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	session, _ := connect(t, ctx, nil)

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      mcptest.ToolFail,
		Arguments: mcptest.FailInput{Message: "boom"},
	})
	if err != nil {
		t.Fatalf("CallTool returned a transport error; a tool error must arrive as a result: %v", err)
	}
	if !res.IsError {
		t.Error("result.IsError = false, want true")
	}

	// The session survives it: a tool error is not a connection fault.
	after := callText(t, ctx, session, mcptest.ToolEcho, mcptest.EchoInput{Text: "still here"})
	if got := textOf(t, after); got != "still here" {
		t.Errorf("echo after a tool error = %q, want %q", got, "still here")
	}
}

func TestSlowRespectsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	session, stderr := connect(t, ctx, nil)

	// The sleep is far longer than anything this test waits for, so the server
	// can only stop sleeping by being told to.
	callCtx, callCancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer callCancel()

	_, err := session.CallTool(callCtx, &mcp.CallToolParams{
		Name:      mcptest.ToolSlow,
		Arguments: mcptest.SlowInput{MS: 30_000},
	})

	// The client side. Necessary, but on its own it proves nothing about the
	// server: this deadline fires whether or not the fixture ever hears about
	// it, which is exactly how a ctx-ignoring handler would pass.
	if err == nil {
		t.Fatal("CallTool returned nil error, want a cancellation error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded", err)
	}

	// The server side, and the actual claim under test: the fixture observed
	// the cancellation and abandoned the sleep. The marker is the only
	// evidence of it — the reply to a cancelled request is discarded.
	//
	// Polled rather than checked once: cancellation propagates over the wire,
	// so the marker arrives shortly after CallTool returns, not before it.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stderr.String(), mcptest.SlowCancelledMarker) {
		if time.Now().After(deadline) {
			t.Fatalf("the fixture never wrote %q: it did not observe the cancellation and is still sleeping.\nstderr: %q",
				mcptest.SlowCancelledMarker, stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The connection is still good: cancelling a request cancels a request.
	after := callText(t, ctx, session, mcptest.ToolEcho, mcptest.EchoInput{Text: "alive"})
	if got := textOf(t, after); got != "alive" {
		t.Errorf("echo after cancellation = %q, want %q", got, "alive")
	}
}

func TestMutateEmitsToolListChanged(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Buffered so the SDK's notification dispatch never blocks on this test,
	// and deep enough for both mutations plus any the SDK coalesces around them.
	changed := make(chan struct{}, 8)
	opts := &mcp.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) {
			select {
			case changed <- struct{}{}:
			default:
			}
		},
	}
	session, _ := connect(t, ctx, opts, "-mutate")

	awaitChange := func(what string) {
		t.Helper()
		select {
		case <-changed:
		case <-time.After(10 * time.Second):
			t.Fatalf("no tools/list_changed notification after %s", what)
		}
	}
	hasTool := func(name string) bool {
		t.Helper()
		res, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		for _, tool := range res.Tools {
			if tool.Name == name {
				return true
			}
		}
		return false
	}

	if hasTool(mcptest.ToolMutated) {
		t.Fatalf("%q is present before any mutation", mcptest.ToolMutated)
	}

	// Drain anything the server emitted while registering the mutate tool, so
	// the notification this test waits for is the one it caused.
	for len(changed) > 0 {
		<-changed
	}

	if res := callText(t, ctx, session, mcptest.ToolMutate, mcptest.MutateInput{Add: true}); res.IsError {
		t.Fatalf("mutate add failed: %s", textOf(t, res))
	}
	awaitChange("adding " + mcptest.ToolMutated)
	if !hasTool(mcptest.ToolMutated) {
		t.Errorf("%q missing after mutate add", mcptest.ToolMutated)
	}
	// It is a real tool, not a name in a list.
	if got := textOf(t, callText(t, ctx, session, mcptest.ToolMutated, mcptest.EchoInput{Text: "added"})); got != "added" {
		t.Errorf("%s = %q, want %q", mcptest.ToolMutated, got, "added")
	}

	if res := callText(t, ctx, session, mcptest.ToolMutate, mcptest.MutateInput{Add: false}); res.IsError {
		t.Fatalf("mutate remove failed: %s", textOf(t, res))
	}
	awaitChange("removing " + mcptest.ToolMutated)
	if hasTool(mcptest.ToolMutated) {
		t.Errorf("%q still present after mutate remove", mcptest.ToolMutated)
	}
}

func TestPrompts(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	session, _ := connect(t, ctx, nil, "-prompts")

	list, err := session.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if len(list.Prompts) != 1 || list.Prompts[0].Name != mcptest.PromptGreet {
		t.Fatalf("prompts = %+v, want one named %q", list.Prompts, mcptest.PromptGreet)
	}
	args := list.Prompts[0].Arguments
	if len(args) != 1 || args[0].Name != mcptest.GreetArg || !args[0].Required {
		t.Errorf("prompt arguments = %+v, want one required %q", args, mcptest.GreetArg)
	}

	got, err := session.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      mcptest.PromptGreet,
		Arguments: map[string]string{mcptest.GreetArg: "Ada"},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("messages = %+v, want 1", got.Messages)
	}
	text, ok := got.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("message content is %T, want *mcp.TextContent", got.Messages[0].Content)
	}
	if !strings.Contains(text.Text, "Ada") {
		t.Errorf("greeting = %q, want it to mention Ada", text.Text)
	}

	// A missing required argument is the server's to reject: the SDK does not
	// validate prompt arguments.
	if _, err := session.GetPrompt(ctx, &mcp.GetPromptParams{Name: mcptest.PromptGreet}); err == nil {
		t.Error("GetPrompt with no arguments succeeded, want an error")
	}
}

func TestResources(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	session, _ := connect(t, ctx, nil, "-resources")

	list, err := session.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(list.Resources) != 1 || list.Resources[0].URI != mcptest.ResourceStaticURI {
		t.Fatalf("resources = %+v, want one at %q", list.Resources, mcptest.ResourceStaticURI)
	}

	templates, err := session.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}
	if len(templates.ResourceTemplates) != 1 || templates.ResourceTemplates[0].URITemplate != mcptest.ResourceEchoTemplate {
		t.Fatalf("templates = %+v, want one at %q", templates.ResourceTemplates, mcptest.ResourceEchoTemplate)
	}

	tests := []struct {
		name     string
		uri      string
		want     string
		wantErr  bool
		wantMIME string
	}{
		{name: "static resource", uri: mcptest.ResourceStaticURI, want: mcptest.ResourceStaticBody, wantMIME: "text/plain"},
		{name: "template resource", uri: "fixture://echo/banana", want: "banana", wantMIME: "text/plain"},
		{name: "unknown resource", uri: "fixture://nope", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: tt.uri})
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadResource(%q) error = %v, wantErr %v", tt.uri, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(res.Contents) != 1 {
				t.Fatalf("contents = %+v, want 1", res.Contents)
			}
			if res.Contents[0].Text != tt.want {
				t.Errorf("text = %q, want %q", res.Contents[0].Text, tt.want)
			}
			if res.Contents[0].MIMEType != tt.wantMIME {
				t.Errorf("mime = %q, want %q", res.Contents[0].MIMEType, tt.wantMIME)
			}
		})
	}
}

func TestElicitOnInitialize(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	messages := make(chan string, 1)
	opts := &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			select {
			case messages <- req.Params.Message:
			default:
			}
			return &mcp.ElicitResult{Action: "decline"}, nil
		},
	}
	session, _ := connect(t, ctx, opts, "-elicit-on-initialize")

	select {
	case got := <-messages:
		if got != mcptest.ElicitMessage {
			t.Errorf("elicitation message = %q, want %q", got, mcptest.ElicitMessage)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no elicitation request arrived after initialize")
	}

	// Declining the elicitation does not break the session.
	if got := textOf(t, callText(t, ctx, session, mcptest.ToolEcho, mcptest.EchoInput{Text: "ok"})); got != "ok" {
		t.Errorf("echo after elicitation = %q, want %q", got, "ok")
	}
}

// TestElicitOnInitializeWithoutClientSupport pins the fixture's behavior when
// the client cannot elicit: the server complains on stderr and serves anyway.
// A fixture that refused to start here would fail every test that set the flag
// for an unrelated reason.
func TestElicitOnInitializeWithoutClientSupport(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// No ElicitationHandler: the client advertises no elicitation capability.
	session, _ := connect(t, ctx, nil, "-elicit-on-initialize")
	if got := textOf(t, callText(t, ctx, session, mcptest.ToolEcho, mcptest.EchoInput{Text: "served"})); got != "served" {
		t.Errorf("echo = %q, want %q", got, "served")
	}
}

// ---------------------------------------------------------------------------
// Raw-pipe tests: what the SDK client cannot see.
// ---------------------------------------------------------------------------

// rawClient is a minimal JSON-RPC client over the fixture's pipes. It exists
// for the two questions the SDK client answers by hiding them: what bytes are
// on stdout, and how the process exits.
type rawClient struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *lockedBuffer
}

func startRaw(t *testing.T, ctx context.Context, args ...string) *rawClient {
	t.Helper()

	bin := mcptest.BuildFixture(t)
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- bin is built by this package into the test's TempDir; args are test literals

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting fixture: %v", err)
	}
	c := &rawClient{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: stderr}
	t.Cleanup(func() {
		// Best effort: these tests own the process's death, so a failure here
		// usually means it is already gone.
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return c
}

// send writes one newline-delimited JSON-RPC message.
func (c *rawClient) send(t *testing.T, msg string) {
	t.Helper()
	if _, err := io.WriteString(c.stdin, msg+"\n"); err != nil {
		t.Fatalf("writing %s: %v (stderr: %s)", msg, err, c.stderr.String())
	}
}

// readLine reads one line of stdout.
func (c *rawClient) readLine(t *testing.T) (string, error) {
	t.Helper()
	line, err := c.stdout.ReadString('\n')
	return strings.TrimRight(line, "\n"), err
}

// handshake performs initialize + notifications/initialized and returns the
// initialize response line.
//
// Note the order: the initialize response is read before the initialized
// notification is sent. That is what a client does, and it also keeps stdin
// open until the reply is in hand — see the comment on closeStdin.
func (c *rawClient) handshake(t *testing.T) string {
	t.Helper()
	c.send(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"0.0.1"}}}`)
	line, err := c.readLine(t)
	if err != nil {
		t.Fatalf("reading initialize response: %v (stderr: %s)", err, c.stderr.String())
	}
	c.send(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return line
}

// closeStdin ends the session the way the MCP spec says a client should.
//
// Read the replies you care about first. Closing stdin is a stop, not a flush,
// and a reply not yet written is dropped — see "Shutdown: closing stdin is a
// stop, not a flush" in the mcptest package doc for the full semantics and the
// exit codes.
func (c *rawClient) closeStdin(t *testing.T) {
	t.Helper()
	if err := c.stdin.Close(); err != nil {
		t.Fatalf("closing stdin: %v", err)
	}
}

// jsonRPCEnvelope is the part of a JSON-RPC message the framing test checks. If
// a line decodes into this with the right version, it is protocol traffic; if it
// does not, something wrote to stdout that had no business there.
type jsonRPCEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// TestStdoutCarriesOnlyMCPFraming is the critical one: stdout is the transport.
// A server that prints anything to it — a log line, a stray fmt.Println, the
// stderr noise going to the wrong stream — corrupts the framing, and the
// failure surfaces far from the cause.
func TestStdoutCarriesOnlyMCPFraming(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	const noiseBytes = 64 * 1024
	c := startRaw(t, ctx, "-noise-bytes", fmt.Sprint(noiseBytes), "-prompts", "-resources", "-mutate")

	lines := 0
	// check validates one line and reports whether it is a response, and to
	// which id. Every line on stdout goes through here: that is the assertion.
	check := func(line string) jsonRPCEnvelope {
		t.Helper()
		lines++
		var env jsonRPCEnvelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("stdout line %d is not JSON — stdout must carry only MCP framing.\nline: %q\nerror: %v", lines, line, err)
		}
		if env.JSONRPC != "2.0" {
			t.Errorf("stdout line %d has jsonrpc = %q, want \"2.0\": %s", lines, env.JSONRPC, line)
		}
		if env.Method == "" && env.Result == nil && env.Error == nil {
			t.Errorf("stdout line %d is neither a request, response, nor error: %s", lines, line)
		}
		if strings.Contains(line, "MCPTEST-NOISE") {
			t.Fatalf("stderr noise reached stdout on line %d: %s", lines, line)
		}
		return env
	}

	init := check(c.handshake(t))
	if !strings.Contains(string(init.Result), "serverInfo") {
		t.Errorf("first stdout line is not an initialize response: %s", init.Result)
	}

	// Exercise the server past the handshake, including a mutation — which
	// makes it send a notification unprompted. The notification is protocol
	// traffic and belongs on stdout; nothing else does.
	requests := map[string]string{
		"2": `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		"3": `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`,
		"4": `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mutate","arguments":{"add":true}}}`,
		"5": `{"jsonrpc":"2.0","id":5,"method":"prompts/list"}`,
		"6": `{"jsonrpc":"2.0","id":6,"method":"resources/list"}`,
	}
	for _, id := range []string{"2", "3", "4", "5", "6"} {
		c.send(t, requests[id])
	}

	// Read every reply before closing stdin: closing it is a shutdown, and a
	// reply not yet written is dropped. Notifications interleave freely, hence
	// waiting on the ids rather than on a line count.
	pending := len(requests)
	for pending > 0 {
		line, err := c.readLine(t)
		if err != nil {
			t.Fatalf("reading stdout with %d replies outstanding: %v (stderr had %d bytes)", pending, err, c.stderr.Len())
		}
		env := check(line)
		if len(env.ID) == 0 {
			continue // a notification; it still had to be valid framing
		}
		id := string(env.ID)
		if _, ok := requests[id]; !ok {
			t.Fatalf("response to unknown id %s: %s", id, line)
		}
		delete(requests, id)
		pending--
	}

	// Now shut down and account for every remaining byte through EOF.
	c.closeStdin(t)
	for {
		line, err := c.readLine(t)
		if line != "" {
			check(line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("draining stdout: %v", err)
		}
	}

	if lines < 6 {
		t.Errorf("stdout carried %d messages, want at least 6 (one per request)", lines)
	}

	// The noise did happen — otherwise this test proves stdout is clean only
	// because nothing was ever written anywhere.
	if got := c.stderr.Len(); got != noiseBytes {
		t.Errorf("stderr has %d bytes, want exactly %d", got, noiseBytes)
	}
	if !strings.Contains(c.stderr.String(), "MCPTEST-NOISE") {
		t.Error("stderr does not contain the noise marker")
	}
}

// TestCrashExitsNonZero drives the crash tool over raw pipes because the SDK's
// CommandTransport owns the process's Wait: this test needs the exit status,
// which is the whole point of the mode.
func TestCrashExitsNonZero(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	const wantCode = 9
	c := startRaw(t, ctx, "-crash", "-crash-exit-code", fmt.Sprint(wantCode))
	c.handshake(t)

	c.send(t, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"crash"}}`)

	// No reply, and no clean shutdown: stdout ends without an answer to id 2.
	line, err := c.readLine(t)
	if err == nil {
		t.Fatalf("got a reply to the crash call, want the process to die: %s", line)
	}
	if !errors.Is(err, io.EOF) {
		t.Logf("stdout read after crash: %v", err) // a broken pipe is equally valid
	}

	waitErr := c.cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		t.Fatalf("fixture exited with %v, want a non-zero exit (stderr: %s)", waitErr, c.stderr.String())
	}
	if got := exitErr.ExitCode(); got != wantCode {
		t.Errorf("exit code = %d, want %d", got, wantCode)
	}
}

// TestBadFlagsFailAtStartup: a misconfigured fixture must die immediately with
// a message, not serve a subtly wrong protocol.
func TestBadFlagsFailAtStartup(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	bin := mcptest.BuildFixture(t)
	// A crash exit code of 0 is not a crash; Validate rejects it.
	cmd := exec.CommandContext(ctx, bin, "-crash", "-crash-exit-code", "0") // #nosec G204 -- bin is built by this package into the test's TempDir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("fixture started with an invalid crash exit code; output: %s", out)
	}
	if !strings.Contains(string(out), "crash exit code") {
		t.Errorf("output = %q, want it to name the bad flag", out)
	}
}

// ---------------------------------------------------------------------------
// Unit tests: no subprocess.
// ---------------------------------------------------------------------------

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     mcptest.Config
		wantErr bool
	}{
		{name: "zero value is valid", cfg: mcptest.Config{}},
		{
			name: "everything on",
			cfg: mcptest.Config{
				Instructions:       "hi",
				Prompts:            true,
				Resources:          true,
				Mutate:             true,
				Crash:              true,
				CrashExitCode:      mcptest.DefaultCrashExitCode,
				NoiseBytes:         1024,
				ElicitOnInitialize: true,
			},
		},
		{name: "crash exit code is ignored when crash is off", cfg: mcptest.Config{CrashExitCode: 0}},
		{name: "crash exit code zero", cfg: mcptest.Config{Crash: true, CrashExitCode: 0}, wantErr: true},
		{name: "crash exit code negative", cfg: mcptest.Config{Crash: true, CrashExitCode: -1}, wantErr: true},
		{name: "crash exit code at the low bound", cfg: mcptest.Config{Crash: true, CrashExitCode: 1}},
		{name: "crash exit code at the high bound", cfg: mcptest.Config{Crash: true, CrashExitCode: 125}},
		{name: "crash exit code above the bound", cfg: mcptest.Config{Crash: true, CrashExitCode: 126}, wantErr: true},
		{name: "noise bytes negative", cfg: mcptest.Config{NoiseBytes: -1}, wantErr: true},
		{name: "noise bytes at the bound", cfg: mcptest.Config{NoiseBytes: mcptest.MaxNoiseBytes}},
		{name: "noise bytes above the bound", cfg: mcptest.Config{NoiseBytes: mcptest.MaxNoiseBytes + 1}, wantErr: true},
		{
			name:    "instructions above the bound",
			cfg:     mcptest.Config{Instructions: strings.Repeat("a", mcptest.MaxInstructionsBytes+1)},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.cfg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			// NewServer must agree with Validate: a config that validates must
			// build, and one that does not must not.
			_, err := mcptest.NewServer(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteNoise(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		n       int
		wantErr bool
	}{
		{name: "zero writes nothing", n: 0},
		{name: "one byte", n: 1},
		{name: "less than one line", n: 10},
		{name: "exactly one line", n: 80},
		{name: "many lines", n: 10_000},
		{name: "at the bound", n: mcptest.MaxNoiseBytes},
		{name: "negative", n: -1, wantErr: true},
		{name: "above the bound", n: mcptest.MaxNoiseBytes + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := mcptest.WriteNoise(&buf, tt.n)
			if (err != nil) != tt.wantErr {
				t.Fatalf("WriteNoise(%d) error = %v, wantErr %v", tt.n, err, tt.wantErr)
			}
			if tt.wantErr {
				if buf.Len() != 0 {
					t.Errorf("WriteNoise wrote %d bytes on error, want 0", buf.Len())
				}
				return
			}
			if buf.Len() != tt.n {
				t.Errorf("WriteNoise wrote %d bytes, want exactly %d", buf.Len(), tt.n)
			}
		})
	}
}

// TestWriteNoiseReportsWriteErrors: the noise is a diagnostic, but a diagnostic
// that silently fails to be written is worse than none.
func TestWriteNoiseReportsWriteErrors(t *testing.T) {
	t.Parallel()
	if err := mcptest.WriteNoise(errWriter{}, 100); err == nil {
		t.Error("WriteNoise returned nil for a failing writer, want an error")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("no") }
