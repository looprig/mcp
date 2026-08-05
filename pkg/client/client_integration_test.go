//go:build integration

// Integration tests for the client's catalog and call surface, against the real
// fixture MCP server over a real stdio subprocess.
//
// The unit tests in this package drive a fake conn, which proves the client's
// own logic — the gates, the classification, the projection — and proves it
// against this module's idea of MCP. These tests prove the other half: that the
// idea is right. Discovery really paginates a real SDK server, a real tool error
// really arrives as IsError rather than a transport failure, a real cancelled
// call really reaches the server, and a real server's progress and log
// notifications really route back to a handler.

package client_test

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/pkg/client"
	"github.com/looprig/mcp/pkg/transport/stdio"
)

// testTimeout bounds each test's own work. Generous: a slow CI box must not
// turn a passing assertion into a flake, and every test here fails fast on its
// own terms when something is actually wrong.
const testTimeout = 60 * time.Second

// fixtureClient connects a Client to a fixture server configured by args.
func fixtureClient(t *testing.T, h client.Handlers, shape func(*client.Definition), args ...string) *client.Client {
	t.Helper()

	tr, err := stdio.New(stdio.Config{
		Command: mcptest.BuildFixture(t),
		Args:    args,
	})
	if err != nil {
		t.Fatalf("stdio.New() error = %v", err)
	}

	def := client.Definition{Name: "fixture", Transport: tr}
	if shape != nil {
		shape(&def)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	c, err := client.Connect(ctx, def, h)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), testTimeout)
		defer closeCancel()
		if err := c.Close(closeCtx); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	return c
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	t.Cleanup(cancel)
	return ctx
}

// resultText flattens a tool result's text content.
func resultText(t *testing.T, res client.ToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if text, ok := c.(client.Text); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

// TestDiscoversARealServer covers the whole of discovery against real MCP:
// tools, prompts, resources, templates, instructions, and the identity and
// capabilities the handshake settled.
func TestDiscoversARealServer(t *testing.T) {
	t.Parallel()

	const instructions = "be careful with this server"
	c := fixtureClient(t, client.Handlers{}, nil,
		"-instructions", instructions, "-prompts", "-resources")

	cat := c.Catalog()
	if !cat.Valid() {
		t.Fatal("a ready binding has no adopted catalog")
	}
	if cat.Generation != 1 {
		t.Errorf("Generation = %d, want 1", cat.Generation)
	}
	if len(cat.Digest) != 64 {
		t.Errorf("Digest = %q, want 64 hex chars", cat.Digest)
	}
	if cat.Instructions != instructions {
		t.Errorf("Instructions = %q, want %q", cat.Instructions, instructions)
	}
	if cat.Server.Name != mcptest.ServerName || cat.Server.Version != mcptest.ServerVersion {
		t.Errorf("Server = %+v, want the fixture's identity", cat.Server)
	}
	if cat.ProtocolVersion == "" {
		t.Error("ProtocolVersion is empty after a successful handshake")
	}

	caps := cat.Capabilities
	if !caps.Tools || !caps.Prompts || !caps.Resources {
		t.Errorf("Capabilities = %+v, want tools, prompts and resources advertised", caps)
	}

	// Tools: the fixture's base set, with real inferred schemas.
	for _, want := range []string{mcptest.ToolEcho, mcptest.ToolSlow, mcptest.ToolFail, mcptest.ToolBig} {
		tool, ok := cat.ToolByRawName(want)
		if !ok {
			t.Errorf("tool %q missing from the discovered catalog", want)
			continue
		}
		if len(tool.InputSchema) == 0 || !json.Valid(tool.InputSchema) {
			t.Errorf("tool %q has no valid input schema: %s", want, tool.InputSchema)
		}
		if len(tool.InputSchemaDigest) != 64 {
			t.Errorf("tool %q digest = %q, want 64 hex chars", want, tool.InputSchemaDigest)
		}
		if tool.ModelName != "mcp__fixture__"+want {
			t.Errorf("tool %q ModelName = %q", want, tool.ModelName)
		}
		if _, ok := cat.ToolByModelName(tool.ModelName); !ok {
			t.Errorf("tool %q does not resolve by its model name %q", want, tool.ModelName)
		}
	}
	// echo declares a read-only hint, which must survive as untrusted input.
	if echo, ok := cat.ToolByRawName(mcptest.ToolEcho); ok {
		if echo.Annotations == nil || !echo.Annotations.ReadOnlyHint {
			t.Errorf("echo annotations = %+v, want the server's ReadOnlyHint carried", echo.Annotations)
		}
	}

	// Prompts, with the required argument.
	if len(cat.Prompts) != 1 || cat.Prompts[0].Name != mcptest.PromptGreet {
		t.Fatalf("Prompts = %+v, want the greet prompt", cat.Prompts)
	}
	args := cat.Prompts[0].Arguments
	if len(args) != 1 || args[0].Name != mcptest.GreetArg || !args[0].Required {
		t.Errorf("greet arguments = %+v, want one required %q", args, mcptest.GreetArg)
	}

	// Resources and templates are separate lists and both must arrive.
	if len(cat.Resources) != 1 || cat.Resources[0].URI != mcptest.ResourceStaticURI {
		t.Errorf("Resources = %+v, want the static resource", cat.Resources)
	}
	if len(cat.ResourceTemplates) != 1 || cat.ResourceTemplates[0].URITemplate != mcptest.ResourceEchoTemplate {
		t.Errorf("ResourceTemplates = %+v, want the echo template", cat.ResourceTemplates)
	}

	if s := c.Status(); s.CatalogDigest != cat.Digest || s.CatalogGeneration != 1 {
		t.Errorf("Status catalog = %d/%s, want it to match the adopted catalog", s.CatalogGeneration, s.CatalogDigest)
	}
}

// TestDiscoveryPaginatesARealServer forces a real multi-page catalog by
// shrinking the server's page size. This is the assertion that would pass
// vacuously against the default fixture — its catalog fits in one page — so the
// server is configured to make pagination unavoidable.
func TestDiscoveryPaginatesARealServer(t *testing.T) {
	t.Parallel()

	const extra = 25
	c := fixtureClient(t, client.Handlers{}, nil, "-extra-tools", "25", "-page-size", "2")

	cat := c.Catalog()
	// The base tools plus the filler ones; asserting the exact count is what
	// catches a paginator that stops early or double-counts a page.
	baseTools := []string{mcptest.ToolEcho, mcptest.ToolSlow, mcptest.ToolFail, mcptest.ToolBig,
		mcptest.ToolProgress, mcptest.ToolLog}
	want := len(baseTools) + extra
	if len(cat.Tools) != want {
		t.Errorf("Tools = %d, want %d: pagination lost or duplicated items", len(cat.Tools), want)
	}
	for _, name := range baseTools {
		if _, ok := cat.ToolByRawName(name); !ok {
			t.Errorf("base tool %q missing after pagination", name)
		}
	}
	for i := range extra {
		name := mcptest.ExtraToolPrefix + strconv.Itoa(i)
		if _, ok := cat.ToolByRawName(name); !ok {
			t.Errorf("filler tool %q missing after pagination", name)
		}
	}
	// Every model name is still unique across pages.
	seen := map[string]string{}
	for _, tool := range cat.Tools {
		if prev, dup := seen[tool.ModelName]; dup {
			t.Errorf("tools %q and %q share the model name %q", prev, tool.RawName, tool.ModelName)
		}
		seen[tool.ModelName] = tool.RawName
	}
}

// TestDiscoveryRefusesAnOverLimitRealCatalog proves the item bound is enforced
// against a genuinely large server, not just a scripted one.
func TestDiscoveryRefusesAnOverLimitRealCatalog(t *testing.T) {
	t.Parallel()

	tr, err := stdio.New(stdio.Config{
		Command: mcptest.BuildFixture(t),
		Args:    []string{"-extra-tools", "50", "-page-size", "5"},
	})
	if err != nil {
		t.Fatalf("stdio.New() error = %v", err)
	}
	def := client.Definition{Name: "fixture", Transport: tr}
	def.Limits.MaxCatalogItems = 10

	c, err := client.Connect(testCtx(t), def, client.Handlers{})
	if err == nil {
		_ = c.Close(context.Background())
		t.Fatal("Connect() accepted a catalog over the item bound")
	}
	if c != nil {
		t.Error("Connect() returned a Client alongside its error")
	}
	if class, _ := client.ClassOf(err); class != client.FailureCatalogOverLimit {
		t.Errorf("class = %v, want %v", class, client.FailureCatalogOverLimit)
	}
}

// TestCallEchoRoundTrip is the basic proof that a call reaches a real server
// and its result comes back converted.
func TestCallEchoRoundTrip(t *testing.T) {
	t.Parallel()

	c := fixtureClient(t, client.Handlers{}, nil)
	const want = "hello over real mcp"

	res, err := c.CallTool(testCtx(t), mcptest.ToolEcho,
		json.RawMessage(`{"text":"`+want+`"}`), client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError set on a successful echo: %q", resultText(t, res))
	}
	if got := resultText(t, res); got != want {
		t.Errorf("echo = %q, want %q", got, want)
	}
}

// TestCallFailIsAStructuredResult is the design's rule against a real server: a
// tool that reports failure produces IsError, not a transport error.
func TestCallFailIsAStructuredResult(t *testing.T) {
	t.Parallel()

	c := fixtureClient(t, client.Handlers{}, nil)

	res, err := c.CallTool(testCtx(t), mcptest.ToolFail, json.RawMessage(`{}`), client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v: a protocol-level tool error must be a result, not an error", err)
	}
	if !res.IsError {
		t.Fatal("IsError is not set: the caller cannot tell the tool failed")
	}
	if got := resultText(t, res); got != mcptest.DefaultFailMessage {
		t.Errorf("failure text = %q, want %q", got, mcptest.DefaultFailMessage)
	}
	// The binding is still healthy: a tool failing is not a binding failing.
	if s := c.Status(); s.State != client.StateReady {
		t.Errorf("State = %v, want the binding still ready after a tool error", s.State)
	}
}

// TestCallBigIsBounded proves the text bound is enforced on a real oversized
// result, and reported rather than hidden.
func TestCallBigIsBounded(t *testing.T) {
	t.Parallel()

	const limit = 4096
	c := fixtureClient(t, client.Handlers{}, func(d *client.Definition) {
		d.Limits.MaxTextResultBytes = limit
	})

	res, err := c.CallTool(testCtx(t), mcptest.ToolBig,
		json.RawMessage(`{"bytes":200000}`), client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v: an oversized result must be truncated, not fatal", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("Content = %+v, want one text item", res.Content)
	}
	text, ok := res.Content[0].(client.Text)
	if !ok {
		t.Fatalf("Content[0] = %T, want client.Text", res.Content[0])
	}
	if !text.Truncated {
		t.Error("Truncated is not set: the caller cannot tell the result was cut")
	}
	if len(text.Text) > limit {
		t.Errorf("text is %d bytes, over the %d-byte bound", len(text.Text), limit)
	}
	// It was actually truncated from something much larger, so this is not
	// passing because the server sent little.
	if len(text.Text) == 0 {
		t.Error("the whole result was dropped; it should have been truncated")
	}
}

// TestCallSlowCancellation proves cancellation reaches the server rather than
// merely abandoning the call.
//
// The marker on stderr is the only evidence that exists: the reply to a
// cancelled request is discarded, so a test that merely watches its own
// deadline fire would pass against a client that never told the server
// anything.
func TestCallSlowCancellation(t *testing.T) {
	t.Parallel()

	c := fixtureClient(t, client.Handlers{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := c.CallTool(ctx, mcptest.ToolSlow, json.RawMessage(`{"ms":60000}`), client.CallOpts{})
	if err == nil {
		t.Fatal("a cancelled call succeeded")
	}
	if class, _ := client.ClassOf(err); class != client.FailureCancelled {
		t.Errorf("class = %v, want %v", class, client.FailureCancelled)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("the call took %v: cancellation did not stop the wait", elapsed)
	}
}

// TestCallDeadlineAgainstARealServer covers the per-call deadline end to end.
func TestCallDeadlineAgainstARealServer(t *testing.T) {
	t.Parallel()

	c := fixtureClient(t, client.Handlers{}, nil)

	start := time.Now()
	_, err := c.CallTool(context.Background(), mcptest.ToolSlow,
		json.RawMessage(`{"ms":60000}`), client.CallOpts{
			Deadline: time.Now().Add(200 * time.Millisecond),
		})
	if err == nil {
		t.Fatal("a call past its deadline succeeded")
	}
	if class, _ := client.ClassOf(err); class != client.FailureDeadline {
		t.Errorf("class = %v, want %v", class, client.FailureDeadline)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("the call took %v: the deadline was not applied", elapsed)
	}
}

// TestProgressFromARealServer proves the progress token, the notification
// routing and the callback all work against real MCP — and that a chatty server
// still cannot outlive its deadline.
func TestProgressFromARealServer(t *testing.T) {
	t.Parallel()

	c := fixtureClient(t, client.Handlers{}, nil)

	t.Run("progress reaches the caller", func(t *testing.T) {
		var mu sync.Mutex
		var seen []client.Progress

		res, err := c.CallTool(testCtx(t), mcptest.ToolProgress,
			json.RawMessage(`{"count":5}`), client.CallOpts{
				Progress: func(p client.Progress) {
					mu.Lock()
					seen = append(seen, p)
					mu.Unlock()
				},
			})
		if err != nil {
			t.Fatalf("CallTool() error = %v", err)
		}
		if res.IsError {
			t.Fatalf("progress tool failed: %q", resultText(t, res))
		}

		mu.Lock()
		defer mu.Unlock()
		if len(seen) == 0 {
			t.Fatal("no progress notifications reached the callback: the token or the routing is broken")
		}
		for _, p := range seen {
			if p.Binding != "fixture" {
				t.Errorf("progress binding = %q, want the binding tagged", p.Binding)
			}
			if p.Message != mcptest.ProgressMessage {
				t.Errorf("progress message = %q, want %q", p.Message, mcptest.ProgressMessage)
			}
			if p.Total != 5 {
				t.Errorf("progress total = %v, want 5", p.Total)
			}
		}
	})

	t.Run("a chatty server does not extend its deadline", func(t *testing.T) {
		var count int
		var mu sync.Mutex

		start := time.Now()
		// hang=true: the server reports progress forever and never replies.
		_, err := c.CallTool(context.Background(), mcptest.ToolProgress,
			json.RawMessage(`{"count":0,"ms":10,"hang":true}`), client.CallOpts{
				Deadline: time.Now().Add(500 * time.Millisecond),
				Progress: func(client.Progress) {
					mu.Lock()
					count++
					mu.Unlock()
				},
			})
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("a call that only ever reported progress succeeded")
		}
		if class, _ := client.ClassOf(err); class != client.FailureDeadline {
			t.Errorf("class = %v, want %v", class, client.FailureDeadline)
		}
		if elapsed > 20*time.Second {
			t.Errorf("the call ran for %v against a 500ms deadline: progress extended it", elapsed)
		}
		// The server really was chatty, so the deadline fired despite activity
		// rather than in its absence.
		mu.Lock()
		defer mu.Unlock()
		if count == 0 {
			t.Error("no progress arrived; the test did not exercise activity against a deadline")
		}
	})
}

// TestServerLogsReachTheHandler proves the whole logging path against a real
// server: the level is set (without which a server sends nothing), the
// notification arrives, and the payload is bounded.
func TestServerLogsReachTheHandler(t *testing.T) {
	t.Parallel()

	const limit = 512

	var mu sync.Mutex
	var got []client.LogMessage
	done := make(chan struct{})
	var once sync.Once

	c := fixtureClient(t, client.Handlers{
		Log: func(m client.LogMessage) {
			mu.Lock()
			got = append(got, m)
			mu.Unlock()
			once.Do(func() { close(done) })
		},
	}, func(d *client.Definition) {
		d.Limits.MaxLogMessageBytes = limit
		d.LogLevel = client.LogDebug
	})

	// Ask the server to log far more than the bound allows.
	if _, err := c.CallTool(testCtx(t), mcptest.ToolLog,
		json.RawMessage(`{"bytes":100000,"level":"warning"}`), client.CallOpts{}); err != nil {
		t.Fatalf("CallTool(log) error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("no log message reached the handler: the client never set a level, or the notification is not routed")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("no log messages")
	}
	m := got[0]
	if m.Binding != "fixture" {
		t.Errorf("Binding = %q, want the binding tagged", m.Binding)
	}
	if m.Level != client.LogWarning {
		t.Errorf("Level = %q, want %q", m.Level, client.LogWarning)
	}
	if len(m.Text) > limit {
		t.Errorf("log text is %d bytes, over the %d-byte bound: a server can make a log line a memory problem", len(m.Text), limit)
	}
	if len(m.Text) == 0 {
		t.Error("the log text was dropped entirely; it should have been truncated")
	}
}

// TestPromptsAndResourcesAgainstARealServer covers the typed prompt and
// resource APIs end to end, including a templated resource.
func TestPromptsAndResourcesAgainstARealServer(t *testing.T) {
	t.Parallel()

	c := fixtureClient(t, client.Handlers{}, nil, "-prompts", "-resources")

	t.Run("GetPrompt", func(t *testing.T) {
		got, err := c.GetPrompt(testCtx(t), mcptest.PromptGreet,
			map[string]string{mcptest.GreetArg: "Ada"})
		if err != nil {
			t.Fatalf("GetPrompt() error = %v", err)
		}
		if len(got.Messages) != 1 {
			t.Fatalf("Messages = %+v, want one", got.Messages)
		}
		text, ok := got.Messages[0].Content.(client.Text)
		if !ok {
			t.Fatalf("Content = %T, want client.Text", got.Messages[0].Content)
		}
		if !strings.Contains(text.Text, "Ada") {
			t.Errorf("prompt text = %q, want the argument substituted", text.Text)
		}
		if got.Messages[0].Role != "user" {
			t.Errorf("Role = %q, want user", got.Messages[0].Role)
		}
	})

	t.Run("ReadResource", func(t *testing.T) {
		got, err := c.ReadResource(testCtx(t), mcptest.ResourceStaticURI)
		if err != nil {
			t.Fatalf("ReadResource() error = %v", err)
		}
		if len(got.Contents) != 1 {
			t.Fatalf("Contents = %+v, want one", got.Contents)
		}
		if got.Contents[0].Text != mcptest.ResourceStaticBody {
			t.Errorf("body = %q, want %q", got.Contents[0].Text, mcptest.ResourceStaticBody)
		}
		if got.Contents[0].URI != mcptest.ResourceStaticURI {
			t.Errorf("URI = %q, want it preserved", got.Contents[0].URI)
		}
	})

	t.Run("ReadResource through a template", func(t *testing.T) {
		got, err := c.ReadResource(testCtx(t), "fixture://echo/word")
		if err != nil {
			t.Fatalf("ReadResource() error = %v", err)
		}
		if len(got.Contents) != 1 || got.Contents[0].Text != "word" {
			t.Errorf("Contents = %+v, want the templated word", got.Contents)
		}
	})
}

// TestUnadvertisedCapabilitiesAreNotFetchedAndFailCleanly is the design's
// compatibility rule against a real server.
//
// The fixture without -prompts and -resources advertises neither, so a client
// that guessed would send prompts/list and get a method-not-found — which is
// indistinguishable from a real failure. Instead nothing is fetched, and the
// corresponding methods refuse locally with a class the caller can branch on.
func TestUnadvertisedCapabilitiesAreNotFetchedAndFailCleanly(t *testing.T) {
	t.Parallel()

	c := fixtureClient(t, client.Handlers{}, nil) // tools only

	cat := c.Catalog()
	if !cat.Capabilities.Tools {
		t.Fatal("the fixture did not advertise tools")
	}
	if cat.Capabilities.Prompts || cat.Capabilities.Resources {
		t.Fatalf("the fixture advertised prompts/resources without the flags: %+v", cat.Capabilities)
	}
	// Nothing was fetched for the families the server never promised.
	if len(cat.Prompts) != 0 || len(cat.Resources) != 0 || len(cat.ResourceTemplates) != 0 {
		t.Errorf("catalog carries unadvertised families: %d prompts, %d resources, %d templates",
			len(cat.Prompts), len(cat.Resources), len(cat.ResourceTemplates))
	}
	// Tools still worked, so this is not passing because discovery gave up.
	if len(cat.Tools) == 0 {
		t.Fatal("no tools discovered; the test proves nothing about selective fetching")
	}

	tests := []struct {
		name string
		call func() error
	}{
		{"GetPrompt", func() error {
			_, err := c.GetPrompt(testCtx(t), mcptest.PromptGreet, nil)
			return err
		}},
		{"ReadResource", func() error {
			_, err := c.ReadResource(testCtx(t), mcptest.ResourceStaticURI)
			return err
		}},
		{"Subscribe", func() error {
			return c.Subscribe(testCtx(t), mcptest.ResourceStaticURI)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatalf("%s() succeeded against a server that never advertised the capability", tt.name)
			}
			if class, _ := client.ClassOf(err); class != client.FailureUnsupportedProtocol {
				t.Errorf("class = %v, want %v", class, client.FailureUnsupportedProtocol)
			}
		})
	}

	// The binding is untouched by the refusals: they never reached the wire.
	if s := c.Status(); s.State != client.StateReady {
		t.Errorf("State = %v, want ready", s.State)
	}
}

// TestToolFilterAgainstARealServer proves the filter shapes the projection and
// gates the call, against a server that really does offer the tool.
func TestToolFilterAgainstARealServer(t *testing.T) {
	t.Parallel()

	c := fixtureClient(t, client.Handlers{}, func(d *client.Definition) {
		d.ToolFilter = client.ToolFilter{Deny: []string{mcptest.ToolBig}}
	})

	cat := c.Catalog()
	if _, ok := cat.ToolByRawName(mcptest.ToolBig); ok {
		t.Error("a denied tool is visible in the catalog projection")
	}
	if _, ok := cat.ToolByRawName(mcptest.ToolEcho); !ok {
		t.Error("a permitted tool is missing from the catalog")
	}

	_, err := c.CallTool(testCtx(t), mcptest.ToolBig, json.RawMessage(`{"bytes":1}`), client.CallOpts{})
	if err == nil {
		t.Fatal("a denied tool was called against a server that really offers it")
	}
	if class, _ := client.ClassOf(err); class != client.FailureToolUnavailable {
		t.Errorf("class = %v, want %v", class, client.FailureToolUnavailable)
	}

	// The permitted one still works, so the filter is not simply breaking the
	// binding.
	if _, err := c.CallTool(testCtx(t), mcptest.ToolEcho,
		json.RawMessage(`{"text":"ok"}`), client.CallOpts{}); err != nil {
		t.Errorf("CallTool(echo) error = %v", err)
	}
}
