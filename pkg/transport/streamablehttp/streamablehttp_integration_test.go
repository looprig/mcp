//go:build integration

// Integration tests for the Streamable HTTP transport: a real SDK-based MCP
// server, real HTTP, real TLS. The fixture (internal/mcptest) speaks the real
// protocol, so what is exercised here is MCP and not our idea of it.
//
// The unit tests use httptest servers too, so the line between the two files is
// not "does it use a socket". It is what is on the other end: a hostile
// response, a status code or a refused credential needs a server that misbehaves
// precisely, which is a handler; a handshake, a tool call and a session's
// lifetime need a server that behaves, which is the fixture.
//
// The fixture runs in-process here rather than as a subprocess, and that is not
// a shortcut — see internal/mcptest/http.go. HTTP is a socket, httptest provides
// one, and a child process would add a port to allocate and a readiness race to
// lose in exchange for nothing. The transport still speaks real HTTP to a real
// SDK server.

package streamablehttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/httpconn"
	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/pkg/auth"
	"github.com/looprig/mcp/pkg/client"

	"github.com/looprig/mcp/internal/protocol"
)

// newFixtureServer starts the fixture over Streamable HTTP and returns its URL.
func newFixtureServer(t *testing.T, cfg mcptest.Config) string {
	t.Helper()

	h, err := mcptest.NewHTTPHandler(cfg)
	if err != nil {
		t.Fatalf("mcptest.NewHTTPHandler() error = %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// connectFixture connects the transport to endpoint and initializes it,
// registering the close. It returns the live connection.
func connectFixture(t *testing.T, cfg Config) *httpconn.Conn {
	t.Helper()

	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	return c.(*httpconn.Conn)
}

// callTool drives a real tool call over the established connection, through the
// same neutral API a consumer uses. What is under test is that this transport
// carries MCP traffic, and a real tool call is what proves it.
//
// args is a map here purely for the call sites' convenience: it is marshalled
// straight to the raw JSON the protocol layer takes, which is what a tool's
// arguments are on the wire.
func callTool(ctx context.Context, c *httpconn.Conn, name string, args map[string]any) (protocol.ToolResult, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return protocol.ToolResult{}, err
	}
	return c.CallTool(ctx, name, raw, protocol.CallOptions{})
}

// resultText flattens a tool result's text content.
func resultText(t *testing.T, res protocol.ToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, content := range res.Content {
		if text, ok := content.(protocol.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

// TestClientConnectOverHTTP is the end-to-end shape a consumer sees: a
// Definition with a Streamable HTTP transport, connected through pkg/client.
func TestClientConnectOverHTTP(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{Instructions: "be excellent to each other"})
	f, err := New(Config{Endpoint: url + "/mcp"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := client.Connect(ctx, client.Definition{Name: "fixture", Transport: f}, client.Handlers{})
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		if err := c.Close(closeCtx); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	status := c.Status()
	if status.State != client.StateReady {
		t.Errorf("State = %v, want ready (failure: %+v)", status.State, status.Failure)
	}
	if status.TransportKind != "streamablehttp" {
		t.Errorf("TransportKind = %q, want %q", status.TransportKind, "streamablehttp")
	}
	// The origin, not the endpoint: the "/mcp" path is not in it.
	if !strings.HasPrefix(status.RedactedOrigin, "http://127.0.0.1:") {
		t.Errorf("RedactedOrigin = %q, want the loopback origin", status.RedactedOrigin)
	}
	if strings.Contains(status.RedactedOrigin, "/mcp") {
		t.Errorf("RedactedOrigin = %q, want no path", status.RedactedOrigin)
	}
	if status.Server.Name != mcptest.ServerName {
		t.Errorf("Server.Name = %q, want %q", status.Server.Name, mcptest.ServerName)
	}
	if status.ProtocolVersion == "" {
		t.Error("ProtocolVersion is empty: the handshake did not settle a version")
	}
	if status.Failure != nil {
		t.Errorf("Failure = %+v, want nil", status.Failure)
	}
}

// TestInitializeReportsWhatTheServerSaid checks the handshake's converted
// result, which is the transport's one protocol output.
func TestInitializeReportsWhatTheServerSaid(t *testing.T) {
	t.Parallel()

	const instructions = "read the fixture's mind"
	url := newFixtureServer(t, mcptest.Config{Instructions: instructions, Prompts: true, Resources: true})

	f, err := New(Config{Endpoint: url + "/mcp"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := c.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if res.Server.Name != mcptest.ServerName {
		t.Errorf("Server.Name = %q, want %q", res.Server.Name, mcptest.ServerName)
	}
	if res.Server.Version != mcptest.ServerVersion {
		t.Errorf("Server.Version = %q, want %q", res.Server.Version, mcptest.ServerVersion)
	}
	if res.Instructions != instructions {
		t.Errorf("Instructions = %q, want %q", res.Instructions, instructions)
	}
	if res.ProtocolVersion == "" {
		t.Error("ProtocolVersion is empty")
	}
	for _, want := range []struct {
		name string
		got  bool
	}{
		{"Tools", res.Capabilities.Tools},
		{"Prompts", res.Capabilities.Prompts},
		{"Resources", res.Capabilities.Resources},
	} {
		if !want.got {
			t.Errorf("Capabilities.%s = false, want true", want.name)
		}
	}
}

// TestToolCallRoundTrip drives real tool calls over the transport. This is the
// operation the module exists for.
func TestToolCallRoundTrip(t *testing.T) {
	t.Parallel()

	c := connectFixture(t, Config{Endpoint: newFixtureServer(t, mcptest.Config{}) + "/mcp"})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("echo", func(t *testing.T) {
		const want = "hello over http"
		res, err := callTool(ctx, c, mcptest.ToolEcho, map[string]any{"text": want})
		if err != nil {
			t.Fatalf("CallTool(%s) error = %v", mcptest.ToolEcho, err)
		}
		if res.IsError {
			t.Fatalf("CallTool(%s) reported an error result: %s", mcptest.ToolEcho, resultText(t, res))
		}
		if got := resultText(t, res); got != want {
			t.Errorf("echo = %q, want %q", got, want)
		}
	})

	t.Run("a tool error is not a transport failure", func(t *testing.T) {
		res, err := callTool(ctx, c, mcptest.ToolFail, map[string]any{})
		if err != nil {
			t.Fatalf("CallTool(%s) error = %v; a tool error result is a successful call", mcptest.ToolFail, err)
		}
		if !res.IsError {
			t.Error("CallTool(fail) did not report an error result")
		}
	})

	t.Run("a large result crosses intact", func(t *testing.T) {
		const size = 256 << 10
		res, err := callTool(ctx, c, mcptest.ToolBig, map[string]any{"bytes": size})
		if err != nil {
			t.Fatalf("CallTool(%s) error = %v", mcptest.ToolBig, err)
		}
		if got := len(resultText(t, res)); got != size {
			t.Errorf("big returned %d bytes, want %d", got, size)
		}
	})
}

// TestToolCallIsNotRetried is the package comment's central claim, made against
// a real MCP server and a real tool call.
//
// The failure is injected underneath the fixture: a proxy that counts tool-call
// POSTs and answers them with a 500. A transport that retried would send a
// second, and the count would say so.
func TestToolCallIsNotRetried(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
	}{
		// 401 and 403 are the only statuses that reach the SDK's
		// authorize-and-resend branch. They are the cases that would break the
		// day someone wires OAuthHandler up, and a tool call is the payload
		// where re-sending actually costs something — so they are tested here,
		// against a real server, on a real call.
		{name: "401", status: http.StatusUnauthorized},
		{name: "403", status: http.StatusForbidden},
		{name: "500", status: http.StatusInternalServerError},
		{name: "429", status: http.StatusTooManyRequests},
		{name: "503", status: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			upstream := newFixtureServer(t, mcptest.Config{})
			var calls atomic.Int64
			// Only tools/call fails, so the handshake still succeeds and what is
			// counted is the call itself.
			proxy := newProxy(t, upstream, func(w http.ResponseWriter, r *http.Request, body []byte) bool {
				if r.Method == http.MethodPost && bytes.Contains(body, []byte(`"tools/call"`)) {
					calls.Add(1)
					w.WriteHeader(tt.status)
					return true
				}
				return false
			})

			c := connectFixture(t, Config{Endpoint: proxy + "/mcp"})

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if _, err := callTool(ctx, c, mcptest.ToolEcho, map[string]any{"text": "never arrives"}); err == nil {
				t.Fatalf("CallTool() succeeded against a %d, want a failure", tt.status)
			}

			// Long enough for the SDK's jittered backoff — which starts at a
			// second — to have produced a retry, if there were one to produce.
			// Without the wait this test would pass against a retrying transport
			// by finishing first.
			time.Sleep(1500 * time.Millisecond)

			if n := calls.Load(); n != 1 {
				t.Errorf("the server received %d tools/call POSTs, want exactly 1: a tool call must never be re-sent", n)
			}
		})
	}
}

// TestCancellationIsHonored checks that a caller who gives up gets control back
// promptly, rather than waiting out a tool that is still sleeping.
func TestCancellationIsHonored(t *testing.T) {
	t.Parallel()

	c := connectFixture(t, Config{Endpoint: newFixtureServer(t, mcptest.Config{}) + "/mcp"})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := callTool(ctx, c, mcptest.ToolSlow, map[string]any{"ms": 60000})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("CallTool(slow) succeeded; the cancellation was ignored")
	}
	if elapsed > 15*time.Second {
		t.Errorf("the call took %v; it must return when its context does, not when the tool does", elapsed)
	}
}

// TestAuthProtectedServer drives the auth seam end-to-end: a server that demands
// a bearer token, and a provider that supplies one.
func TestAuthProtectedServer(t *testing.T) {
	t.Parallel()

	const token = "test-token-not-a-real-credential"
	upstream := newFixtureServer(t, mcptest.Config{})
	guard := newProxy(t, upstream, func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		return false
	})

	t.Run("with a credential", func(t *testing.T) {
		c := connectFixture(t, Config{Endpoint: guard + "/mcp", Auth: bearerProvider(token)})

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		res, err := callTool(ctx, c, mcptest.ToolEcho, map[string]any{"text": "authorized"})
		if err != nil {
			t.Fatalf("CallTool() error = %v", err)
		}
		if got := resultText(t, res); got != "authorized" {
			t.Errorf("echo = %q, want %q", got, "authorized")
		}
	})

	t.Run("without a credential", func(t *testing.T) {
		assertUnauthorized(t, Config{Endpoint: guard + "/mcp"}, "")
	})

	t.Run("with the wrong credential", func(t *testing.T) {
		const wrong = "wrong-token-still-a-secret"
		assertUnauthorized(t, Config{Endpoint: guard + "/mcp", Auth: bearerProvider(wrong)}, wrong)
	})
}

// assertUnauthorized requires that cfg fails the handshake with an auth class,
// and that the failure does not quote secret, when one is given.
func assertUnauthorized(t *testing.T, cfg Config, secret string) {
	t.Helper()

	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := c.Initialize(ctx); err == nil {
		t.Fatal("Initialize() succeeded against a 401, want a failure")
	} else {
		if class, ok := client.ClassOf(err); !ok || class != client.FailureAuthRequired {
			t.Errorf("class = %v, want %v (error: %v)", class, client.FailureAuthRequired, err)
		}
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Errorf("the error leaked the credential: %v", err)
		}
	}
}

// TestTLS is the transport over real TLS, verified — not skipped.
//
// httptest's TLS server signs with its own CA and hands out a client that trusts
// it, which is what a private CA looks like in production. That client goes in
// through Config.HTTPClient and is used after vetting. The alternative that
// would also make this test pass — InsecureSkipVerify — is exactly what this
// module refuses, so a test that used it would assert the opposite of the
// requirement.
func TestTLS(t *testing.T) {
	t.Parallel()

	h, err := mcptest.NewHTTPHandler(mcptest.Config{})
	if err != nil {
		t.Fatalf("mcptest.NewHTTPHandler() error = %v", err)
	}
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	c := connectFixture(t, Config{Endpoint: srv.URL + "/mcp", HTTPClient: srv.Client()})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := callTool(ctx, c, mcptest.ToolEcho, map[string]any{"text": "over tls"})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if got := resultText(t, res); got != "over tls" {
		t.Errorf("echo = %q, want %q", got, "over tls")
	}
}

// TestTLSVerificationIsNotOptional is TestTLS's negative: the same server,
// without its CA, must fail. The two together are what distinguish a transport
// that verifies certificates from one that pretends to — TestTLS alone would
// pass just as happily with verification disabled.
func TestTLSVerificationIsNotOptional(t *testing.T) {
	t.Parallel()

	h, err := mcptest.NewHTTPHandler(mcptest.Config{})
	if err != nil {
		t.Fatalf("mcptest.NewHTTPHandler() error = %v", err)
	}
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	// No HTTPClient: the default one trusts the system roots, which do not
	// include httptest's throwaway CA.
	f, err := New(Config{Endpoint: srv.URL + "/mcp"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := c.Initialize(ctx); err == nil {
		t.Fatal("Initialize() succeeded against an untrusted certificate; verification is not optional")
	} else {
		var verr *tls.CertificateVerificationError
		if !errors.As(err, &verr) {
			// Not fatal: what matters is that it failed. The exact error type is
			// the stdlib's business and has changed before.
			t.Logf("failed with %v (not a *tls.CertificateVerificationError)", err)
		}
	}
}

// TestSessionLifetime checks the part the SDK owns and this transport delegates:
// a session id is negotiated, carried on subsequent requests, and released by a
// DELETE at close. It is here because delegating it is a decision, and a
// decision that nothing checks is a decision that can silently stop holding.
func TestSessionLifetime(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	sessions := map[string]int{}
	var deleted atomic.Bool

	upstream := newFixtureServer(t, mcptest.Config{})
	proxy := newProxy(t, upstream, func(_ http.ResponseWriter, r *http.Request, _ []byte) bool {
		if id := r.Header.Get("Mcp-Session-Id"); id != "" {
			mu.Lock()
			sessions[id]++
			mu.Unlock()
		}
		if r.Method == http.MethodDelete {
			deleted.Store(true)
		}
		return false
	})

	f, err := New(Config{Endpoint: proxy + "/mcp"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if _, err := callTool(ctx, c.(*httpconn.Conn), mcptest.ToolEcho, map[string]any{"text": "one"}); err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(sessions) != 1 {
		t.Fatalf("saw %d session ids, want exactly 1: %v", len(sessions), sessions)
	}
	for id, n := range sessions {
		if n < 2 {
			t.Errorf("session %s was carried on %d requests, want it on every request after initialize", id, n)
		}
	}
	if !deleted.Load() {
		t.Error("no DELETE was sent: the session was never released")
	}
}

// newProxy starts a reverse proxy in front of upstream and returns its URL.
//
// intercept is called with each request's buffered body before it is forwarded.
// Returning true means it has answered the request itself; returning false
// forwards it verbatim. This is how a test puts a failure, or a guard, in front
// of a server that is otherwise behaving normally — the fixture stays honest and
// the misbehavior is injected where it belongs.
func newProxy(t *testing.T, upstream string, intercept func(http.ResponseWriter, *http.Request, []byte) bool) string {
	t.Helper()

	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", upstream, err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bounded: this is a test proxy, but an unbounded ReadAll in a test is
		// how a test becomes the thing that OOMs the CI runner.
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if intercept(w, r, body) {
			return
		}
		// The body was consumed to inspect it, so it is put back before the
		// request is forwarded.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// bearerProvider is an auth.HeaderProvider supplying a fixed bearer token: the
// stub an application replaces with a real credential source.
type bearerProvider string

func (p bearerProvider) Headers(context.Context) ([]auth.Header, error) {
	return []auth.Header{auth.NewHeader("Authorization", "Bearer "+string(p))}, nil
}
