//go:build integration

// Integration tests for the legacy SSE transport: a real SDK-based legacy SSE
// server, real HTTP, real TLS. The fixture (internal/mcptest) speaks the real
// 2024-11-05 protocol — the hanging GET, the endpoint event, the POSTed
// messages — so what is exercised here is that protocol and not our idea of it.
//
// That matters more here than it does for Streamable HTTP. This transport exists
// to talk to servers nobody is going to update, so "it works against the real
// thing" is the entire claim, and a test against a fixture that could not
// actually do legacy SSE would prove nothing at all. internal/mcptest grew
// NewSSEHandler for exactly this.
//
// The unit tests use httptest servers too, so the line between the two files is
// not "does it use a socket". It is what is on the other end: a server that
// misbehaves precisely is a handler; a handshake, a tool call and a session's
// lifetime need a server that behaves, which is the fixture.

package sse

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/httpconn"
	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/auth"
	"github.com/looprig/mcp/pkg/client"
)

// testTimeout bounds each test's own work. Generous: a slow box must not turn an
// assertion into a flake, and every test here fails on its own terms.
const testTimeout = 30 * time.Second

// newFixtureServer starts the fixture over legacy SSE and returns its URL.
func newFixtureServer(t *testing.T, cfg mcptest.Config) string {
	t.Helper()

	h, err := mcptest.NewSSEHandler(cfg)
	if err != nil {
		t.Fatalf("mcptest.NewSSEHandler() error = %v", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	c, err := f.Connect(ctx, testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	return c.(*httpconn.Conn)
}

// TestHandshakeAgainstARealLegacyServer is the claim this package exists to
// make: a legacy SSE server, spoken to over the legacy protocol, works.
func TestHandshakeAgainstARealLegacyServer(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{})
	f, err := New(Config{Endpoint: url})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	c, err := f.Connect(ctx, testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	res, err := c.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if res.ProtocolVersion == "" {
		t.Error("Initialize() returned no protocol version")
	}
	if res.Server.Name == "" {
		t.Error("Initialize() returned no server name")
	}
}

// TestToolCallAgainstARealLegacyServer drives a real tool call. It is the whole
// round trip: the request POSTs to the endpoint the server nominated, and the
// reply comes back on the hanging GET.
func TestToolCallAgainstARealLegacyServer(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{})
	c := connectFixture(t, Config{Endpoint: url})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	args, err := json.Marshal(map[string]any{"text": "hello"})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	res, err := c.CallTool(ctx, mcptest.ToolEcho, args, protocol.CallOptions{})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if res.IsError {
		t.Fatalf("CallTool() returned a tool error: %+v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("CallTool() returned no content")
	}
	text, ok := res.Content[0].(protocol.TextContent)
	if !ok {
		t.Fatalf("content[0] = %T, want protocol.TextContent", res.Content[0])
	}
	if !strings.Contains(text.Text, "hello") {
		t.Errorf("echo returned %q, want it to contain %q", text.Text, "hello")
	}
}

// TestListToolsAgainstARealLegacyServer: discovery works, which is what the
// client above does first.
func TestListToolsAgainstARealLegacyServer(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{})
	c := connectFixture(t, Config{Endpoint: url})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	page, err := c.ListTools(ctx, "")
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(page.Tools) == 0 {
		t.Fatal("ListTools() returned no tools")
	}
	var found bool
	for _, tool := range page.Tools {
		if tool.RawName == mcptest.ToolEcho {
			found = true
		}
	}
	if !found {
		t.Errorf("ListTools() did not return %q", mcptest.ToolEcho)
	}
}

// TestSessionOutlivesTheContextThatConnectedIt pins the defect stream.go exists
// to correct, against the real server that exposes it.
//
// The SDK opens this transport's hanging GET with the context passed to Connect,
// and keeps the session on it. internal/protocol connects from Initialize, and
// pkg/client gives Initialize a context bounded by Timeouts.Startup and cancels
// it as soon as startup returns — so without the wrapper the handshake succeeds
// and every request afterwards is answered "session not found" by a server that
// tore the session down when the GET died.
//
// This test reproduces that exactly: the context that connects and initializes
// is cancelled before anything else is asked of the session. It is the shape
// pkg/client uses, so if this passes the transport works under the real client,
// and if the wrapper is removed the ListTools below 404s.
func TestSessionOutlivesTheContextThatConnectedIt(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{})
	f, err := New(Config{Endpoint: url})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// The startup context: bounded, and dead the moment startup is over.
	startCtx, cancelStart := context.WithTimeout(context.Background(), testTimeout)
	c, err := f.Connect(startCtx, testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	if _, err := c.Initialize(startCtx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	cancelStart()

	// A fresh context, as a caller's request would carry. The session must still
	// be there.
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if _, err := c.ListTools(ctx, ""); err != nil {
		t.Fatalf("ListTools() after the startup context was cancelled: error = %v\n"+
			"the session did not survive the context that connected it, which is the whole "+
			"reason stream.go wraps the SDK's transport", err)
	}
}

// TestCredentialsReachARealServer: the auth seam works over this transport too,
// per request, on the POSTs and the stream alike.
func TestCredentialsReachARealServer(t *testing.T) {
	t.Parallel()

	var seen atomic.Int32
	var missing atomic.Int32

	h, err := mcptest.NewSSEHandler(mcptest.Config{})
	if err != nil {
		t.Fatalf("mcptest.NewSSEHandler() error = %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+secret {
			seen.Add(1)
		} else {
			missing.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	// t.Cleanup, not defer, and the order is load-bearing: this transport's
	// session is a hanging GET that now outlives the context that opened it (see
	// stream.go), so httptest's Close blocks until the client lets go. Registered
	// before connectFixture, it therefore runs after the connection's own
	// cleanup. A defer here would run first and deadlock.
	t.Cleanup(srv.Close)

	c := connectFixture(t, Config{
		Endpoint: srv.URL,
		Headers:  []auth.Header{auth.NewHeader("Authorization", "Bearer "+secret)},
	})

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if _, err := c.ListTools(ctx, ""); err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}

	if seen.Load() == 0 {
		t.Error("no request carried the credential")
	}
	if missing.Load() != 0 {
		t.Errorf("%d request(s) reached the server without the credential: it is attached per request, "+
			"so the stream and the POSTs must both carry it", missing.Load())
	}
}

// TestTLSIsVerifiedAgainstARealServer: a server with a certificate this
// transport has no reason to trust is refused, and the refusal is a real TLS
// failure rather than a happy path nobody checked.
func TestTLSIsVerifiedAgainstARealServer(t *testing.T) {
	t.Parallel()

	h, err := mcptest.NewSSEHandler(mcptest.Config{})
	if err != nil {
		t.Fatalf("mcptest.NewSSEHandler() error = %v", err)
	}
	// t.Cleanup before any connection is made; see TestCredentialsReachARealServer
	// for why the ordering matters.
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	f, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	c, err := f.Connect(ctx, testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	if _, err := c.Initialize(ctx); err == nil {
		t.Fatal("Initialize() error = nil: the fixture's self-signed certificate must not be trusted")
	}

	// And with the CA pinned, the same server works — which is what proves the
	// refusal above was the certificate and not this transport failing to speak
	// TLS at all.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	trusting := connectFixture(t, Config{
		Endpoint: srv.URL,
		HTTPClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}},
	})
	if _, err := trusting.ListTools(ctx, ""); err != nil {
		t.Errorf("ListTools() over pinned TLS: error = %v", err)
	}
}

// TestCancellationIsHonoredAgainstARealServer: a cancelled caller is reported as
// a cancellation, not as a mystery.
func TestCancellationIsHonoredAgainstARealServer(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{})
	c := connectFixture(t, Config{Endpoint: url})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.ListTools(ctx, "")
	if err == nil {
		t.Fatal("ListTools() error = nil, want a cancellation")
	}
	var e *client.Error
	if !errors.As(err, &e) || e.Class != client.FailureCancelled {
		t.Fatalf("ListTools() error = %v, want class FailureCancelled", err)
	}
}

// TestCloseEndsTheSession: closing releases the hanging GET rather than leaking
// it, and is idempotent.
func TestCloseEndsTheSession(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{})
	f, err := New(Config{Endpoint: url})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	c, err := f.Connect(ctx, testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	for i := range 3 {
		if err := c.Close(ctx); err != nil {
			t.Fatalf("Close() #%d error = %v, want nil", i+1, err)
		}
	}
}
