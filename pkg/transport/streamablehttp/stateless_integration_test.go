//go:build integration

// Integration tests for the Streamable HTTP transport against a *stateless*
// server (SEP-2567, the 2026-07-28 spec's default deployment shape): no
// Mcp-Session-Id, no held server-side session state, discover instead of
// initialize. TestClientConnectOverHTTP and its siblings in
// streamablehttp_integration_test.go cover the stateful shape; this file
// covers the other one a real deployment can choose.

package streamablehttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/pkg/client"
)

// TestClientConnectStateless is TestClientConnectOverHTTP against a stateless
// fixture: the shape a 2026-07-28-only deployment has. What is under test is
// the whole client stack — discover instead of initialize, catalog discovery,
// a real tool call — over the new wire model.
func TestClientConnectStateless(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{Stateless: true, Instructions: "stateless fixture"})
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
		_ = c.Close(closeCtx)
	})

	cat := c.Catalog()
	if !cat.Valid() {
		t.Fatal("no adopted catalog against a stateless server")
	}
	if cat.ProtocolVersion != "2026-07-28" {
		t.Errorf("ProtocolVersion = %q, want 2026-07-28", cat.ProtocolVersion)
	}
	if _, ok := cat.ToolByRawName(mcptest.ToolEcho); !ok {
		t.Error("echo tool missing from the stateless catalog")
	}

	args, err := json.Marshal(mcptest.EchoInput{Text: "stateless"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := c.CallTool(ctx, mcptest.ToolEcho, args, client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool(echo) error = %v", err)
	}
	if res.IsError {
		t.Errorf("CallTool(echo) tool error: %+v", res.Content)
	}
}

// relistenWithRetry rebinds addr, retrying briefly against EADDRINUSE: the
// kernel can hold the port a moment after the previous listener closes, and
// that is a timing artifact of this test's server-resurrection dance, not a
// reconnect defect.
//
// It reports errors by return value rather than t.Fatalf because it runs on a
// background goroutine in TestReconnectStateless (see that test's comment on
// why resurrection is delayed) — testing.T's Fatal/FailNow family is only
// safe to call from the test's own goroutine.
func relistenWithRetry(addr string) (net.Listener, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestReconnectStateless proves the reconnect sequence over the stateless
// protocol: the server goes away, the binding classifies the loss, redials,
// re-runs discovery (there is no stream to resume on 2026-07-28), and serves
// calls again with the adopted catalog intact.
//
// In stateless mode each POST is its own exchange, so the client may not
// notice the outage until it makes a call: this test polls calls rather than
// awaiting a state transition, and only asserts StateReconnecting was
// observed if it happened to be (see sawReconnecting below) — a call that
// simply fails then succeeds is acceptable stateless behavior too, as long as
// at least one call attempt actually failed during the outage.
func TestReconnectStateless(t *testing.T) {
	t.Parallel()

	h, err := mcptest.NewHTTPHandler(mcptest.Config{Stateless: true})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	srv := httptest.NewServer(h)
	addr := srv.Listener.Addr().String()

	f, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	def := client.Definition{Name: "fixture", Transport: f}
	def.Reconnect.Attempts = 5
	def.Reconnect.BaseDelay = 20 * time.Millisecond
	def.Reconnect.MaxDelay = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := client.Connect(ctx, def, client.Handlers{})
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		_ = c.Close(closeCtx)
	})
	before := c.Catalog()

	// Kill the server. Resurrection is deliberately delayed on a background
	// goroutine rather than done inline: an inline relisten completes fast
	// enough (kernel + Go scheduler, no real network latency) that the polling
	// loop below never observes a failure at all — its first CallTool always
	// lands on the already-live successor, and the reconnect path this test
	// exists to exercise never runs. The delay gives the loop a real outage
	// window: at least one call must hit "nothing is listening" before the
	// address comes back.
	srv.CloseClientConnections()
	srv.Close()

	type resurrection struct {
		srv *httptest.Server
		err error
	}
	resCh := make(chan resurrection, 1)
	go func() {
		time.Sleep(150 * time.Millisecond)
		ln, err := relistenWithRetry(addr)
		if err != nil {
			resCh <- resurrection{err: fmt.Errorf("relisten on %s: %w", addr, err)}
			return
		}
		s := &httptest.Server{Listener: ln, Config: &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}}
		s.Start()
		resCh <- resurrection{srv: s}
	}()

	// A call during/after the outage must eventually succeed again. Each
	// iteration also samples Status().State: StateReconnecting only appears
	// once a failed call has told the binding its connection is gone (see
	// noteFailure/connectionLost in reconnect.go), so it can only show up
	// interleaved with these very call attempts, not before them.
	sawReconnecting := false
	deadline := time.Now().Add(45 * time.Second)
	var lastErr error
	sawFailure := false
	for time.Now().Before(deadline) {
		if c.Status().State == client.StateReconnecting {
			sawReconnecting = true
		}
		args, _ := json.Marshal(mcptest.EchoInput{Text: "back"})
		res, err := c.CallTool(ctx, mcptest.ToolEcho, args, client.CallOpts{})
		if err == nil && !res.IsError {
			lastErr = nil
			break
		}
		sawFailure = true
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("binding never recovered: last error = %v", lastErr)
	}
	if !sawFailure && !sawReconnecting {
		t.Error("the outage was never observed by the client (no failed call, no StateReconnecting): " +
			"the test proves nothing about reconnect")
	}
	t.Logf("outage observed via: failure=%v StateReconnecting=%v", sawFailure, sawReconnecting)

	r := <-resCh
	if r.err != nil {
		t.Fatalf("resurrect server: %v", r.err)
	}
	t.Cleanup(r.srv.Close)

	after := c.Catalog()
	if after.Generation != before.Generation || after.Digest != before.Digest {
		t.Errorf("adopted catalog changed across reconnect: (gen %d, %s) -> (gen %d, %s)",
			before.Generation, before.Digest, after.Generation, after.Digest)
	}
	if got := c.Status().ProtocolVersion; got != "2026-07-28" {
		t.Errorf("ProtocolVersion after reconnect = %q, want 2026-07-28", got)
	}
}
