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
	"strings"
	"sync"
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

// statelessElicitor answers every elicitation the same way, and records what
// it was asked. It is a minimal local copy of scriptedElicitor
// (pkg/client/elicit_integration_test.go:28): that type is in another
// package's test build and cannot be imported.
type statelessElicitor struct {
	mu   sync.Mutex
	seen []client.ElicitRequest
}

func (e *statelessElicitor) Elicit(_ context.Context, req client.ElicitRequest) (client.ElicitResult, error) {
	e.mu.Lock()
	e.seen = append(e.seen, req)
	e.mu.Unlock()
	return client.ElicitResult{Action: client.ElicitAccept, Content: json.RawMessage(`{"name":"ada"}`)}, nil
}

// clientResultText flattens a client.ToolResult's text content. It is
// resultText's counterpart for client.ToolResult (streamablehttp_integration_
// test.go's resultText works on the lower-level protocol.ToolResult), needed
// here because this test drives the call through pkg/client rather than
// through a raw *httpconn.Conn.
func clientResultText(t *testing.T, res client.ToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		if text, ok := c.(client.Text); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

// TestElicitationStateless: on 2026-07-28 a server cannot call the client, so
// the elicit tool comes back input-required and the SDK's MRTR middleware
// invokes our handler and retries. The application-visible contract — the
// handler sees the server's prompt, the answer reaches the tool — is identical
// to the legacy flow, and that identity is what this test pins.
//
// It drives mcptest.ToolElicitMRTR, not mcptest.ToolElicit: the latter still
// calls ServerSession.Elicit ad hoc, which stateless mode cannot serve at all
// (there is no session to push a server-initiated request over). ToolElicitMRTR
// is the fixture's MRTR-native twin, built for exactly this — see its doc
// comment in internal/mcptest/server.go for why it is a second tool rather
// than a rewrite of ToolElicit's handler.
func TestElicitationStateless(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{Stateless: true, Elicit: true})
	f, err := New(Config{Endpoint: url})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	el := &statelessElicitor{}
	def := client.Definition{Name: "fixture", Transport: f}
	def.Capabilities.Elicitation = true

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := client.Connect(ctx, def, client.Handlers{Elicitation: el})
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		_ = c.Close(closeCtx)
	})

	res, err := c.CallTool(ctx, mcptest.ToolElicitMRTR, json.RawMessage(`{}`), client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool(elicit) error = %v", err)
	}
	if res.IsError {
		t.Fatalf("CallTool(elicit) tool error: %+v", res.Content)
	}

	// The server was told what the human said — the same assertion
	// TestRealServerElicitsAHuman makes over stdio, pinning that MRTR's
	// application-visible outcome matches the legacy ad hoc flow's.
	if got, want := clientResultText(t, res), mcptest.ElicitAnswerPrefix+"accept"; got != want {
		t.Errorf("the tool reported %q, want %q", got, want)
	}

	el.mu.Lock()
	seen := len(el.seen)
	el.mu.Unlock()
	if seen != 1 {
		t.Errorf("elicitation handler invoked %d times, want 1", seen)
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

// TestListChangedStateless: the fixture mutates its tool list; on 2026-07-28
// the change notification arrives on the subscriptions/listen stream rather
// than as a free-floating notification, and must still produce a candidate
// generation.
func TestListChangedStateless(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{Stateless: true, Mutate: true})
	f, err := New(Config{Endpoint: url})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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

	args, err := json.Marshal(mcptest.MutateInput{Add: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := c.CallTool(ctx, mcptest.ToolMutate, args, client.CallOpts{})
	if err != nil || res.IsError {
		t.Fatalf("CallTool(mutate) error = %v, IsError = %v", err, res.IsError)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cand, ok := c.Candidate(); ok {
			if _, ok := cand.ToolByRawName(mcptest.ToolMutated); !ok {
				t.Errorf("candidate lacks the mutated tool %q", mcptest.ToolMutated)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no candidate generation arrived over subscriptions/listen")
}
