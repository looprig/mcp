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
