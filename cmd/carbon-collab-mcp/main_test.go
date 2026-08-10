package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/looprig/mcp/internal/serverwire"
	"github.com/looprig/mcp/pkg/collab"
	"github.com/looprig/mcp/pkg/server"
)

func TestCollaborationServerExposesOnlyMessageAgent(t *testing.T) {
	t.Parallel()

	server, err := newCollaborationServer(testConfig())
	if err != nil {
		t.Fatalf("newCollaborationServer() error = %v", err)
	}
	client, _, stop := connectServer(t, server)
	defer stop()

	tools, err := client.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "MessageAgent" {
		t.Fatalf("tools = %#v, want exactly MessageAgent", tools.Tools)
	}
	var schema map[string]json.RawMessage
	inputSchema, err := json.Marshal(tools.Tools[0].InputSchema)
	if err != nil {
		t.Fatalf("marshal input schema error = %v", err)
	}
	if err := json.Unmarshal(inputSchema, &schema); err != nil {
		t.Fatalf("input schema error = %v", err)
	}
	var properties map[string]json.RawMessage
	if err := json.Unmarshal(schema["properties"], &properties); err != nil {
		t.Fatalf("properties error = %v", err)
	}
	for field := range properties {
		switch field {
		case "agent_id", "message", "wait_for_response", "timeout_seconds":
		default:
			t.Errorf("unexpected MessageAgent schema field %q", field)
		}
	}
	if len(properties) != 4 {
		t.Fatalf("schema properties = %d, want 4", len(properties))
	}
	var additional bool
	if err := json.Unmarshal(schema["additionalProperties"], &additional); err != nil || additional {
		t.Fatalf("additionalProperties = %v, want false", additional)
	}
}

func TestCollaborationServerRejectsHostileMessageAgentArgumentsBeforeIPC(t *testing.T) {
	t.Parallel()

	server, err := newCollaborationServer(testConfig())
	if err != nil {
		t.Fatalf("newCollaborationServer() error = %v", err)
	}
	client, _, stop := connectServer(t, server)
	defer stop()
	_, err = client.CallTool(t.Context(), &serverwire.CallToolParams{
		Name:      "MessageAgent",
		Arguments: json.RawMessage(`{"agent_id":"55555555-5555-4555-8555-555555555555","message":"hello","request_id":"forged"}`),
	})
	if err == nil {
		t.Fatal("CallTool() error = nil, want invalid arguments")
	}
	if strings.Contains(err.Error(), "forged") {
		t.Fatalf("CallTool() error exposed correlation value: %v", err)
	}
}

func TestRunRejectsMissingEnvironmentBeforeServing(t *testing.T) {
	t.Parallel()

	called := false
	err := run(context.Background(), strings.NewReader(""), &bytes.Buffer{}, func(string) (string, bool) {
		called = true
		return "", false
	})
	if !errors.Is(err, errConfiguration) {
		t.Fatalf("run() error = %v, want errConfiguration", err)
	}
	if !called {
		t.Fatal("run() did not inspect fixed environment")
	}
}

func testConfig() collab.ClientConfig {
	return collab.ClientConfig{Endpoint: "/tmp/carbon-collab-test.sock", Capability: bytes.Repeat([]byte{0x01}, collab.CapabilityBytes)}
}

func connectServer(t *testing.T, s *server.Server) (*serverwire.ClientSession, io.Closer, func()) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve(ctx, serverConn, serverConn) }()
	clientDef := serverwire.NewClient(&serverwire.Implementation{Name: "probe", Version: "1"}, nil)
	client, err := clientDef.Connect(ctx, &serverwire.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	if err != nil {
		cancel()
		clientConn.Close()
		t.Fatalf("Connect() error = %v", err)
	}
	_ = client.InitializeResult()
	stop := func() {
		cancel()
		_ = client.Close()
		_ = clientConn.Close()
		_ = serverConn.Close()
		select {
		case <-serveErr:
		default:
		}
	}
	return client, clientConn, stop
}
