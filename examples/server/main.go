package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/looprig/mcp/pkg/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	s, err := server.New(server.Config{Name: "docs-server", Version: "1.0.0"})
	must(err)
	must(s.RegisterTool(server.Tool{
		Name:         "sum",
		Description:  "Add two integers.",
		InputSchema:  json.RawMessage(`{"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"]}`),
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"total":{"type":"integer"}},"required":["total"]}`),
		Handler: func(_ context.Context, raw json.RawMessage) (server.Result, error) {
			var input struct{ A, B int }
			if err := json.Unmarshal(raw, &input); err != nil {
				return server.Result{}, server.ErrInvalidArgument
			}
			structured, _ := json.Marshal(map[string]int{"total": input.A + input.B})
			return server.Result{Content: []server.Content{{Text: fmt.Sprint(input.A + input.B)}}, StructuredContent: structured}, nil
		},
	}))

	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- s.Serve(ctx, serverConn, serverConn) }()

	probe := mcp.NewClient(&mcp.Implementation{Name: "docs-probe", Version: "1.0.0"}, nil)
	session, err := probe.Connect(ctx, &mcp.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	must(err)
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "sum", Arguments: map[string]any{"a": 20, "b": 22}})
	must(err)
	encoded, _ := json.Marshal(result.StructuredContent)
	if session.InitializeResult().ServerInfo.Name != "docs-server" || string(encoded) != `{"total":42}` {
		panic(fmt.Sprintf("unexpected server result: name=%q structured=%s", session.InitializeResult().ServerInfo.Name, encoded))
	}
	fmt.Printf("server=%s\ntool=sum\nstructured=%s\n", session.InitializeResult().ServerInfo.Name, encoded)
	must(session.Close())
	cancel()
	_ = clientConn.Close()
	<-done
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
