package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/looprig/mcp/pkg/client"
	"github.com/looprig/mcp/pkg/server"
	"github.com/looprig/mcp/pkg/transport/stdio"
)

const childMode = "LOOPRIG_MCP_EXAMPLE_CHILD"

func main() {
	if os.Getenv(childMode) == "1" {
		serveChild()
		return
	}
	if err := runClient(); err != nil {
		panic(err)
	}
}

func serveChild() {
	s, err := server.New(server.Config{Name: "docs-stdio", Version: "1.0.0"})
	if err != nil {
		panic(err)
	}
	err = s.RegisterTool(server.Tool{
		Name:        "echo",
		Description: "Return the supplied text.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}`),
		Handler: func(_ context.Context, args json.RawMessage) (server.Result, error) {
			var in struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(args, &in); err != nil {
				return server.Result{}, server.ErrInvalidArgument
			}
			return server.Result{Content: []server.Content{{Text: in.Text}}}, nil
		},
	})
	if err != nil {
		panic(err)
	}
	if err := s.Run(context.Background()); err != nil {
		panic(err)
	}
}

func runClient() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	transport, err := stdio.New(stdio.Config{
		Command: executable,
		Env:     stdio.EnvAllowlist{Vars: []stdio.Var{{Name: childMode, Value: "1"}}},
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Connect(ctx, client.Definition{Name: "docs", Transport: transport}, client.Handlers{})
	if err != nil {
		return err
	}
	defer c.Close(context.Background())

	result, err := c.CallTool(ctx, "echo", json.RawMessage(`{"text":"hello over stdio"}`), client.CallOpts{})
	if err != nil {
		return err
	}
	if len(result.Content) != 1 {
		return fmt.Errorf("content blocks = %d, want 1", len(result.Content))
	}
	text, ok := result.Content[0].(client.Text)
	if !ok || text.Text != "hello over stdio" {
		return fmt.Errorf("unexpected tool result: %#v", result.Content[0])
	}
	status := c.Status()
	if status.TransportKind != "stdio" || status.Server.Name != "docs-stdio" || len(c.Catalog().Tools) != 1 {
		return fmt.Errorf("unexpected connected state: %#v", status)
	}
	fmt.Printf("transport=%s\nserver=%s\ntools=%d\nresult=%s\n", status.TransportKind, status.Server.Name, len(c.Catalog().Tools), text.Text)
	return nil
}
