package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"

	"github.com/looprig/mcp/pkg/auth"
	"github.com/looprig/mcp/pkg/client"
	"github.com/looprig/mcp/pkg/transport/streamablehttp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const token = "docs-token"

type bearer struct{ calls *atomic.Int32 }

func (b bearer) Headers(context.Context) ([]auth.Header, error) {
	b.calls.Add(1)
	return []auth.Header{auth.NewHeader("Authorization", "Bearer "+token)}, nil
}

func main() {
	sdkServer := mcp.NewServer(&mcp.Implementation{Name: "docs-http", Version: "1.0.0"}, nil)
	type echoInput struct {
		Text string `json:"text"`
	}
	mcp.AddTool(sdkServer, &mcp.Tool{Name: "echo", Description: "Return text."}, func(_ context.Context, _ *mcp.CallToolRequest, in echoInput) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Text}}}, nil, nil
	})

	var authorizedRequests atomic.Int32
	var reused, released atomic.Bool
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return sdkServer }, nil)
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.Header().Set("WWW-Authenticate", `Bearer realm="docs"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authorizedRequests.Add(1)
		if r.Header.Get("Mcp-Session-Id") != "" {
			reused.Store(true)
		}
		if r.Method == http.MethodDelete {
			released.Store(true)
		}
		handler.ServeHTTP(w, r)
	})
	httpServer := httptest.NewServer(guarded)
	defer httpServer.Close()

	var authCalls atomic.Int32
	transport, err := streamablehttp.New(streamablehttp.Config{Endpoint: httpServer.URL, Auth: bearer{calls: &authCalls}})
	must(err)
	ctx := context.Background()
	c, err := client.Connect(ctx, client.Definition{Name: "docs", Transport: transport}, client.Handlers{})
	must(err)
	result, err := c.CallTool(ctx, "echo", json.RawMessage(`{"text":"hello over http"}`), client.CallOpts{})
	must(err)
	if len(result.Content) != 1 {
		panic(fmt.Sprintf("content blocks = %d, want 1", len(result.Content)))
	}
	text, ok := result.Content[0].(client.Text)
	if !ok || text.Text != "hello over http" {
		panic(fmt.Sprintf("unexpected tool result: %#v", result.Content[0]))
	}
	must(c.Close(ctx))

	unauthenticated, err := streamablehttp.New(streamablehttp.Config{Endpoint: httpServer.URL})
	must(err)
	_, denied := client.Connect(ctx, client.Definition{Name: "denied", Transport: unauthenticated}, client.Handlers{})
	class, classified := client.ClassOf(denied)
	authPerRequest := authCalls.Load() == authorizedRequests.Load()
	if !authPerRequest || !reused.Load() || !released.Load() || !classified || class != client.FailureAuthRequired {
		panic(fmt.Sprintf("unexpected lifecycle: auth=%d requests=%d reused=%t released=%t failure=%s", authCalls.Load(), authorizedRequests.Load(), reused.Load(), released.Load(), class))
	}
	fmt.Printf("result=%s\nauth-per-request=%t\nsession-reused=%t\nsession-released=%t\nfailure=%s\n", text.Text, authPerRequest, reused.Load(), released.Load(), class)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
