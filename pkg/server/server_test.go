package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestServerRegistersToolAndReturnsStructuredContent(t *testing.T) {
	t.Parallel()

	var seen atomic.Int32
	s, err := New(Config{
		Name:            "looprig-test",
		Version:         "1.2.3",
		MaxMessageBytes: 16 << 10,
		MaxInputBytes:   128,
		MaxOutputBytes:  1024,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.RegisterTool(Tool{
		Name:        "echo",
		Description: "returns a structured value",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(_ context.Context, args json.RawMessage) (Result, error) {
			seen.Add(1)
			if string(args) != `{"message":"hello"}` {
				return Result{}, fmt.Errorf("unexpected args: %s", args)
			}
			return Result{
				Content:           []Content{{Text: "hello"}},
				StructuredContent: json.RawMessage(`{"ok":true,"value":42}`),
			}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()

	probe := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "0"}, nil)
	cs, err := probe.Connect(ctx, &mcp.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	if err != nil {
		clientConn.Close()
		t.Fatalf("client Connect() error = %v", err)
	}
	defer cs.Close()

	if got := cs.InitializeResult().ServerInfo.Name; got != "looprig-test" {
		t.Fatalf("server name = %q, want looprig-test", got)
	}
	if got := cs.InitializeResult().ServerInfo.Version; got != "1.2.3" {
		t.Fatalf("server version = %q, want 1.2.3", got)
	}
	caps := cs.InitializeResult().Capabilities
	if caps == nil || caps.Tools == nil {
		t.Fatalf("tools capability = %#v, want tools only", caps)
	}
	if caps.Logging != nil || caps.Prompts != nil || caps.Resources != nil || caps.Completions != nil {
		t.Fatalf("unexpected server capabilities: %#v", caps)
	}

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo" {
		t.Fatalf("tools = %#v, want only echo", tools.Tools)
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: json.RawMessage(`{"message":"hello"}`),
	})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if res.IsError {
		t.Fatalf("CallTool() returned tool error: %#v", res)
	}
	if len(res.Content) != 1 {
		t.Fatalf("content = %#v, want one block", res.Content)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "hello" {
		t.Fatalf("content[0] = %#v, want text hello", res.Content[0])
	}
	if got, want := string(mustJSON(t, res.StructuredContent)), `{"ok":true,"value":42}`; got != want {
		t.Fatalf("structured content = %s, want %s", got, want)
	}
	if seen.Load() != 1 {
		t.Fatalf("handler calls = %d, want 1", seen.Load())
	}

	cancel()
	clientConn.Close()
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not shut down after cancellation")
	case err := <-serverErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error after cancellation = %v", err)
		}
	}
}

func TestServerRejectsDuplicateAndInvalidToolNames(t *testing.T) {
	t.Parallel()

	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	tool := Tool{Name: "echo", Handler: func(context.Context, json.RawMessage) (Result, error) {
		return Result{}, nil
	}}
	if err := s.RegisterTool(tool); err != nil {
		t.Fatalf("first RegisterTool() error = %v", err)
	}
	if err := s.RegisterTool(tool); !errors.Is(err, ErrDuplicateTool) {
		t.Fatalf("duplicate RegisterTool() error = %v, want ErrDuplicateTool", err)
	}

	for _, name := range []string{"", "has space", strings.Repeat("x", 129), "slash/name"} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			if err := s.RegisterTool(Tool{Name: name, Handler: tool.Handler}); !errors.Is(err, ErrInvalidToolName) {
				t.Fatalf("RegisterTool(%q) error = %v, want ErrInvalidToolName", name, err)
			}
		})
	}
}

func TestServerBoundsInputBeforeCallingHandler(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	s, err := New(Config{MaxInputBytes: 8})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.RegisterTool(Tool{
		Name: "bounded",
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			calls.Add(1)
			return Result{}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	probe := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "0"}, nil)
	cs, err := probe.Connect(ctx, &mcp.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	if err != nil {
		clientConn.Close()
		t.Fatalf("client Connect() error = %v", err)
	}
	defer cs.Close()

	_, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "bounded",
		Arguments: json.RawMessage(`{"too":"large"}`),
	})
	var wireErr *jsonrpc.Error
	if !errors.As(err, &wireErr) || wireErr.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("CallTool() error = %v (%T), want invalid params", err, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("handler calls = %d, want 0", calls.Load())
	}

	cancel()
	clientConn.Close()
	<-serverErr
}

func TestServerClassifiesHandlerErrorsWithoutLeakingSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		code int64
	}{
		{name: "invalid argument", err: fmt.Errorf("%w: handler-secret", ErrInvalidArgument), code: jsonrpc.CodeInvalidParams},
		{name: "internal", err: errors.New("handler-secret"), code: jsonrpc.CodeInternalError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New(Config{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if err := s.RegisterTool(Tool{
				Name: "fail",
				Handler: func(context.Context, json.RawMessage) (Result, error) {
					return Result{}, tt.err
				},
			}); err != nil {
				t.Fatalf("RegisterTool() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			serverConn, clientConn := net.Pipe()
			serverErr := make(chan error, 1)
			go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
			probe := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "0"}, nil)
			cs, err := probe.Connect(ctx, &mcp.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
			if err != nil {
				clientConn.Close()
				cancel()
				t.Fatalf("client Connect() error = %v", err)
			}
			_, callErr := cs.CallTool(ctx, &mcp.CallToolParams{Name: "fail"})
			var wireErr *jsonrpc.Error
			if !errors.As(callErr, &wireErr) || wireErr.Code != tt.code {
				t.Fatalf("CallTool() error = %v (%T), want code %d", callErr, callErr, tt.code)
			}
			if strings.Contains(callErr.Error(), "handler-secret") {
				t.Fatalf("CallTool() error leaked handler secret: %v", callErr)
			}
			cs.Close()
			clientConn.Close()
			cancel()
			<-serverErr
		})
	}
}

func TestServerBoundsHandlerOutput(t *testing.T) {
	t.Parallel()

	s, err := New(Config{MaxOutputBytes: 16})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.RegisterTool(Tool{
		Name: "big",
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			return Result{StructuredContent: json.RawMessage(`{"secret":"this is too large"}`)}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	probe := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "0"}, nil)
	cs, err := probe.Connect(ctx, &mcp.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	if err != nil {
		clientConn.Close()
		cancel()
		t.Fatalf("client Connect() error = %v", err)
	}
	_, callErr := cs.CallTool(ctx, &mcp.CallToolParams{Name: "big"})
	var wireErr *jsonrpc.Error
	if !errors.As(callErr, &wireErr) || wireErr.Code != jsonrpc.CodeInternalError {
		t.Fatalf("CallTool() error = %v (%T), want internal error", callErr, callErr)
	}
	if strings.Contains(callErr.Error(), "this is too large") {
		t.Fatalf("CallTool() error leaked output: %v", callErr)
	}
	cs.Close()
	clientConn.Close()
	cancel()
	<-serverErr
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return b
}
