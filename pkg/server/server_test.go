package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/serverwire"
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

	probe := serverwire.NewClient(&serverwire.Implementation{Name: "probe", Version: "0"}, nil)
	cs, err := probe.Connect(ctx, &serverwire.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
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

	res, err := cs.CallTool(ctx, &serverwire.CallToolParams{
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
	text, ok := res.Content[0].(*serverwire.TextContent)
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

func TestServerRejectsBoundsAboveHardMaximumAndIncompatibleFrames(t *testing.T) {
	t.Parallel()

	tests := []Config{
		{MaxInputBytes: DefaultMaxInputBytes + 1},
		{MaxOutputBytes: DefaultMaxOutputBytes + 1},
		{MaxMessageBytes: DefaultMaxMessageBytes + 1},
		{MaxMessageBytes: DefaultMaxMessageBytes - 1, MaxInputBytes: DefaultMaxInputBytes},
		{MaxMessageBytes: DefaultMaxMessageBytes - 1, MaxOutputBytes: DefaultMaxOutputBytes},
	}
	for _, cfg := range tests {
		if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("New(%+v) error = %v, want ErrInvalidConfig", cfg, err)
		}
	}
	if _, err := New(Config{
		MaxMessageBytes: DefaultMaxMessageBytes,
		MaxInputBytes:   DefaultMaxInputBytes,
		MaxOutputBytes:  DefaultMaxOutputBytes,
	}); err != nil {
		t.Fatalf("New() at exact hard maxima error = %v", err)
	}
}

func TestServerAcceptsInputAtExactArgumentLimit(t *testing.T) {
	t.Parallel()

	var seen atomic.Int32
	s, err := New(Config{MaxInputBytes: DefaultMaxInputBytes})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.RegisterTool(Tool{
		Name: "exact-input",
		Handler: func(_ context.Context, args json.RawMessage) (Result, error) {
			if len(args) != DefaultMaxInputBytes {
				return Result{}, fmt.Errorf("unexpected argument length: %d", len(args))
			}
			seen.Add(1)
			return Result{}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	argument := exactObjectJSON(t, DefaultMaxInputBytes)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	probe := serverwire.NewClient(&serverwire.Implementation{Name: "probe", Version: "0"}, nil)
	cs, err := probe.Connect(ctx, &serverwire.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	if err != nil {
		clientConn.Close()
		t.Fatalf("client Connect() error = %v", err)
	}
	defer cs.Close()
	if _, err := cs.CallTool(ctx, &serverwire.CallToolParams{Name: "exact-input", Arguments: argument}); err != nil {
		t.Fatalf("CallTool() at exact argument limit error = %v", err)
	}
	if seen.Load() != 1 {
		t.Fatalf("handler calls = %d, want 1", seen.Load())
	}
	cancel()
	clientConn.Close()
	<-serverErr
}

func TestServerMaxOutputFitsTheFrameEnvelope(t *testing.T) {
	t.Parallel()

	s, err := New(Config{MaxOutputBytes: DefaultMaxOutputBytes})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// Find the largest structured string whose complete MCP result is exactly
	// the handler output bound. This exercises the result layer at the exact
	// boundary, then the frame writer with its trailing newline excluded.
	var structured json.RawMessage
	var encoded []byte
	for n := DefaultMaxOutputBytes; n >= 0; n-- {
		candidate := json.RawMessage(fmt.Sprintf(`{"value":%q}`, strings.Repeat("x", n)))
		wire, resultErr := s.result(Result{StructuredContent: candidate})
		if resultErr != nil {
			continue
		}
		encoded, err = json.Marshal(wire)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		if len(encoded) == DefaultMaxOutputBytes {
			structured = candidate
			break
		}
	}
	if len(structured) == 0 {
		t.Fatal("could not construct exact-boundary structured output")
	}
	if len(encoded) != DefaultMaxOutputBytes {
		t.Fatalf("encoded output length = %d, want %d", len(encoded), DefaultMaxOutputBytes)
	}
	var dst bytes.Buffer
	w := newBoundedFrameWriter(&dst, DefaultMaxMessageBytes)
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		t.Fatalf("writing max-valid output frame error = %v", err)
	}
	if got, want := dst.Len(), len(encoded)+1; got != want {
		t.Fatalf("written bytes = %d, want %d", got, want)
	}
}

func TestServeRejectsOversizedRequestIDBeforeHandler(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.RegisterTool(Tool{
		Name: "guard",
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			calls.Add(1)
			return Result{}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	reader := bufio.NewReader(clientConn)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}`)
	readRawRPC(t, reader)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)

	overlargeID := strings.Repeat("i", MaxFrameOverheadBytes)
	call := fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/call","params":{"name":"guard","arguments":{}}}`, overlargeID)
	writeRawRPC(t, clientConn, call)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := reader.ReadBytes('\n')
	if readErr == nil {
		t.Fatal("oversized request ID unexpectedly received a response")
	}
	if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrClosedPipe) && !strings.Contains(readErr.Error(), "closed") {
		t.Fatalf("oversized request ID read error = %v, want bounded shutdown", readErr)
	}
	if calls.Load() != 0 {
		t.Fatalf("handler calls = %d, want 0", calls.Load())
	}

	cancel()
	clientConn.Close()
	if err := <-serverErr; err != nil && strings.Contains(err.Error(), overlargeID) {
		t.Fatalf("server error leaked request ID: %v", err)
	}
}

func TestServeNearBoundRequestIDAndMaxResultWritesWithinFrame(t *testing.T) {
	t.Parallel()

	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	structured := exactStructuredContent(t, s)
	if err := s.RegisterTool(Tool{
		Name: "max-result",
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			return Result{StructuredContent: structured}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	reader := bufio.NewReader(clientConn)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}`)
	readRawRPC(t, reader)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)

	// MaxRequestIDBytes counts the encoded JSON ID; a string ID contributes two
	// quote bytes in addition to its value.
	requestID := strings.Repeat("n", MaxRequestIDBytes-2-12) + "\u2028\u2029"
	if got := len(canonicalJSONString(t, requestID)); got != MaxRequestIDBytes {
		t.Fatalf("canonical near-bound ID bytes = %d, want %d", got, MaxRequestIDBytes)
	}
	call := fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/call","params":{"name":"max-result","arguments":{}}}`, requestID)
	writeRawRPC(t, clientConn, call)
	response, readErr := reader.ReadBytes('\n')
	if readErr != nil {
		select {
		case serveErr := <-serverErr:
			t.Fatalf("read max-valid response error = %v (server error: %v)", readErr, serveErr)
		default:
			t.Fatalf("read max-valid response error = %v", readErr)
		}
	}
	if len(response) < 1 || response[len(response)-1] != '\n' {
		t.Fatalf("response missing newline delimiter")
	}
	if got := len(response) - 1; got > DefaultMaxMessageBytes {
		t.Fatalf("response JSON bytes = %d, exceed frame limit %d", got, DefaultMaxMessageBytes)
	}
	var decoded struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(response) error = %v", err)
	}
	if len(decoded.Error) != 0 && string(decoded.Error) != "null" {
		t.Fatalf("max-valid result returned error: %s", decoded.Error)
	}
	if !bytes.Equal(decoded.ID, canonicalJSONString(t, requestID)) {
		t.Fatalf("response ID length/value mismatch: got %d bytes", len(decoded.ID))
	}
	if len(decoded.Result) == 0 {
		t.Fatal("response result is empty")
	}

	cancel()
	clientConn.Close()
	<-serverErr
}

func TestServeRejectsNullRequestIDBeforeHandler(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.RegisterTool(Tool{
		Name: "guard",
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			calls.Add(1)
			return Result{}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	reader := bufio.NewReader(clientConn)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}`)
	readRawRPC(t, reader)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"guard","arguments":{}}}`)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := reader.ReadBytes('\n')
	if readErr == nil {
		t.Fatal("null request ID unexpectedly received a response")
	}
	if calls.Load() != 0 {
		t.Fatalf("handler calls = %d, want 0", calls.Load())
	}
	cancel()
	clientConn.Close()
	<-serverErr
}

func TestServeRejectsCanonicalExpandedRequestIDBeforeHandler(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.RegisterTool(Tool{
		Name: "guard",
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			calls.Add(1)
			return Result{}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	reader := bufio.NewReader(clientConn)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}`)
	readRawRPC(t, reader)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)

	value := strings.Repeat("c", MaxRequestIDBytes-2-3-1) + "\u2028"
	literalID := `"` + value + `"`
	if len([]byte(literalID)) >= MaxRequestIDBytes {
		t.Fatalf("raw literal ID unexpectedly exceeds bound: %d", len(literalID))
	}
	if len(canonicalJSONString(t, value)) <= MaxRequestIDBytes {
		t.Fatalf("canonical ID did not exceed bound: %d", len(canonicalJSONString(t, value)))
	}
	call := `{"jsonrpc":"2.0","id":` + literalID + `,"method":"tools/call","params":{"name":"guard","arguments":{}}}`
	writeRawRPC(t, clientConn, call)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := reader.ReadBytes('\n')
	if readErr == nil {
		t.Fatal("canonically oversized request ID unexpectedly received a response")
	}
	if calls.Load() != 0 {
		t.Fatalf("handler calls = %d, want 0", calls.Load())
	}
	cancel()
	clientConn.Close()
	if err := <-serverErr; err != nil && strings.Contains(err.Error(), value) {
		t.Fatalf("server error leaked canonical-expanded ID: %v", err)
	}
}

func TestServeRejectsBatchWithOversizedIDBeforeDispatch(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.RegisterTool(Tool{
		Name: "guard",
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			calls.Add(1)
			return Result{}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	reader := bufio.NewReader(clientConn)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}`)
	readRawRPC(t, reader)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)

	overlargeID := strings.Repeat("b", MaxFrameOverheadBytes)
	call := fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/call","params":{"name":"guard","arguments":{}}}`, overlargeID)
	writeRawRPC(t, clientConn, " \t["+call+"]")
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, readErr := reader.ReadBytes('\n')
	if readErr == nil {
		t.Fatal("batch with oversized ID unexpectedly received a response")
	}
	if calls.Load() != 0 {
		t.Fatalf("handler calls = %d, want 0", calls.Load())
	}
	cancel()
	clientConn.Close()
	if err := <-serverErr; err != nil && strings.Contains(err.Error(), overlargeID) {
		t.Fatalf("server error leaked batch ID: %v", err)
	}
}

func TestServeRejectsBatchOfMaxOutputCallsBeforeDispatch(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	maxResult := exactStructuredContent(t, s)
	if err := s.RegisterTool(Tool{
		Name: "max-result",
		Handler: func(context.Context, json.RawMessage) (Result, error) {
			calls.Add(1)
			return Result{StructuredContent: maxResult}, nil
		},
	}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	reader := bufio.NewReader(clientConn)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}`)
	readRawRPC(t, reader)
	writeRawRPC(t, clientConn, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)
	batch := `[{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"max-result","arguments":{}}},{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"max-result","arguments":{}}}]`
	writeRawRPC(t, clientConn, batch)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, readErr := reader.ReadBytes('\n')
	if readErr == nil && len(response)-1 > DefaultMaxMessageBytes {
		t.Fatalf("batch response JSON bytes = %d, exceed frame limit %d", len(response)-1, DefaultMaxMessageBytes)
	}
	if calls.Load() != 0 {
		t.Fatalf("handler calls = %d, want 0", calls.Load())
	}
	cancel()
	clientConn.Close()
	if err := <-serverErr; err != nil && strings.Contains(err.Error(), "max-result") {
		t.Fatalf("server error leaked tool/request data: %v", err)
	}
}

func exactStructuredContent(t *testing.T, s *Server) json.RawMessage {
	t.Helper()
	for n := DefaultMaxOutputBytes; n >= 0; n-- {
		candidate := json.RawMessage(fmt.Sprintf(`{"value":%q}`, strings.Repeat("x", n)))
		wire, err := s.result(Result{StructuredContent: candidate})
		if err != nil {
			continue
		}
		encoded, err := json.Marshal(wire)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		if len(encoded) == DefaultMaxOutputBytes {
			return candidate
		}
	}
	t.Fatal("could not construct exact-boundary structured output")
	return nil
}

func canonicalJSONString(t *testing.T, value string) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatalf("canonical ID encoding error = %v", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
}

func writeRawRPC(t *testing.T, writer io.Writer, raw string) {
	t.Helper()
	if _, err := io.WriteString(writer, raw+"\n"); err != nil {
		t.Fatalf("writeRawRPC() error = %v", err)
	}
}

func readRawRPC(t *testing.T, reader *bufio.Reader) []byte {
	t.Helper()
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatalf("readRawRPC() error = %v", err)
	}
	return line
}

func exactObjectJSON(t *testing.T, size int) json.RawMessage {
	t.Helper()
	if size < len(`{"x":""}`) {
		t.Fatalf("size %d is too small for exact object fixture", size)
	}
	return json.RawMessage(fmt.Sprintf(`{"x":%q}`, strings.Repeat("x", size-len(`{"x":""}`))))
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
	probe := serverwire.NewClient(&serverwire.Implementation{Name: "probe", Version: "0"}, nil)
	cs, err := probe.Connect(ctx, &serverwire.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	if err != nil {
		clientConn.Close()
		t.Fatalf("client Connect() error = %v", err)
	}
	defer cs.Close()

	_, err = cs.CallTool(ctx, &serverwire.CallToolParams{
		Name:      "bounded",
		Arguments: json.RawMessage(`{"too":"large"}`),
	})
	var wireErr *serverwire.JSONRPCError
	if !errors.As(err, &wireErr) || wireErr.Code != serverwire.CodeInvalidParams {
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
		{name: "invalid argument", err: fmt.Errorf("%w: handler-secret", ErrInvalidArgument), code: serverwire.CodeInvalidParams},
		{name: "internal", err: errors.New("handler-secret"), code: serverwire.CodeInternalError},
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
			probe := serverwire.NewClient(&serverwire.Implementation{Name: "probe", Version: "0"}, nil)
			cs, err := probe.Connect(ctx, &serverwire.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
			if err != nil {
				clientConn.Close()
				cancel()
				t.Fatalf("client Connect() error = %v", err)
			}
			_, callErr := cs.CallTool(ctx, &serverwire.CallToolParams{Name: "fail"})
			var wireErr *serverwire.JSONRPCError
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
	probe := serverwire.NewClient(&serverwire.Implementation{Name: "probe", Version: "0"}, nil)
	cs, err := probe.Connect(ctx, &serverwire.IOTransport{Reader: clientConn, Writer: clientConn}, nil)
	if err != nil {
		clientConn.Close()
		cancel()
		t.Fatalf("client Connect() error = %v", err)
	}
	_, callErr := cs.CallTool(ctx, &serverwire.CallToolParams{Name: "big"})
	var wireErr *serverwire.JSONRPCError
	if !errors.As(callErr, &wireErr) || wireErr.Code != serverwire.CodeInternalError {
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
