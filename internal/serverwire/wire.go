// Package serverwire is the sole go-sdk adapter for the bounded MCP server.
package serverwire

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Handler func(context.Context, json.RawMessage) (Result, error)
type Tool struct {
	Name, Title, Description  string
	InputSchema, OutputSchema json.RawMessage
	Handler                   Handler
}
type Content struct{ Text string }
type Result struct {
	Content           []Content
	StructuredContent json.RawMessage
	IsError           bool
}

type Config struct {
	Name, Version                                  string
	MaxMessageBytes, MaxInputBytes, MaxOutputBytes int
	MaxConcurrentRequests                          int
	MaxRequestIDBytes                              int
}

type Adapter struct {
	cfg Config
	sdk *mcp.Server
	ctx context.Context
}

func New(cfg Config) *Adapter {
	s := mcp.NewServer(&mcp.Implementation{Name: cfg.Name, Version: cfg.Version}, &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}}})
	return &Adapter{cfg: cfg, sdk: s}
}

func (a *Adapter) RegisterTool(t Tool) {
	a.sdk.AddTool(&mcp.Tool{Name: t.Name, Title: t.Title, Description: t.Description, InputSchema: t.InputSchema, OutputSchema: t.OutputSchema}, a.handler(t.Handler))
}

func (a *Adapter) handler(fn Handler) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if req == nil || req.Params == nil || len(req.Params.Arguments) > a.cfg.MaxInputBytes || !objectJSON(req.Params.Arguments) {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "invalid arguments"}
		}
		args := append(json.RawMessage(nil), req.Params.Arguments...)
		ctx2, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(a.ctx, cancel)
		defer func() { stop(); cancel() }()
		result, err := fn(ctx2, args)
		if err != nil {
			if errors.Is(err, ErrInvalidArgument) {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "invalid arguments"}
			}
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "internal error"}
		}
		wire := &mcp.CallToolResult{IsError: result.IsError}
		for _, c := range result.Content {
			wire.Content = append(wire.Content, &mcp.TextContent{Text: c.Text})
		}
		if len(result.StructuredContent) > 0 {
			if !json.Valid(result.StructuredContent) {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "internal error"}
			}
			wire.StructuredContent = append(json.RawMessage(nil), result.StructuredContent...)
		}
		if b, e := json.Marshal(wire); e != nil || len(b) > a.cfg.MaxOutputBytes {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "internal error"}
		}
		return wire, nil
	}
}

var ErrInvalidArgument = errors.New("invalid argument")
var ErrClosed = errors.New("server closed")
var ErrInputLimit = errors.New("input exceeds limit")
var ErrOutputLimit = errors.New("output exceeds limit")
var ErrInputEnvelope = errors.New("input envelope exceeds limit")
var ErrBatchUnsupported = errors.New("batch requests are not supported")

func objectJSON(b []byte) bool {
	var v map[string]json.RawMessage
	return len(b) > 0 && json.Unmarshal(b, &v) == nil && v != nil
}

// Serve owns both endpoints. Cancellation closes them before waiting for the SDK session.
func (a *Adapter) Serve(ctx context.Context, r io.ReadCloser, w io.WriteCloser) error {
	a.ctx = ctx
	fr := NewFrameReader(r, a.cfg.MaxMessageBytes, a.cfg.MaxRequestIDBytes)
	fw := NewFrameWriter(w, a.cfg.MaxMessageBytes)
	transport := &boundedTransport{reader: &readCloser{Reader: fr, Closer: r}, writer: &writeCloser{Writer: fw, Closer: w}, max: a.cfg.MaxConcurrentRequests}
	session, err := a.sdk.Connect(ctx, transport, nil)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = r.Close(); _ = w.Close(); _ = transport.Close() })
	defer stop()
	err = session.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
