package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Handler handles one tools/call argument object. Arguments are a defensive
// copy of the bounded JSON received from the peer. A handler returning
// ErrInvalidArgument (possibly wrapped) produces JSON-RPC -32602; all other
// handler errors produce the generic JSON-RPC -32603 message.
type Handler func(context.Context, json.RawMessage) (Result, error)

// ToolHandler is a descriptive alias for Handler.
type ToolHandler = Handler

// Tool is a CodeRig-owned tool definition. InputSchema must be a JSON object
// schema; an omitted schema means any object. OutputSchema is optional. SDK
// types intentionally do not appear in this exported API.
type Tool struct {
	Name         string
	Title        string
	Description  string
	InputSchema  json.RawMessage
	OutputSchema json.RawMessage
	Handler      Handler
}

// Content is the deliberately narrow content surface exposed by this server.
// Collaboration responses are text plus structured JSON; image/audio/resource
// content would expand the process boundary without a use in this server.
type Content struct {
	Text string
}

// Result is the CodeRig-owned projection of an MCP tools/call result.
type Result struct {
	Content           []Content
	StructuredContent json.RawMessage
	IsError           bool
}

// ToolResult is a descriptive alias for Result.
type ToolResult = Result

func normalizeTool(tool Tool) (Tool, error) {
	if err := validateToolName(tool.Name); err != nil {
		return Tool{}, err
	}
	if tool.Handler == nil {
		return Tool{}, ErrInvalidToolSchema
	}
	if len(tool.InputSchema) == 0 {
		tool.InputSchema = json.RawMessage(`{"type":"object"}`)
	}
	if err := validateObjectSchema(tool.InputSchema); err != nil {
		return Tool{}, err
	}
	if len(tool.OutputSchema) != 0 && !json.Valid(tool.OutputSchema) {
		return Tool{}, ErrInvalidToolSchema
	}
	tool.InputSchema = append(json.RawMessage(nil), tool.InputSchema...)
	tool.OutputSchema = append(json.RawMessage(nil), tool.OutputSchema...)
	return tool, nil
}

func validateToolName(name string) error {
	if name == "" || len(name) > 128 {
		return fmt.Errorf("%w: %s", ErrInvalidToolName, name)
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return fmt.Errorf("%w: %s", ErrInvalidToolName, name)
		}
	}
	return nil
}

func validateObjectSchema(raw json.RawMessage) error {
	var schema map[string]json.RawMessage
	if !json.Valid(raw) || json.Unmarshal(raw, &schema) != nil || schema == nil {
		return ErrInvalidToolSchema
	}
	var typ string
	if rawType, ok := schema["type"]; !ok || json.Unmarshal(rawType, &typ) != nil || typ != "object" {
		return ErrInvalidToolSchema
	}
	return nil
}

func (s *Server) handler(handler Handler) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := json.RawMessage(`{}`)
		if req == nil || req.Params == nil {
			return nil, invalidArgumentWireError()
		}
		if len(req.Params.Arguments) > s.cfg.MaxInputBytes {
			return nil, invalidArgumentWireError()
		}
		if len(req.Params.Arguments) > 0 {
			args = append(json.RawMessage(nil), req.Params.Arguments...)
			if !isObjectJSON(args) || !json.Valid(args) {
				return nil, invalidArgumentWireError()
			}
		}

		result, err := handler(ctx, args)
		if err != nil {
			if errors.Is(err, ErrInvalidArgument) {
				return nil, invalidArgumentWireError()
			}
			return nil, internalWireError()
		}
		wireResult, err := s.result(result)
		if err != nil {
			return nil, err
		}
		return wireResult, nil
	}
}

func (s *Server) result(result Result) (*mcp.CallToolResult, error) {
	wire := &mcp.CallToolResult{IsError: result.IsError}
	for _, content := range result.Content {
		wire.Content = append(wire.Content, &mcp.TextContent{Text: content.Text})
	}
	if len(result.StructuredContent) > 0 {
		if !json.Valid(result.StructuredContent) {
			return nil, internalWireError()
		}
		wire.StructuredContent = append(json.RawMessage(nil), result.StructuredContent...)
	}

	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > s.cfg.MaxOutputBytes {
		return nil, internalWireError()
	}
	return wire, nil
}

func isObjectJSON(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func invalidArgumentWireError() error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: invalidArgumentMessage}
}

func internalWireError() error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: internalErrorMessage}
}
