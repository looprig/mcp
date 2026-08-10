package server

import (
	"context"
	"encoding/json"
	"fmt"
)

// Handler handles one tools/call argument object. Arguments are a defensive
// copy of the bounded JSON received from the peer. A handler returning
// ErrInvalidArgument (possibly wrapped) produces JSON-RPC -32602; all other
// handler errors produce the generic JSON-RPC -32603 message.
type Handler func(context.Context, json.RawMessage) (Result, error)

// ToolHandler is a descriptive alias for Handler.
type ToolHandler = Handler

// Tool is a product-owned tool definition. InputSchema must be a JSON object
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

// Result is the product-owned projection of an MCP tools/call result.
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

// result is retained as a package-local sizing seam for tests; it deliberately
// uses only neutral JSON data and does not expose an SDK result type.
type sizedResult struct {
	Content           []sizedContent  `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError,omitempty"`
}
type sizedContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (s *Server) result(result Result) (*sizedResult, error) {
	w := &sizedResult{IsError: result.IsError}
	for _, c := range result.Content {
		w.Content = append(w.Content, sizedContent{Type: "text", Text: c.Text})
	}
	if len(result.StructuredContent) > 0 && !json.Valid(result.StructuredContent) {
		return nil, ErrInternal
	}
	w.StructuredContent = append(json.RawMessage(nil), result.StructuredContent...)
	b, err := json.Marshal(w)
	if err != nil || len(b) > s.cfg.MaxOutputBytes {
		return nil, ErrInternal
	}
	return w, nil
}
