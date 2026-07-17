package protocol_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
)

// elicitBounds is a small, explicit bound set: small enough that a test can
// exceed a bound without building a megabyte, and every field set so that a
// failure names the bound it meant rather than a zero that fails closed.
func elicitBounds() protocol.Bounds {
	b := initBounds()
	b.MaxElicitMessageBytes = 64
	b.MaxElicitSchemaBytes = 128
	return b
}

// paddedSchema builds a JSON Schema object of roughly n bytes, so a test can sit
// either side of MaxElicitSchemaBytes deliberately.
func paddedSchema(n int) json.RawMessage {
	const head = `{"type":"object","title":"`
	const tail = `"}`
	pad := n - len(head) - len(tail)
	if pad < 0 {
		pad = 0
	}
	return json.RawMessage(head + strings.Repeat("x", pad) + tail)
}

func TestFromSDKElicitParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      *mcp.ElicitParams
		want    protocol.ElicitRequest
		wantErr bool
		// errIs, when set, is the sentinel/type the error must match, so a case
		// asserts *why* it failed rather than only that it did.
		errIs func(error) bool
	}{
		{
			name:    "nil params are rejected",
			in:      nil,
			wantErr: true,
		},
		{
			name: "an empty mode is form, per MCP's own default",
			in:   &mcp.ElicitParams{Message: "confirm?"},
			want: protocol.ElicitRequest{Mode: protocol.ElicitModeForm, Message: "confirm?"},
		},
		{
			name: "an explicit form mode with a schema",
			in: &mcp.ElicitParams{
				Mode:            "form",
				Message:         "your name?",
				RequestedSchema: json.RawMessage(`{"type":"object"}`),
			},
			want: protocol.ElicitRequest{
				Mode:    protocol.ElicitModeForm,
				Message: "your name?",
				Schema:  json.RawMessage(`{"type":"object"}`),
			},
		},
		{
			name: "a form with no schema is legal: a bare confirmation",
			in:   &mcp.ElicitParams{Mode: "form", Message: "sure?"},
			want: protocol.ElicitRequest{Mode: protocol.ElicitModeForm, Message: "sure?"},
		},
		{
			name: "url mode carries its url and id",
			in: &mcp.ElicitParams{
				Mode:          "url",
				Message:       "authorize",
				URL:           "https://example.com/authorize?token=abc",
				ElicitationID: "e-1",
			},
			want: protocol.ElicitRequest{
				Mode:          protocol.ElicitModeURL,
				Message:       "authorize",
				URL:           "https://example.com/authorize?token=abc",
				ElicitationID: "e-1",
			},
		},
		{
			name: "a url mode schema is dropped, not carried",
			in: &mcp.ElicitParams{
				Mode:            "url",
				Message:         "authorize",
				URL:             "https://example.com/a",
				RequestedSchema: json.RawMessage(`{"type":"object"}`),
			},
			want: protocol.ElicitRequest{
				Mode:    protocol.ElicitModeURL,
				Message: "authorize",
				URL:     "https://example.com/a",
			},
		},
		{
			name: "a form mode url is dropped, not carried",
			in: &mcp.ElicitParams{
				Mode:          "form",
				Message:       "name?",
				URL:           "https://example.com/a",
				ElicitationID: "e-1",
			},
			want: protocol.ElicitRequest{Mode: protocol.ElicitModeForm, Message: "name?"},
		},
		{
			name:    "an unknown mode is rejected, never guessed",
			in:      &mcp.ElicitParams{Mode: "voice", Message: "speak"},
			wantErr: true,
		},
		{
			name:    "a mode differing only in case is unknown: the wire strings are exact",
			in:      &mcp.ElicitParams{Mode: "Form", Message: "hi"},
			wantErr: true,
		},
		{
			name: "a message at the bound is accepted",
			in:   &mcp.ElicitParams{Message: strings.Repeat("m", 64)},
			want: protocol.ElicitRequest{Mode: protocol.ElicitModeForm, Message: strings.Repeat("m", 64)},
		},
		{
			name:    "a message over the bound is rejected, not truncated",
			in:      &mcp.ElicitParams{Message: strings.Repeat("m", 65)},
			wantErr: true,
			errIs:   isOverLimit(protocol.WhatElicitMessageBytes),
		},
		{
			name: "a schema at the bound is accepted",
			in: &mcp.ElicitParams{
				Mode:            "form",
				RequestedSchema: paddedSchema(128),
			},
			want: protocol.ElicitRequest{Mode: protocol.ElicitModeForm, Schema: paddedSchema(128)},
		},
		{
			name: "a schema over the bound is rejected",
			in: &mcp.ElicitParams{
				Mode:            "form",
				RequestedSchema: paddedSchema(129),
			},
			wantErr: true,
			errIs:   isOverLimit(protocol.WhatElicitSchemaBytes),
		},
		{
			name: "an over-bound url is rejected: it is part of the prompt",
			in: &mcp.ElicitParams{
				Mode: "url",
				URL:  "https://example.com/" + strings.Repeat("p", 64),
			},
			wantErr: true,
			errIs:   isOverLimit(protocol.WhatElicitMessageBytes),
		},
		{
			name: "an over-bound elicitation id is rejected",
			in: &mcp.ElicitParams{
				Mode:          "url",
				URL:           "https://example.com/a",
				ElicitationID: strings.Repeat("i", 65),
			},
			wantErr: true,
			errIs:   isOverLimit(protocol.WhatElicitMessageBytes),
		},
		{
			name: "a non-object schema is rejected",
			in: &mcp.ElicitParams{
				Mode:            "form",
				RequestedSchema: json.RawMessage(`["not","an","object"]`),
			},
			wantErr: true,
		},
		{
			name: "an unmarshalable schema is rejected",
			in: &mcp.ElicitParams{
				Mode:            "form",
				RequestedSchema: json.RawMessage(`{not json`),
			},
			wantErr: true,
		},
		{
			name: "a schema nested past the depth bound is rejected",
			in: &mcp.ElicitParams{
				Mode:            "form",
				RequestedSchema: json.RawMessage(deepObject(64)),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := elicitBounds()
			got, err := protocol.FromSDKElicitParams(tt.in, b)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromSDKElicitParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if tt.errIs != nil && !tt.errIs(err) {
					t.Errorf("FromSDKElicitParams() error = %v, not the bound this case is about", err)
				}
				// A rejected request must yield nothing at all: a caller that
				// ignored the error must not find a usable prompt waiting.
				if got.Mode != 0 || got.Message != "" || got.URL != "" ||
					got.ElicitationID != "" || got.Schema != nil {
					t.Errorf("FromSDKElicitParams() returned %+v alongside an error, want the zero request", got)
				}
				return
			}
			if got.Mode != tt.want.Mode || got.Message != tt.want.Message ||
				got.URL != tt.want.URL || got.ElicitationID != tt.want.ElicitationID {
				t.Errorf("FromSDKElicitParams() = %+v, want %+v", got, tt.want)
			}
			if string(got.Schema) != string(tt.want.Schema) {
				t.Errorf("Schema = %s, want %s", got.Schema, tt.want.Schema)
			}
		})
	}
}

// isOverLimit returns a matcher for an OverLimitError naming a particular bound.
func isOverLimit(what string) func(error) bool {
	return func(err error) bool {
		var over *limits.OverLimitError
		return errors.As(err, &over) && over.What == what
	}
}

// deepObject builds a JSON object nested n deep.
func deepObject(n int) string {
	return strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n)
}

// TestFromSDKElicitParamsDoesNotAliasSDKMemory: the schema this boundary hands
// on must not be a window into a value the SDK still owns. json.Marshal
// allocates, so this holds — and holds only as long as nobody "optimizes" the
// RawMessage fast path back in.
func TestFromSDKElicitParamsDoesNotAliasSDKMemory(t *testing.T) {
	t.Parallel()

	schema := json.RawMessage(`{"type":"object"}`)
	params := &mcp.ElicitParams{Mode: "form", RequestedSchema: schema}

	got, err := protocol.FromSDKElicitParams(params, elicitBounds())
	if err != nil {
		t.Fatalf("FromSDKElicitParams() error = %v", err)
	}
	before := string(got.Schema)
	// The SDK's buffer is scribbled on, as a peer's memory may be at any time.
	for i := range schema {
		schema[i] = 'X'
	}
	if string(got.Schema) != before {
		t.Errorf("the converted schema aliased SDK memory: %s became %s", before, got.Schema)
	}
}

func TestToSDKElicitResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		in          protocol.ElicitResult
		wantAction  string
		wantContent map[string]any
		wantErr     bool
	}{
		{
			name:        "an accept carries its content as the SDK's map",
			in:          protocol.ElicitResult{Action: protocol.ElicitAccept, Content: json.RawMessage(`{"name":"ada"}`)},
			wantAction:  "accept",
			wantContent: map[string]any{"name": "ada"},
		},
		{
			name:       "an accept with no content is legal: a bare confirmation",
			in:         protocol.ElicitResult{Action: protocol.ElicitAccept},
			wantAction: "accept",
		},
		{
			name:       "a decline",
			in:         protocol.ElicitResult{Action: protocol.ElicitDecline},
			wantAction: "decline",
		},
		{
			name:       "a cancel",
			in:         protocol.ElicitResult{Action: protocol.ElicitCancel},
			wantAction: "cancel",
		},
		{
			name:    "the zero action is refused: it is not an answer",
			in:      protocol.ElicitResult{},
			wantErr: true,
		},
		{
			name:    "an undeclared action is refused",
			in:      protocol.ElicitResult{Action: protocol.ElicitAction(99)},
			wantErr: true,
		},
		{
			name:    "a decline carrying content is refused rather than guessed",
			in:      protocol.ElicitResult{Action: protocol.ElicitDecline, Content: json.RawMessage(`{"name":"ada"}`)},
			wantErr: true,
		},
		{
			name:    "content that is not an object is refused",
			in:      protocol.ElicitResult{Action: protocol.ElicitAccept, Content: json.RawMessage(`["ada"]`)},
			wantErr: true,
		},
		{
			name:    "malformed content is refused",
			in:      protocol.ElicitResult{Action: protocol.ElicitAccept, Content: json.RawMessage(`{oops`)},
			wantErr: true,
		},
		{
			name:    "JSON null content is refused, not silently dropped",
			in:      protocol.ElicitResult{Action: protocol.ElicitAccept, Content: json.RawMessage(`null`)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := protocol.ToSDKElicitResult(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ToSDKElicitResult() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if got != nil {
					t.Errorf("ToSDKElicitResult() returned %+v alongside an error, want nil", got)
				}
				return
			}
			if got.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", got.Action, tt.wantAction)
			}
			if len(got.Content) != len(tt.wantContent) {
				t.Fatalf("Content = %v, want %v", got.Content, tt.wantContent)
			}
			for k, want := range tt.wantContent {
				if got.Content[k] != want {
					t.Errorf("Content[%q] = %v, want %v", k, got.Content[k], want)
				}
			}
		})
	}
}

func TestElicitModeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode protocol.ElicitMode
		want string
	}{
		{protocol.ElicitModeForm, "form"},
		{protocol.ElicitModeURL, "url"},
		{0, "unknown"},
		{protocol.ElicitMode(200), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("ElicitMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestElicitActionString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		action protocol.ElicitAction
		want   string
	}{
		{protocol.ElicitAccept, "accept"},
		{protocol.ElicitDecline, "decline"},
		{protocol.ElicitCancel, "cancel"},
		{0, "unknown"},
		{protocol.ElicitAction(200), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.action.String(); got != tt.want {
			t.Errorf("ElicitAction(%d).String() = %q, want %q", tt.action, got, tt.want)
		}
	}
}

// FuzzFromSDKElicitParams drives arbitrary server-controlled bytes through the
// elicitation converter — the mode, the prompt and the requested schema are all
// chosen by an untrusted peer.
//
// The invariants are the ones a human's safety rests on: the converter must
// never panic, and anything it *accepts* must be a declared mode, a prompt
// within the bound, and (in form mode) a schema that is valid JSON within its
// own bound. An accepted request is one this module is about to show a person,
// so "accepted" is the claim worth checking.
func FuzzFromSDKElicitParams(f *testing.F) {
	seeds := []struct {
		mode, message, schema, url, id string
	}{
		{"", "confirm?", "", "", ""},
		{"form", "your name?", `{"type":"object"}`, "", ""},
		{"form", "", "", "", ""},
		{"url", "authorize", "", "https://example.com/a?token=x", "e-1"},
		{"voice", "speak", "", "", ""},
		{"FORM", "case", "", "", ""},
		{"form", strings.Repeat("m", 65), "", "", ""},
		{"form", "ok", `{"unterminated":`, "", ""},
		{"form", "ok", `[]`, "", ""},
		{"form", "ok", `null`, "", ""},
		{"form", "ok", deepObject(64), "", ""},
		{"form", "ok", `{"pad":"` + strings.Repeat("x", 200) + `"}`, "", ""},
		{"url", "ok", "", "https://example.com/" + strings.Repeat("p", 64), ""},
		{"form", "\xff\xfe", "", "", ""},
	}
	for _, s := range seeds {
		f.Add(s.mode, s.message, s.schema, s.url, s.id)
	}

	f.Fuzz(func(t *testing.T, mode, message, schema, url, id string) {
		b := elicitBounds()
		params := &mcp.ElicitParams{Mode: mode, Message: message, URL: url, ElicitationID: id}
		if schema != "" {
			params.RequestedSchema = json.RawMessage(schema)
		}

		got, err := protocol.FromSDKElicitParams(params, b)
		if err != nil {
			return
		}

		// Accepted: every promise this boundary makes must hold.
		if got.Mode != protocol.ElicitModeForm && got.Mode != protocol.ElicitModeURL {
			t.Fatalf("accepted an undeclared mode %d from %q", got.Mode, mode)
		}
		if len(got.Message) > b.MaxElicitMessageBytes {
			t.Fatalf("accepted a %d byte prompt, over the %d byte bound",
				len(got.Message), b.MaxElicitMessageBytes)
		}
		switch got.Mode {
		case protocol.ElicitModeForm:
			if got.URL != "" || got.ElicitationID != "" {
				t.Fatalf("a form carries url fields: %+v", got)
			}
			if len(got.Schema) > b.MaxElicitSchemaBytes {
				t.Fatalf("accepted a %d byte schema, over the %d byte bound",
					len(got.Schema), b.MaxElicitSchemaBytes)
			}
			if len(got.Schema) > 0 && !json.Valid(got.Schema) {
				t.Fatalf("accepted an invalid JSON schema: %s", got.Schema)
			}
		case protocol.ElicitModeURL:
			if got.Schema != nil {
				t.Fatalf("a url elicitation carries a schema: %+v", got)
			}
			if len(got.URL) > b.MaxElicitMessageBytes {
				t.Fatalf("accepted a %d byte url, over the %d byte bound", len(got.URL), b.MaxElicitMessageBytes)
			}
		}
	})
}
