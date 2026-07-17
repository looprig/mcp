package protocol_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
)

// resultBounds are tight, so a test can reach each bound with a small value.
var resultBounds = protocol.Bounds{
	MaxSchemaBytes:     256,
	MaxSchemaDepth:     5,
	MaxTextBytes:       64,
	MaxStructuredBytes: 64,
	MaxBinaryItemBytes: 32,
	MaxBinaryItems:     2,
	MaxLogBytes:        32,
}

func TestFromSDKCallToolResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		res            *mcp.CallToolResult
		wantErr        bool
		wantIsError    bool
		wantStructured string
		wantWarnings   int
		wantContent    int
	}{
		{
			name: "a plain text result",
			res: &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "hello"}},
			},
			wantContent: 1,
		},
		{
			name: "a tool error is a result, not an error",
			res: &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "it broke"}},
			},
			wantIsError: true,
			wantContent: 1,
		},
		{
			name: "structured content within the bound is retained",
			res: &mcp.CallToolResult{
				StructuredContent: map[string]any{"ok": true},
			},
			wantStructured: `{"ok":true}`,
		},
		{
			name: "structured content over the bound is dropped with a warning",
			res: &mcp.CallToolResult{
				StructuredContent: map[string]any{"pad": strings.Repeat("x", 200)},
			},
			wantStructured: "",
			wantWarnings:   1,
		},
		{
			name: "structured content too deep is dropped with a warning",
			res: &mcp.CallToolResult{
				StructuredContent: json.RawMessage(
					strings.Repeat(`{"a":`, 10) + `1` + strings.Repeat(`}`, 10)),
			},
			wantWarnings: 1,
		},
		{
			name:           "no structured content is not a defect",
			res:            &mcp.CallToolResult{},
			wantStructured: "",
			wantWarnings:   0,
		},
		{
			name: "JSON null structured content is absence, not a defect",
			res: &mcp.CallToolResult{
				StructuredContent: json.RawMessage(`null`),
			},
			wantStructured: "",
			wantWarnings:   0,
		},
		{
			name: "unmarshalable structured content is dropped with a warning",
			res: &mcp.CallToolResult{
				StructuredContent: make(chan int), // channels do not marshal
			},
			wantWarnings: 1,
		},
		{
			name:    "a nil result is refused",
			res:     nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKCallToolResult(tt.res, resultBounds)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.IsError != tt.wantIsError {
				t.Errorf("IsError = %v, want %v", got.IsError, tt.wantIsError)
			}
			if string(got.Structured) != tt.wantStructured {
				t.Errorf("Structured = %s, want %q", got.Structured, tt.wantStructured)
			}
			if len(got.Warnings) != tt.wantWarnings {
				t.Errorf("Warnings = %v, want %d", got.Warnings, tt.wantWarnings)
			}
			if len(got.Content) != tt.wantContent {
				t.Errorf("Content = %d items, want %d", len(got.Content), tt.wantContent)
			}
			// Whatever happened, an accepted structured document is within the
			// bound. This is the invariant MaxStructuredBytes exists for.
			if len(got.Structured) > resultBounds.MaxStructuredBytes {
				t.Errorf("retained structured content is %d bytes, over the %d bound",
					len(got.Structured), resultBounds.MaxStructuredBytes)
			}
		})
	}
}

// TestStructuredOverLimitWarningIsTyped: the warning must name the bound that
// was hit, so an operator can tell an over-limit drop from a malformed one and
// know which limit to raise.
func TestStructuredOverLimitWarningIsTyped(t *testing.T) {
	t.Parallel()

	got, err := protocol.FromSDKCallToolResult(&mcp.CallToolResult{
		StructuredContent: map[string]any{"pad": strings.Repeat("x", 200)},
	}, resultBounds)
	if err != nil {
		t.Fatalf("FromSDKCallToolResult() error = %v", err)
	}
	if len(got.Warnings) != 1 {
		t.Fatalf("Warnings = %v, want one", got.Warnings)
	}
	w := got.Warnings[0]
	if !strings.Contains(w, protocol.WhatStructuredBytes) {
		t.Errorf("warning = %q, want it to name %q", w, protocol.WhatStructuredBytes)
	}
	// The oversized document itself must not be in the warning: that would
	// retain the very bytes the bound refused.
	if strings.Contains(w, strings.Repeat("x", 50)) {
		t.Errorf("the warning quotes the payload it refused: %q", w)
	}
	// And the same shape is what limits reports elsewhere.
	over := &limits.OverLimitError{What: protocol.WhatStructuredBytes, Limit: resultBounds.MaxStructuredBytes}
	if !strings.Contains(w, over.Error()) {
		t.Errorf("warning = %q, want it to carry %q", w, over.Error())
	}
}

// TestCallToolResultContentIsBounded proves the content bounds are applied to a
// tool result, not only to a bare content list.
func TestCallToolResultContentIsBounded(t *testing.T) {
	t.Parallel()

	got, err := protocol.FromSDKCallToolResult(&mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: strings.Repeat("t", 500)},
			&mcp.ImageContent{Data: make([]byte, 500), MIMEType: "image/png"},
		},
	}, resultBounds)
	if err != nil {
		t.Fatalf("FromSDKCallToolResult() error = %v", err)
	}
	if len(got.Content) != 2 {
		t.Fatalf("Content = %d items, want both positions kept", len(got.Content))
	}

	text, ok := got.Content[0].(protocol.TextContent)
	if !ok {
		t.Fatalf("Content[0] = %T, want TextContent", got.Content[0])
	}
	if !text.Truncated || len(text.Text) > resultBounds.MaxTextBytes {
		t.Errorf("text = %d bytes (truncated=%v), want it cut to %d",
			len(text.Text), text.Truncated, resultBounds.MaxTextBytes)
	}

	// An oversized image is refused, and says so rather than vanishing.
	unsupported, ok := got.Content[1].(protocol.UnsupportedContent)
	if !ok {
		t.Fatalf("Content[1] = %T, want UnsupportedContent for an oversized image", got.Content[1])
	}
	if unsupported.Kind != protocol.KindImage || unsupported.Bytes != 500 {
		t.Errorf("Unsupported = %+v, want the image's refused size reported", unsupported)
	}
}

func TestFromSDKGetPromptResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		res     *mcp.GetPromptResult
		wantErr bool
	}{
		{
			name: "a well-formed prompt",
			res: &mcp.GetPromptResult{
				Description: "a greeting",
				Messages: []*mcp.PromptMessage{
					{Role: "user", Content: &mcp.TextContent{Text: "Hello"}},
				},
			},
		},
		{
			name: "no messages is valid",
			res:  &mcp.GetPromptResult{Description: "empty"},
		},
		{
			name:    "a nil result is refused",
			res:     nil,
			wantErr: true,
		},
		{
			name: "a nil message is refused",
			res: &mcp.GetPromptResult{
				Messages: []*mcp.PromptMessage{nil},
			},
			wantErr: true,
		},
		{
			name: "a message with nil content is refused",
			res: &mcp.GetPromptResult{
				Messages: []*mcp.PromptMessage{{Role: "user"}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := protocol.FromSDKGetPromptResult(tt.res, resultBounds)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGetPromptResultIsBounded: a prompt's text is server data like any other.
func TestGetPromptResultIsBounded(t *testing.T) {
	t.Parallel()

	got, err := protocol.FromSDKGetPromptResult(&mcp.GetPromptResult{
		Description: strings.Repeat("d", 500),
		Messages: []*mcp.PromptMessage{
			{Role: mcp.Role(strings.Repeat("r", 500)), Content: &mcp.TextContent{Text: strings.Repeat("m", 500)}},
		},
	}, resultBounds)
	if err != nil {
		t.Fatalf("FromSDKGetPromptResult() error = %v", err)
	}
	if len(got.Description) > resultBounds.MaxTextBytes {
		t.Errorf("Description is %d bytes, over the %d bound", len(got.Description), resultBounds.MaxTextBytes)
	}
	if len(got.Messages[0].Role) > resultBounds.MaxTextBytes {
		t.Errorf("Role is %d bytes, over the %d bound", len(got.Messages[0].Role), resultBounds.MaxTextBytes)
	}
	text, ok := got.Messages[0].Content.(protocol.TextContent)
	if !ok {
		t.Fatalf("Content = %T, want TextContent", got.Messages[0].Content)
	}
	if !text.Truncated || len(text.Text) > resultBounds.MaxTextBytes {
		t.Errorf("message text is %d bytes (truncated=%v), over the %d bound",
			len(text.Text), text.Truncated, resultBounds.MaxTextBytes)
	}
}

func TestFromSDKReadResourceResult(t *testing.T) {
	t.Parallel()

	t.Run("text contents are truncated", func(t *testing.T) {
		t.Parallel()
		got, err := protocol.FromSDKReadResourceResult(&mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{URI: "x://a", MIMEType: "text/plain", Text: strings.Repeat("t", 500)},
			},
		}, resultBounds)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if len(got.Contents) != 1 {
			t.Fatalf("Contents = %+v", got.Contents)
		}
		c := got.Contents[0]
		if !c.Truncated || len(c.Text) > resultBounds.MaxTextBytes {
			t.Errorf("text is %d bytes (truncated=%v), over the %d bound",
				len(c.Text), c.Truncated, resultBounds.MaxTextBytes)
		}
		if c.URI != "x://a" || c.MIMEType != "text/plain" {
			t.Errorf("provenance lost: %+v", c)
		}
	})

	t.Run("a blob within the bound is retained", func(t *testing.T) {
		t.Parallel()
		got, err := protocol.FromSDKReadResourceResult(&mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{URI: "x://a", Blob: []byte("small")},
			},
		}, resultBounds)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if string(got.Contents[0].Data) != "small" {
			t.Errorf("Data = %q, want the blob retained", got.Contents[0].Data)
		}
		if got.Contents[0].Truncated {
			t.Error("Truncated is set on a blob that fits")
		}
	})

	t.Run("an oversized blob is summarized, not injected", func(t *testing.T) {
		t.Parallel()
		got, err := protocol.FromSDKReadResourceResult(&mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{URI: "x://big", MIMEType: "application/octet-stream", Blob: make([]byte, 500)},
			},
		}, resultBounds)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		c := got.Contents[0]
		if len(c.Data) != 0 {
			t.Errorf("an oversized blob was retained (%d bytes): the bound achieved nothing", len(c.Data))
		}
		if !c.Truncated {
			t.Error("Truncated is not set: the caller cannot tell the payload was refused")
		}
		// The metadata is what makes the omission visible.
		if c.URI != "x://big" || c.MIMEType != "application/octet-stream" {
			t.Errorf("the summary lost its provenance: %+v", c)
		}
	})

	t.Run("the binary item budget is enforced across items", func(t *testing.T) {
		t.Parallel()
		// MaxBinaryItems is 2, so the third blob must not be retained.
		got, err := protocol.FromSDKReadResourceResult(&mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{URI: "x://1", Blob: []byte("a")},
				{URI: "x://2", Blob: []byte("b")},
				{URI: "x://3", Blob: []byte("c")},
			},
		}, resultBounds)
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if len(got.Contents) != 3 {
			t.Fatalf("Contents = %d, want every position kept", len(got.Contents))
		}
		if len(got.Contents[0].Data) == 0 || len(got.Contents[1].Data) == 0 {
			t.Error("items within the budget were dropped")
		}
		if len(got.Contents[2].Data) != 0 {
			t.Error("a blob past the binary-item budget was retained")
		}
		if !got.Contents[2].Truncated {
			t.Error("the refused item does not report itself refused")
		}
	})

	t.Run("nil handling", func(t *testing.T) {
		t.Parallel()
		if _, err := protocol.FromSDKReadResourceResult(nil, resultBounds); err == nil {
			t.Error("a nil result was accepted")
		}
		_, err := protocol.FromSDKReadResourceResult(&mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{nil},
		}, resultBounds)
		if err == nil {
			t.Error("a nil contents entry was accepted")
		}
		got, err := protocol.FromSDKReadResourceResult(&mcp.ReadResourceResult{}, resultBounds)
		if err != nil {
			t.Errorf("an empty result is not a defect, got %v", err)
		}
		if len(got.Contents) != 0 {
			t.Errorf("Contents = %+v, want none", got.Contents)
		}
	})
}

func TestFromSDKLogParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		params   *mcp.LoggingMessageParams
		wantText string
	}{
		{
			name:     "a string payload is used as-is",
			params:   &mcp.LoggingMessageParams{Level: "info", Logger: "srv", Data: "hello"},
			wantText: "hello",
		},
		{
			name:     "a structured payload is rendered as JSON",
			params:   &mcp.LoggingMessageParams{Level: "info", Data: map[string]any{"k": "v"}},
			wantText: `{"k":"v"}`,
		},
		{
			name:     "a nil payload is empty, not a panic",
			params:   &mcp.LoggingMessageParams{Level: "info"},
			wantText: "",
		},
		{
			name:     "a number payload renders",
			params:   &mcp.LoggingMessageParams{Level: "info", Data: 42},
			wantText: "42",
		},
		{
			name:     "an unrenderable payload is reported, not dropped",
			params:   &mcp.LoggingMessageParams{Level: "info", Data: make(chan int)},
			wantText: "[unrenderable log payload]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := protocol.FromSDKLogParams(tt.params, resultBounds)
			if got.Text != tt.wantText {
				t.Errorf("Text = %q, want %q", got.Text, tt.wantText)
			}
			if got.Level != string(tt.params.Level) {
				t.Errorf("Level = %q, want %q", got.Level, tt.params.Level)
			}
		})
	}
}

// TestLogParamsAreBounded: a log line is a diagnostic from an untrusted peer,
// not a data channel — a server must not be able to make one a memory problem.
func TestLogParamsAreBounded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data any
	}{
		{"a huge string", strings.Repeat("x", 100_000)},
		{"a huge structured payload", map[string]any{"pad": strings.Repeat("y", 100_000)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := protocol.FromSDKLogParams(&mcp.LoggingMessageParams{
				Level:  "info",
				Logger: strings.Repeat("l", 100_000),
				Data:   tt.data,
			}, resultBounds)

			if len(got.Text) > resultBounds.MaxLogBytes {
				t.Errorf("Text is %d bytes, over the %d bound", len(got.Text), resultBounds.MaxLogBytes)
			}
			if len(got.Logger) > resultBounds.MaxLogBytes {
				t.Errorf("Logger is %d bytes, over the %d bound", len(got.Logger), resultBounds.MaxLogBytes)
			}
			if got.Text == "" {
				t.Error("the whole payload was dropped; it should have been truncated")
			}
		})
	}
}

// TestSessionCallsBeforeInitialize: a request on a session whose handshake
// never happened is a typed error, not a nil dereference.
func TestSessionCallsBeforeInitialize(t *testing.T) {
	t.Parallel()

	s := protocol.NewSession(nil, protocol.ConnectConfig{Bounds: resultBounds})

	tests := []struct {
		name string
		call func() error
	}{
		{"CallTool", func() error {
			_, err := s.CallTool(t.Context(), "echo", nil, protocol.CallOptions{})
			return err
		}},
		{"GetPrompt", func() error {
			_, err := s.GetPrompt(t.Context(), "greet", nil)
			return err
		}},
		{"ReadResource", func() error {
			_, err := s.ReadResource(t.Context(), "x://a")
			return err
		}},
		{"Subscribe", func() error { return s.Subscribe(t.Context(), "x://a") }},
		{"SetLogLevel", func() error { return s.SetLogLevel(t.Context(), "info") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.call()
			if err == nil {
				t.Fatal("a request on an uninitialized session succeeded")
			}
			if !strings.Contains(err.Error(), "not initialized") {
				t.Errorf("error = %q, want it to say the session is not initialized", err)
			}
		})
	}
}

// TestCallToolRejectsEmptyIdentifiers: an empty name or URI can never be routed
// to, so it is refused before it reaches the wire.
func TestCallToolRejectsEmptyIdentifiers(t *testing.T) {
	t.Parallel()

	// A session that is "established" enough to get past the nil check is not
	// available without a real connection, so this asserts the ordering that IS
	// observable: the not-initialized check comes first, and neither path
	// panics on an empty identifier.
	s := protocol.NewSession(nil, protocol.ConnectConfig{Bounds: resultBounds})
	if _, err := s.CallTool(t.Context(), "", nil, protocol.CallOptions{}); err == nil {
		t.Error("CallTool with an empty name succeeded")
	}
	if _, err := s.ReadResource(t.Context(), ""); err == nil {
		t.Error("ReadResource with an empty URI succeeded")
	}
}
