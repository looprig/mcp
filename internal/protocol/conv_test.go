package protocol_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
)

// testBounds is a roomy, valid bound set; individual tests tighten one field.
func testBounds() protocol.Bounds {
	return protocol.Bounds{
		MaxSchemaBytes:     4096,
		MaxSchemaDepth:     8,
		MaxTextBytes:       1024,
		MaxStructuredBytes: 1024,
		MaxBinaryItemBytes: 1024,
		MaxBinaryItems:     3,
	}
}

// deepJSON builds a valid nested-object schema of exactly the given bracket
// depth: deepJSON(1) is `{}`, deepJSON(2) is `{"x":{}}`, and so on.
func deepJSON(depth int) json.RawMessage {
	raw := strings.Repeat(`{"x":`, depth-1) + `{}` + strings.Repeat(`}`, depth-1)
	if !json.Valid([]byte(raw)) {
		panic("deepJSON produced invalid JSON: " + raw)
	}
	return json.RawMessage(raw)
}

func TestFromSDKTool(t *testing.T) {
	t.Parallel()
	okSchema := json.RawMessage(`{"type":"object","properties":{"a":{"type":"string"}}}`)
	bigSchema := json.RawMessage(`{"pad":"` + strings.Repeat("x", 5000) + `"}`)
	// json.RawMessage holding invalid JSON fails to marshal.
	badSchema := json.RawMessage(`{"unterminated":`)

	tests := []struct {
		name         string
		tool         *mcp.Tool
		bounds       protocol.Bounds
		wantErr      bool
		wantName     string
		wantIn       string // expected compacted input schema, "" to skip
		wantOutNil   bool
		wantWarnings int
	}{
		{
			name: "happy path",
			tool: &mcp.Tool{
				Name: "search", Title: "Search", Description: "searches",
				InputSchema: okSchema, OutputSchema: okSchema,
			},
			bounds: testBounds(), wantName: "search", wantIn: string(okSchema),
		},
		{
			name:   "no output schema is fine",
			tool:   &mcp.Tool{Name: "t", InputSchema: okSchema},
			bounds: testBounds(), wantName: "t", wantOutNil: true,
		},
		{name: "nil tool", tool: nil, bounds: testBounds(), wantErr: true},
		{
			name:   "empty name",
			tool:   &mcp.Tool{InputSchema: okSchema},
			bounds: testBounds(), wantErr: true,
		},
		{
			name:   "missing input schema",
			tool:   &mcp.Tool{Name: "t"},
			bounds: testBounds(), wantErr: true,
		},
		{
			name:   "input schema is not an object",
			tool:   &mcp.Tool{Name: "t", InputSchema: json.RawMessage(`["nope"]`)},
			bounds: testBounds(), wantErr: true,
		},
		{
			name:   "invalid input schema errors",
			tool:   &mcp.Tool{Name: "t", InputSchema: badSchema},
			bounds: testBounds(), wantErr: true,
		},
		{
			name:   "invalid output schema is dropped and warned",
			tool:   &mcp.Tool{Name: "t", InputSchema: okSchema, OutputSchema: badSchema},
			bounds: testBounds(), wantName: "t", wantOutNil: true, wantWarnings: 1,
		},
		{
			name:   "non-object output schema is dropped and warned",
			tool:   &mcp.Tool{Name: "t", InputSchema: okSchema, OutputSchema: json.RawMessage(`42`)},
			bounds: testBounds(), wantName: "t", wantOutNil: true, wantWarnings: 1,
		},
		{
			name:   "over-byte input schema",
			tool:   &mcp.Tool{Name: "t", InputSchema: bigSchema},
			bounds: testBounds(), wantErr: true,
		},
		{
			// An optional schema over a bound is dropped, not fatal: letting
			// it fail the tool would let a server make an otherwise-usable
			// tool unavailable just by padding an optional field.
			name:   "over-byte output schema is dropped and warned",
			tool:   &mcp.Tool{Name: "t", InputSchema: okSchema, OutputSchema: bigSchema},
			bounds: testBounds(), wantName: "t", wantOutNil: true, wantWarnings: 1,
		},
		{
			name:   "over-depth input schema",
			tool:   &mcp.Tool{Name: "t", InputSchema: deepJSON(12)},
			bounds: testBounds(), wantErr: true,
		},
		{
			name:   "over-depth output schema is dropped and warned",
			tool:   &mcp.Tool{Name: "t", InputSchema: okSchema, OutputSchema: deepJSON(12)},
			bounds: testBounds(), wantName: "t", wantOutNil: true, wantWarnings: 1,
		},
		{
			name:   "at-limit depth passes",
			tool:   &mcp.Tool{Name: "t", InputSchema: deepJSON(8)},
			bounds: testBounds(), wantName: "t",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKTool(tt.tool, tt.bounds)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromSDKTool() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.RawName != tt.wantName {
				t.Errorf("RawName = %q, want %q", got.RawName, tt.wantName)
			}
			if tt.wantIn != "" {
				// Compare compacted, since marshalling normalizes whitespace.
				var want, gotBuf bytes.Buffer
				if err := json.Compact(&want, []byte(tt.wantIn)); err != nil {
					t.Fatalf("bad test schema: %v", err)
				}
				if err := json.Compact(&gotBuf, got.InputSchema); err != nil {
					t.Fatalf("InputSchema is not valid JSON: %v", err)
				}
				if gotBuf.String() != want.String() {
					t.Errorf("InputSchema = %s, want %s", gotBuf.String(), want.String())
				}
			}
			if len(got.InputSchema) == 0 {
				t.Error("InputSchema is empty on a successful conversion")
			}
			if tt.wantOutNil && got.OutputSchema != nil {
				t.Errorf("OutputSchema = %s, want nil", got.OutputSchema)
			}
			if len(got.Warnings) != tt.wantWarnings {
				t.Errorf("Warnings = %v, want %d entries", got.Warnings, tt.wantWarnings)
			}
		})
	}
}

func TestFromSDKToolOverLimitErrorIsTyped(t *testing.T) {
	t.Parallel()
	_, err := protocol.FromSDKTool(
		&mcp.Tool{Name: "t", InputSchema: deepJSON(12)}, testBounds())
	var over *limits.OverLimitError
	if !errors.As(err, &over) {
		t.Fatalf("error = %v, want it to wrap *limits.OverLimitError", err)
	}
	if over.What != limits.WhatJSONDepth {
		t.Errorf("What = %q, want %q", over.What, limits.WhatJSONDepth)
	}
}

func TestFromSDKToolAnnotations(t *testing.T) {
	t.Parallel()
	readOnly := true
	destructive := false
	tool := &mcp.Tool{
		Name:        "t",
		InputSchema: json.RawMessage(`{}`),
		Annotations: &mcp.ToolAnnotations{
			Title:           "Pretty",
			ReadOnlyHint:    readOnly,
			DestructiveHint: &destructive,
		},
	}
	got, err := protocol.FromSDKTool(tool, testBounds())
	if err != nil {
		t.Fatalf("FromSDKTool() error = %v", err)
	}
	if got.Annotations == nil {
		t.Fatal("Annotations = nil, want the converted hints")
	}
	if !got.Annotations.ReadOnlyHint || got.Annotations.Title != "Pretty" {
		t.Errorf("Annotations = %+v, want ReadOnlyHint and Title carried", got.Annotations)
	}
	if got.Annotations.DestructiveHint == nil || *got.Annotations.DestructiveHint {
		t.Errorf("DestructiveHint = %v, want a pointer to false", got.Annotations.DestructiveHint)
	}
	// Defensive copy: mutating the SDK value must not reach the neutral one.
	tool.Annotations.Title = "mutated"
	*tool.Annotations.DestructiveHint = true
	if got.Annotations.Title != "Pretty" || *got.Annotations.DestructiveHint {
		t.Error("Annotations aliases SDK memory")
	}
	// A tool with no annotations converts to a nil Annotations.
	plain, err := protocol.FromSDKTool(&mcp.Tool{Name: "t", InputSchema: json.RawMessage(`{}`)}, testBounds())
	if err != nil {
		t.Fatalf("FromSDKTool() error = %v", err)
	}
	if plain.Annotations != nil {
		t.Errorf("Annotations = %+v, want nil when the server sent none", plain.Annotations)
	}
}

func TestFromSDKToolDefensiveCopy(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"type":"object","k":"original"}`)
	tool := &mcp.Tool{Name: "t", InputSchema: json.RawMessage(raw)}
	got, err := protocol.FromSDKTool(tool, testBounds())
	if err != nil {
		t.Fatalf("FromSDKTool() error = %v", err)
	}
	before := append([]byte(nil), got.InputSchema...)
	// Mutate the SDK-owned backing array underneath the converted value.
	copy(raw, []byte(`{"type":"object","k":"MUTATED!"`))
	if !bytes.Equal(before, got.InputSchema) {
		t.Errorf("InputSchema changed to %s after mutating SDK memory; want %s",
			got.InputSchema, before)
	}
}

// A dropped output schema is only visible through its warning, so the warning
// must say why it went.
func TestFromSDKToolDropWarningNamesReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		schema   json.RawMessage
		wantWord string
	}{
		{name: "over bytes", schema: json.RawMessage(`{"pad":"` + strings.Repeat("x", 5000) + `"}`),
			wantWord: protocol.WhatSchemaBytes},
		{name: "over depth", schema: deepJSON(12), wantWord: limits.WhatJSONDepth},
		{name: "malformed", schema: json.RawMessage(`{bad`), wantWord: "marshalable"},
		{name: "not an object", schema: json.RawMessage(`42`), wantWord: "object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKTool(&mcp.Tool{
				Name: "t", InputSchema: json.RawMessage(`{"type":"object"}`),
				OutputSchema: tt.schema,
			}, testBounds())
			if err != nil {
				t.Fatalf("FromSDKTool() error = %v, want the defect tolerated", err)
			}
			if got.OutputSchema != nil {
				t.Errorf("OutputSchema = %s, want it dropped", got.OutputSchema)
			}
			if len(got.Warnings) != 1 {
				t.Fatalf("Warnings = %v, want exactly one", got.Warnings)
			}
			if !strings.Contains(got.Warnings[0], tt.wantWord) {
				t.Errorf("warning %q does not name the reason %q", got.Warnings[0], tt.wantWord)
			}
			// The tool itself stays usable: its input schema survives.
			if len(got.InputSchema) == 0 {
				t.Error("InputSchema was lost along with the output schema")
			}
		})
	}
}

func TestFromSDKToolWarningsBounded(t *testing.T) {
	t.Parallel()
	// Only one warning is reachable today; the cap must still hold.
	got, err := protocol.FromSDKTool(&mcp.Tool{
		Name: "t", InputSchema: json.RawMessage(`{}`),
		OutputSchema: json.RawMessage(`{bad`),
	}, testBounds())
	if err != nil {
		t.Fatalf("FromSDKTool() error = %v", err)
	}
	if len(got.Warnings) > protocol.MaxWarnings {
		t.Errorf("Warnings = %d entries, want at most %d", len(got.Warnings), protocol.MaxWarnings)
	}
}

func TestFromSDKPrompt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		prompt   *mcp.Prompt
		wantErr  bool
		wantName string
		wantArgs int
	}{
		{
			name: "happy path",
			prompt: &mcp.Prompt{
				Name: "greet", Title: "Greet", Description: "says hi",
				Arguments: []*mcp.PromptArgument{
					{Name: "who", Description: "the target", Required: true},
					{Name: "tone"},
				},
			},
			wantName: "greet", wantArgs: 2,
		},
		{name: "no arguments", prompt: &mcp.Prompt{Name: "p"}, wantName: "p"},
		{name: "nil prompt", prompt: nil, wantErr: true},
		{name: "empty name", prompt: &mcp.Prompt{}, wantErr: true},
		{
			name:    "nil argument entry",
			prompt:  &mcp.Prompt{Name: "p", Arguments: []*mcp.PromptArgument{nil}},
			wantErr: true,
		},
		{
			name:    "argument with empty name",
			prompt:  &mcp.Prompt{Name: "p", Arguments: []*mcp.PromptArgument{{}}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKPrompt(tt.prompt, testBounds())
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromSDKPrompt() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.RawName != tt.wantName {
				t.Errorf("RawName = %q, want %q", got.RawName, tt.wantName)
			}
			if len(got.Arguments) != tt.wantArgs {
				t.Errorf("Arguments = %d, want %d", len(got.Arguments), tt.wantArgs)
			}
		})
	}
}

func TestFromSDKPromptDefensiveCopy(t *testing.T) {
	t.Parallel()
	arg := &mcp.PromptArgument{Name: "who", Required: true}
	p := &mcp.Prompt{Name: "greet", Arguments: []*mcp.PromptArgument{arg}}
	got, err := protocol.FromSDKPrompt(p, testBounds())
	if err != nil {
		t.Fatalf("FromSDKPrompt() error = %v", err)
	}
	arg.Name = "mutated"
	arg.Required = false
	p.Arguments[0] = nil
	if got.Arguments[0].Name != "who" || !got.Arguments[0].Required {
		t.Errorf("Arguments = %+v, want a copy unaffected by SDK mutation", got.Arguments[0])
	}
}

func TestFromSDKResource(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		res     *mcp.Resource
		wantErr bool
		wantURI string
	}{
		{
			name: "happy path",
			res: &mcp.Resource{
				URI: "file:///a.txt", Name: "a", Title: "A",
				Description: "a file", MIMEType: "text/plain",
			},
			wantURI: "file:///a.txt",
		},
		{name: "nil resource", res: nil, wantErr: true},
		{name: "empty uri", res: &mcp.Resource{Name: "a"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKResource(tt.res, testBounds())
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromSDKResource() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got.URI != tt.wantURI {
				t.Errorf("URI = %q, want %q", got.URI, tt.wantURI)
			}
		})
	}
}

func TestFromSDKResourceTemplate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rt      *mcp.ResourceTemplate
		wantErr bool
		wantTpl string
	}{
		{
			name: "happy path",
			rt: &mcp.ResourceTemplate{
				URITemplate: "file:///{path}", Name: "files", Title: "Files",
				Description: "the tree", MIMEType: "text/plain",
			},
			wantTpl: "file:///{path}",
		},
		{name: "nil template", rt: nil, wantErr: true},
		{name: "empty uri template", rt: &mcp.ResourceTemplate{Name: "x"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKResourceTemplate(tt.rt, testBounds())
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromSDKResourceTemplate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got.URITemplate != tt.wantTpl {
				t.Errorf("URITemplate = %q, want %q", got.URITemplate, tt.wantTpl)
			}
		})
	}
}

func TestFromSDKContent(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 2000)

	tests := []struct {
		name    string
		content mcp.Content
		bounds  protocol.Bounds
		wantErr bool
		check   func(t *testing.T, got protocol.Content)
	}{
		{
			name: "text", content: &mcp.TextContent{Text: "hello"}, bounds: testBounds(),
			check: func(t *testing.T, got protocol.Content) {
				tc, ok := got.(protocol.TextContent)
				if !ok {
					t.Fatalf("got %T, want protocol.TextContent", got)
				}
				if tc.Text != "hello" || tc.Truncated {
					t.Errorf("got %+v, want untruncated \"hello\"", tc)
				}
			},
		},
		{
			name: "text truncated", content: &mcp.TextContent{Text: long},
			bounds: protocol.Bounds{MaxTextBytes: 100},
			check: func(t *testing.T, got protocol.Content) {
				tc, ok := got.(protocol.TextContent)
				if !ok {
					t.Fatalf("got %T, want protocol.TextContent", got)
				}
				if !tc.Truncated {
					t.Error("Truncated = false, want true")
				}
				if len(tc.Text) > 100 {
					t.Errorf("Text is %d bytes, want at most 100", len(tc.Text))
				}
			},
		},
		{
			name: "image", content: &mcp.ImageContent{Data: []byte{1, 2, 3}, MIMEType: "image/png"},
			bounds: testBounds(),
			check: func(t *testing.T, got protocol.Content) {
				ic, ok := got.(protocol.ImageContent)
				if !ok {
					t.Fatalf("got %T, want protocol.ImageContent", got)
				}
				if !bytes.Equal(ic.Data, []byte{1, 2, 3}) || ic.MIMEType != "image/png" {
					t.Errorf("got %+v, want the 3 data bytes and image/png", ic)
				}
			},
		},
		{
			name:   "oversized image becomes unsupported",
			bounds: protocol.Bounds{MaxBinaryItemBytes: 2, MaxBinaryItems: 4},
			content: &mcp.ImageContent{
				Data: bytes.Repeat([]byte{7}, 500), MIMEType: "image/png",
			},
			check: func(t *testing.T, got protocol.Content) {
				uc, ok := got.(protocol.UnsupportedContent)
				if !ok {
					t.Fatalf("got %T, want protocol.UnsupportedContent", got)
				}
				if uc.Kind != protocol.KindImage || uc.Bytes != 500 {
					t.Errorf("got %+v, want kind image and Bytes 500", uc)
				}
			},
		},
		{
			name: "audio", content: &mcp.AudioContent{Data: []byte{9}, MIMEType: "audio/wav"},
			bounds: testBounds(),
			check: func(t *testing.T, got protocol.Content) {
				ac, ok := got.(protocol.AudioContent)
				if !ok {
					t.Fatalf("got %T, want protocol.AudioContent", got)
				}
				if !bytes.Equal(ac.Data, []byte{9}) {
					t.Errorf("Data = %v, want [9]", ac.Data)
				}
			},
		},
		{
			name:   "oversized audio becomes unsupported",
			bounds: protocol.Bounds{MaxBinaryItemBytes: 1, MaxBinaryItems: 4},
			content: &mcp.AudioContent{
				Data: bytes.Repeat([]byte{7}, 42), MIMEType: "audio/wav",
			},
			check: func(t *testing.T, got protocol.Content) {
				uc, ok := got.(protocol.UnsupportedContent)
				if !ok {
					t.Fatalf("got %T, want protocol.UnsupportedContent", got)
				}
				if uc.Kind != protocol.KindAudio || uc.Bytes != 42 {
					t.Errorf("got %+v, want kind audio and Bytes 42", uc)
				}
			},
		},
		{
			name: "embedded text resource",
			content: &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
				URI: "file:///a", MIMEType: "text/plain", Text: "body",
			}},
			bounds: testBounds(),
			check: func(t *testing.T, got protocol.Content) {
				er, ok := got.(protocol.EmbeddedResourceContent)
				if !ok {
					t.Fatalf("got %T, want protocol.EmbeddedResourceContent", got)
				}
				if er.URI != "file:///a" || er.Text != "body" || er.Truncated {
					t.Errorf("got %+v, want the URI and text carried untruncated", er)
				}
			},
		},
		{
			name: "embedded text resource truncated",
			content: &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
				URI: "file:///a", Text: long,
			}},
			bounds: protocol.Bounds{MaxTextBytes: 50, MaxBinaryItemBytes: 100, MaxBinaryItems: 4},
			check: func(t *testing.T, got protocol.Content) {
				er, ok := got.(protocol.EmbeddedResourceContent)
				if !ok {
					t.Fatalf("got %T, want protocol.EmbeddedResourceContent", got)
				}
				if !er.Truncated || len(er.Text) > 50 {
					t.Errorf("got %+v, want truncated text within 50 bytes", er)
				}
			},
		},
		{
			name: "embedded blob resource",
			content: &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
				URI: "file:///b.bin", Blob: []byte{1, 2},
			}},
			bounds: testBounds(),
			check: func(t *testing.T, got protocol.Content) {
				er, ok := got.(protocol.EmbeddedResourceContent)
				if !ok {
					t.Fatalf("got %T, want protocol.EmbeddedResourceContent", got)
				}
				if !bytes.Equal(er.Data, []byte{1, 2}) {
					t.Errorf("Data = %v, want [1 2]", er.Data)
				}
			},
		},
		{
			name: "oversized embedded blob becomes unsupported",
			content: &mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
				URI: "file:///b.bin", Blob: bytes.Repeat([]byte{3}, 9),
			}},
			bounds: protocol.Bounds{MaxBinaryItemBytes: 4, MaxBinaryItems: 4, MaxTextBytes: 10},
			check: func(t *testing.T, got protocol.Content) {
				uc, ok := got.(protocol.UnsupportedContent)
				if !ok {
					t.Fatalf("got %T, want protocol.UnsupportedContent", got)
				}
				if uc.Kind != protocol.KindResource || uc.Bytes != 9 {
					t.Errorf("got %+v, want kind resource and Bytes 9", uc)
				}
			},
		},
		{
			name:    "embedded resource with nil contents",
			content: &mcp.EmbeddedResource{},
			bounds:  testBounds(), wantErr: true,
		},
		{
			name:    "resource link is unsupported, not dropped",
			content: &mcp.ResourceLink{URI: "file:///x", Name: "x"},
			bounds:  testBounds(),
			check: func(t *testing.T, got protocol.Content) {
				uc, ok := got.(protocol.UnsupportedContent)
				if !ok {
					t.Fatalf("got %T, want protocol.UnsupportedContent", got)
				}
				if uc.Kind != protocol.KindResourceLink {
					t.Errorf("Kind = %q, want %q", uc.Kind, protocol.KindResourceLink)
				}
				// Sized from the fields (len "file:///x" + len "x"), not by
				// marshalling the item we are refusing.
				if uc.Bytes != len("file:///x")+len("x") {
					t.Errorf("Bytes = %d, want the summed field lengths %d",
						uc.Bytes, len("file:///x")+len("x"))
				}
			},
		},
		{
			name:    "sampling-only tool_use content is unsupported",
			content: &mcp.ToolUseContent{ID: "1", Name: "t"},
			bounds:  testBounds(),
			check: func(t *testing.T, got protocol.Content) {
				uc, ok := got.(protocol.UnsupportedContent)
				if !ok {
					t.Fatalf("got %T, want protocol.UnsupportedContent", got)
				}
				if uc.Kind != protocol.KindToolUse {
					t.Errorf("Kind = %q, want %q", uc.Kind, protocol.KindToolUse)
				}
			},
		},
		{name: "nil content", content: nil, bounds: testBounds(), wantErr: true},
		// A typed nil must be an error for every kind, including the kinds
		// that convert to UnsupportedContent — measuring one would otherwise
		// dereference the nil.
		{
			name: "typed nil text", content: (*mcp.TextContent)(nil),
			bounds: testBounds(), wantErr: true,
		},
		{
			name: "typed nil image", content: (*mcp.ImageContent)(nil),
			bounds: testBounds(), wantErr: true,
		},
		{
			name: "typed nil audio", content: (*mcp.AudioContent)(nil),
			bounds: testBounds(), wantErr: true,
		},
		{
			name: "typed nil embedded resource", content: (*mcp.EmbeddedResource)(nil),
			bounds: testBounds(), wantErr: true,
		},
		{
			name: "typed nil resource link", content: (*mcp.ResourceLink)(nil),
			bounds: testBounds(), wantErr: true,
		},
		{
			name: "typed nil tool use", content: (*mcp.ToolUseContent)(nil),
			bounds: testBounds(), wantErr: true,
		},
		{
			name: "typed nil tool result", content: (*mcp.ToolResultContent)(nil),
			bounds: testBounds(), wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKContent(tt.content, tt.bounds)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromSDKContent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			tt.check(t, got)
		})
	}
}

func TestFromSDKContentDefensiveCopy(t *testing.T) {
	t.Parallel()
	data := []byte{1, 2, 3}
	got, err := protocol.FromSDKContent(
		&mcp.ImageContent{Data: data, MIMEType: "image/png"}, testBounds())
	if err != nil {
		t.Fatalf("FromSDKContent() error = %v", err)
	}
	ic, ok := got.(protocol.ImageContent)
	if !ok {
		t.Fatalf("got %T, want protocol.ImageContent", got)
	}
	data[0] = 99
	if !bytes.Equal(ic.Data, []byte{1, 2, 3}) {
		t.Errorf("Data = %v after mutating SDK memory, want [1 2 3]", ic.Data)
	}
}

func TestFromSDKContents(t *testing.T) {
	t.Parallel()
	img := func() mcp.Content { return &mcp.ImageContent{Data: []byte{1}, MIMEType: "image/png"} }
	txt := func() mcp.Content { return &mcp.TextContent{Text: "t"} }

	t.Run("empty and nil slices", func(t *testing.T) {
		t.Parallel()
		for _, in := range [][]mcp.Content{nil, {}} {
			got, err := protocol.FromSDKContents(in, testBounds())
			if err != nil {
				t.Fatalf("FromSDKContents(%v) error = %v", in, err)
			}
			if len(got) != 0 {
				t.Errorf("got %v, want empty", got)
			}
		}
	})

	t.Run("binary item overflow", func(t *testing.T) {
		t.Parallel()
		// Bound of 2 binary items: the 3rd image is Unsupported, and the
		// interleaved text is unaffected by the binary budget.
		b := testBounds()
		b.MaxBinaryItems = 2
		in := []mcp.Content{img(), txt(), img(), img(), txt()}
		got, err := protocol.FromSDKContents(in, b)
		if err != nil {
			t.Fatalf("FromSDKContents() error = %v", err)
		}
		if len(got) != len(in) {
			t.Fatalf("got %d items, want %d (nothing is dropped)", len(got), len(in))
		}
		if _, ok := got[0].(protocol.ImageContent); !ok {
			t.Errorf("item 0 = %T, want ImageContent (within budget)", got[0])
		}
		if _, ok := got[2].(protocol.ImageContent); !ok {
			t.Errorf("item 2 = %T, want ImageContent (within budget)", got[2])
		}
		uc, ok := got[3].(protocol.UnsupportedContent)
		if !ok {
			t.Fatalf("item 3 = %T, want UnsupportedContent (over budget)", got[3])
		}
		if uc.Kind != protocol.KindImage || uc.Bytes != 1 {
			t.Errorf("item 3 = %+v, want kind image with Bytes 1", uc)
		}
		if _, ok := got[1].(protocol.TextContent); !ok {
			t.Errorf("item 1 = %T, want TextContent", got[1])
		}
		if _, ok := got[4].(protocol.TextContent); !ok {
			t.Errorf("item 4 = %T, want TextContent", got[4])
		}
	})

	t.Run("oversized item does not consume the item budget", func(t *testing.T) {
		t.Parallel()
		// The oversized image is rejected on bytes; it must not also spend a
		// slot, or one bad item would evict a good one.
		b := protocol.Bounds{MaxBinaryItemBytes: 4, MaxBinaryItems: 1, MaxTextBytes: 10}
		in := []mcp.Content{
			&mcp.ImageContent{Data: bytes.Repeat([]byte{1}, 99), MIMEType: "image/png"},
			img(),
		}
		got, err := protocol.FromSDKContents(in, b)
		if err != nil {
			t.Fatalf("FromSDKContents() error = %v", err)
		}
		if _, ok := got[0].(protocol.UnsupportedContent); !ok {
			t.Errorf("item 0 = %T, want UnsupportedContent (over bytes)", got[0])
		}
		if _, ok := got[1].(protocol.ImageContent); !ok {
			t.Errorf("item 1 = %T, want ImageContent (still within the item budget)", got[1])
		}
	})

	t.Run("error propagates", func(t *testing.T) {
		t.Parallel()
		_, err := protocol.FromSDKContents([]mcp.Content{txt(), nil}, testBounds())
		if err == nil {
			t.Fatal("FromSDKContents() error = nil, want an error for the nil element")
		}
	})
}

func TestFromSDKServerIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		impl *mcp.Implementation
		want protocol.ServerIdentity
	}{
		{
			name: "happy path",
			impl: &mcp.Implementation{Name: "srv", Version: "1.2.3", Title: "Server"},
			want: protocol.ServerIdentity{Name: "srv", Version: "1.2.3", Title: "Server"},
		},
		{name: "nil is the zero identity", impl: nil, want: protocol.ServerIdentity{}},
		{name: "empty", impl: &mcp.Implementation{}, want: protocol.ServerIdentity{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := protocol.FromSDKServerIdentity(tt.impl); got != tt.want {
				t.Errorf("FromSDKServerIdentity() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
