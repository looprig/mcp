package protocol_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/protocol"
)

func objectSchema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }

func TestFromSDKToolPage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		res          *mcp.ListToolsResult
		wantTools    []string
		wantCursor   string
		wantWarnings int
		wantErr      bool
	}{
		{
			name: "a well-formed page",
			res: &mcp.ListToolsResult{
				Tools: []*mcp.Tool{
					{Name: "echo", InputSchema: objectSchema()},
					{Name: "slow", InputSchema: objectSchema()},
				},
				NextCursor: "p1",
			},
			wantTools:  []string{"echo", "slow"},
			wantCursor: "p1",
		},
		{
			name:      "an empty page is valid",
			res:       &mcp.ListToolsResult{},
			wantTools: nil,
		},
		{
			name: "a defective tool is dropped, not fatal",
			res: &mcp.ListToolsResult{Tools: []*mcp.Tool{
				{Name: "good", InputSchema: objectSchema()},
				{Name: "no_schema"},
			}},
			wantTools:    []string{"good"},
			wantWarnings: 1,
		},
		{
			name: "a nil entry is dropped, not fatal",
			res: &mcp.ListToolsResult{Tools: []*mcp.Tool{
				nil,
				{Name: "good", InputSchema: objectSchema()},
			}},
			wantTools:    []string{"good"},
			wantWarnings: 1,
		},
		{
			name: "every tool defective yields an empty page, not an error",
			res: &mcp.ListToolsResult{Tools: []*mcp.Tool{
				{Name: "a"}, {Name: "b"},
			}},
			wantTools:    nil,
			wantWarnings: 2,
		},
		{
			name:    "a nil result is refused",
			res:     nil,
			wantErr: true,
		},
		{
			name: "an over-long cursor is refused",
			res: &mcp.ListToolsResult{
				NextCursor: strings.Repeat("c", protocol.MaxCursorBytes+1),
			},
			wantErr: true,
		},
		{
			name: "a cursor at exactly the bound is accepted",
			res: &mcp.ListToolsResult{
				NextCursor: strings.Repeat("c", protocol.MaxCursorBytes),
			},
			wantCursor: strings.Repeat("c", protocol.MaxCursorBytes),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKToolPage(tt.res, pageBounds)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromSDKToolPage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			var names []string
			for _, tool := range got.Tools {
				names = append(names, tool.RawName)
			}
			if !equalStrings(names, tt.wantTools) {
				t.Errorf("tools = %v, want %v", names, tt.wantTools)
			}
			if got.NextCursor != tt.wantCursor {
				t.Errorf("NextCursor = %q, want %q", got.NextCursor, tt.wantCursor)
			}
			if len(got.Warnings) != tt.wantWarnings {
				t.Errorf("Warnings = %v, want %d of them", got.Warnings, tt.wantWarnings)
			}
		})
	}
}

// TestFromSDKToolPageDoesNotLeakCursorBytes: a cursor is opaque, unbounded
// server data with no diagnostic value, so it must never be rendered into an
// error a host will log.
func TestFromSDKToolPageDoesNotLeakCursorBytes(t *testing.T) {
	t.Parallel()

	cursor := strings.Repeat("SECRET", protocol.MaxCursorBytes)
	_, err := protocol.FromSDKToolPage(&mcp.ListToolsResult{NextCursor: cursor}, pageBounds)
	if err == nil {
		t.Fatal("an over-long cursor was accepted")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Errorf("the error rendered the cursor: %q", err)
	}
	if len(err.Error()) > 200 {
		t.Errorf("the error is %d bytes: a bounded rejection must have a bounded message", len(err.Error()))
	}
}

func TestFromSDKPromptPage(t *testing.T) {
	t.Parallel()

	got, err := protocol.FromSDKPromptPage(&mcp.ListPromptsResult{
		Prompts: []*mcp.Prompt{
			{Name: "greet", Arguments: []*mcp.PromptArgument{{Name: "who", Required: true}}},
			{Name: ""}, // unusable: dropped
		},
		NextCursor: "p1",
	}, pageBounds)
	if err != nil {
		t.Fatalf("FromSDKPromptPage() error = %v", err)
	}
	if len(got.Prompts) != 1 || got.Prompts[0].RawName != "greet" {
		t.Fatalf("Prompts = %+v, want just greet", got.Prompts)
	}
	if len(got.Prompts[0].Arguments) != 1 || !got.Prompts[0].Arguments[0].Required {
		t.Errorf("Arguments = %+v, want the required 'who' argument preserved", got.Prompts[0].Arguments)
	}
	if got.NextCursor != "p1" {
		t.Errorf("NextCursor = %q, want p1", got.NextCursor)
	}
	if len(got.Warnings) != 1 {
		t.Errorf("Warnings = %v, want the dropped prompt reported", got.Warnings)
	}

	if _, err := protocol.FromSDKPromptPage(nil, pageBounds); err == nil {
		t.Error("a nil prompts result was accepted")
	}
}

func TestFromSDKResourcePage(t *testing.T) {
	t.Parallel()

	got, err := protocol.FromSDKResourcePage(&mcp.ListResourcesResult{
		Resources: []*mcp.Resource{
			{URI: "x://a", Name: "a", MIMEType: "text/plain"},
			{Name: "no-uri"}, // unusable: dropped
		},
	}, pageBounds)
	if err != nil {
		t.Fatalf("FromSDKResourcePage() error = %v", err)
	}
	if len(got.Resources) != 1 || got.Resources[0].URI != "x://a" {
		t.Fatalf("Resources = %+v, want just x://a", got.Resources)
	}
	if len(got.Warnings) != 1 {
		t.Errorf("Warnings = %v, want the dropped resource reported", got.Warnings)
	}

	if _, err := protocol.FromSDKResourcePage(nil, pageBounds); err == nil {
		t.Error("a nil resources result was accepted")
	}
}

func TestFromSDKResourceTemplatePage(t *testing.T) {
	t.Parallel()

	got, err := protocol.FromSDKResourceTemplatePage(&mcp.ListResourceTemplatesResult{
		ResourceTemplates: []*mcp.ResourceTemplate{
			{URITemplate: "x://{a}", Name: "a"},
			{Name: "no-template"}, // unusable: dropped
		},
	}, pageBounds)
	if err != nil {
		t.Fatalf("FromSDKResourceTemplatePage() error = %v", err)
	}
	if len(got.Templates) != 1 || got.Templates[0].URITemplate != "x://{a}" {
		t.Fatalf("Templates = %+v, want just x://{a}", got.Templates)
	}
	if len(got.Warnings) != 1 {
		t.Errorf("Warnings = %v, want the dropped template reported", got.Warnings)
	}

	if _, err := protocol.FromSDKResourceTemplatePage(nil, pageBounds); err == nil {
		t.Error("a nil templates result was accepted")
	}
}

// TestSessionListBeforeInitialize checks the one caller bug this layer has to
// survive: a request on a session whose handshake never happened must be a
// typed error, not a nil dereference on whatever goroutine made the call.
func TestSessionListBeforeInitialize(t *testing.T) {
	t.Parallel()

	s := protocol.NewSession(nil, protocol.ConnectConfig{Bounds: pageBounds})

	tests := []struct {
		name string
		call func() error
	}{
		{"tools", func() error { _, err := s.ListTools(t.Context(), ""); return err }},
		{"prompts", func() error { _, err := s.ListPrompts(t.Context(), ""); return err }},
		{"resources", func() error { _, err := s.ListResources(t.Context(), ""); return err }},
		{"templates", func() error { _, err := s.ListResourceTemplates(t.Context(), ""); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.call()
			if err == nil {
				t.Fatal("a list on an uninitialized session succeeded")
			}
			if !strings.Contains(err.Error(), "not initialized") {
				t.Errorf("error = %q, want it to say the session is not initialized", err)
			}
		})
	}
}

// TestFromSDKToolPageDetachesFromSDKMemory: a converted page must not alias the
// SDK's values, or a server's later write would reach into a published catalog.
func TestFromSDKToolPageDetachesFromSDKMemory(t *testing.T) {
	t.Parallel()

	schema := objectSchema()
	res := &mcp.ListToolsResult{Tools: []*mcp.Tool{{Name: "echo", InputSchema: schema}}}

	got, err := protocol.FromSDKToolPage(res, pageBounds)
	if err != nil {
		t.Fatalf("FromSDKToolPage() error = %v", err)
	}
	// Mutate everything the SDK still owns.
	res.Tools[0].Name = "hijacked"
	res.Tools[0].InputSchema = json.RawMessage(`{"type":"array"}`)
	res.Tools = nil

	if got.Tools[0].RawName != "echo" {
		t.Errorf("RawName = %q: the page aliases the SDK's tool", got.Tools[0].RawName)
	}
	if !json.Valid(got.Tools[0].InputSchema) {
		t.Error("the retained schema is not valid JSON")
	}
}

func TestCheckCursorErrorIsIdentifiable(t *testing.T) {
	t.Parallel()

	_, err := protocol.FromSDKToolPage(&mcp.ListToolsResult{
		NextCursor: strings.Repeat("c", protocol.MaxCursorBytes+1),
	}, pageBounds)
	if err == nil {
		t.Fatal("an over-long cursor was accepted")
	}
	// The caller classifies on the message rather than a sentinel today; assert
	// it is at least stable and descriptive.
	if !strings.Contains(err.Error(), "cursor") {
		t.Errorf("error = %q, want it to name the cursor", err)
	}
	var over *json.SyntaxError
	if errors.As(err, &over) {
		t.Error("a cursor bound was reported as a JSON syntax error")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
