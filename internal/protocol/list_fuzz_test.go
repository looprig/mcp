package protocol_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/protocol"
)

// pageBounds are tight on purpose: a bound that no fuzz input can reach is a
// bound the fuzzer never tests.
var pageBounds = protocol.Bounds{
	MaxSchemaBytes:     256,
	MaxSchemaDepth:     5,
	MaxTextBytes:       256,
	MaxStructuredBytes: 256,
	MaxBinaryItemBytes: 256,
	MaxBinaryItems:     4,
}

// pageSeeds are the shapes a hostile or broken server produces. They run on
// every `go test`, not only under the fuzzer, so each one is a standing
// regression case.
var pageSeeds = []string{
	`{}`,
	`{"tools":[]}`,
	`{"tools":null}`,
	`{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}`,
	// No name: unroutable, must be dropped rather than exposed.
	`{"tools":[{"inputSchema":{"type":"object"}}]}`,
	// No input schema: arguments would be unconstrained, must be dropped.
	`{"tools":[{"name":"echo"}]}`,
	// A null entry in the list.
	`{"tools":[null]}`,
	`{"tools":[null,{"name":"echo","inputSchema":{"type":"object"}}]}`,
	// A schema that is not an object.
	`{"tools":[{"name":"echo","inputSchema":[]}]}`,
	`{"tools":[{"name":"echo","inputSchema":"nope"}]}`,
	// Cursors: empty, ordinary, and over the bound.
	`{"tools":[],"nextCursor":""}`,
	`{"tools":[],"nextCursor":"p1"}`,
	`{"tools":[],"nextCursor":"` + strings.Repeat("c", protocol.MaxCursorBytes+1) + `"}`,
	// A cursor at exactly the bound: accepted.
	`{"tools":[],"nextCursor":"` + strings.Repeat("c", protocol.MaxCursorBytes) + `"}`,
	// Over the schema bounds.
	`{"tools":[{"name":"e","inputSchema":{"pad":"` + strings.Repeat("x", 600) + `"}}]}`,
	`{"tools":[{"name":"e","inputSchema":` + strings.Repeat(`{"x":`, 20) + `{}` + strings.Repeat(`}`, 20) + `}]}`,
	// Malformed and hostile JSON.
	``,
	`null`,
	`[]`,
	`{"tools":`,
	"{\"tools\":[{\"name\":\"\x00\x1b[31m\",\"inputSchema\":{\"type\":\"object\"}}]}",
	"{\"tools\":[{\"name\":\"\xff\xfe\",\"inputSchema\":{\"type\":\"object\"}}]}",
	// Unknown fields: ignored, per the design's compatibility rule.
	`{"tools":[{"name":"e","inputSchema":{"type":"object"},"whatIsThis":42}],"alsoNew":true}`,
}

// FuzzToolPageDecode drives arbitrary bytes through the whole tools/list decode
// path a server controls: the SDK's JSON unmarshal, then this module's page
// conversion.
//
// The properties asserted are the ones the rest of the module relies on, and
// each one is a real invariant rather than a restatement of the code: the
// conversion never panics; a page it accepts carries only tools whose schemas
// are within bounds and whose names are usable; the cursor is bounded; nothing
// is dropped silently.
func FuzzToolPageDecode(f *testing.F) {
	for _, s := range pageSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var res mcp.ListToolsResult
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			// The SDK refused it before we saw it: nothing for this module to
			// promise.
			return
		}

		page, err := protocol.FromSDKToolPage(&res, pageBounds)
		if err != nil {
			// A rejected page must still be a bounded rejection, not a partial
			// one handed back alongside an error.
			if len(page.Tools) != 0 || page.NextCursor != "" {
				t.Errorf("rejected page still carried %d tools and cursor %q",
					len(page.Tools), page.NextCursor)
			}
			return
		}

		if len(page.NextCursor) > protocol.MaxCursorBytes {
			t.Errorf("accepted cursor is %d bytes, over the %d bound",
				len(page.NextCursor), protocol.MaxCursorBytes)
		}
		if len(page.Warnings) > protocol.MaxWarnings {
			t.Errorf("Warnings = %d entries, want at most %d", len(page.Warnings), protocol.MaxWarnings)
		}
		// Every tool the server sent is either retained or warned about: a
		// caller must always be able to tell what happened to a missing tool.
		if dropped := len(res.Tools) - len(page.Tools); dropped > 0 && len(page.Warnings) == 0 {
			t.Errorf("%d tool(s) were dropped without a warning", dropped)
		}
		for _, tool := range page.Tools {
			if tool.RawName == "" {
				t.Error("accepted a tool with no name: it could never be routed to")
			}
			if len(tool.InputSchema) == 0 {
				t.Errorf("tool %q accepted with no input schema: its arguments are unconstrained", tool.RawName)
			}
			assertSchemaWithinBounds(t, "InputSchema", tool.InputSchema,
				pageBounds.MaxSchemaBytes, pageBounds.MaxSchemaDepth)
			if tool.OutputSchema != nil {
				assertSchemaWithinBounds(t, "OutputSchema", tool.OutputSchema,
					pageBounds.MaxSchemaBytes, pageBounds.MaxSchemaDepth)
			}
		}
	})
}

// FuzzPromptPageDecode drives the prompts/list decode path.
func FuzzPromptPageDecode(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"prompts":[]}`,
		`{"prompts":null}`,
		`{"prompts":[{"name":"greet"}]}`,
		`{"prompts":[{"name":"greet","arguments":[{"name":"who","required":true}]}]}`,
		// A prompt with no name, and an argument with no name: both unusable.
		`{"prompts":[{}]}`,
		`{"prompts":[{"name":"greet","arguments":[{}]}]}`,
		`{"prompts":[null]}`,
		`{"prompts":[],"nextCursor":"` + strings.Repeat("c", protocol.MaxCursorBytes+1) + `"}`,
		`{"prompts":[{"name":"g","arguments":null}]}`,
		``,
		`null`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var res mcp.ListPromptsResult
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			return
		}
		page, err := protocol.FromSDKPromptPage(&res, pageBounds)
		if err != nil {
			return
		}
		if len(page.NextCursor) > protocol.MaxCursorBytes {
			t.Errorf("accepted cursor is %d bytes, over the %d bound",
				len(page.NextCursor), protocol.MaxCursorBytes)
		}
		if dropped := len(res.Prompts) - len(page.Prompts); dropped > 0 && len(page.Warnings) == 0 {
			t.Errorf("%d prompt(s) were dropped without a warning", dropped)
		}
		for _, p := range page.Prompts {
			if p.RawName == "" {
				t.Error("accepted a prompt with no name")
			}
			for _, a := range p.Arguments {
				if a.Name == "" {
					t.Errorf("prompt %q accepted with an unnamed argument", p.RawName)
				}
			}
		}
	})
}

// FuzzResourcePageDecode drives the resources/list decode path.
func FuzzResourcePageDecode(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"resources":[]}`,
		`{"resources":[{"uri":"x://a","name":"a"}]}`,
		// No URI: nothing to read, must be dropped.
		`{"resources":[{"name":"a"}]}`,
		`{"resources":[null]}`,
		`{"resources":[],"nextCursor":"` + strings.Repeat("c", protocol.MaxCursorBytes+1) + `"}`,
		``,
		`null`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var res mcp.ListResourcesResult
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			return
		}
		page, err := protocol.FromSDKResourcePage(&res, pageBounds)
		if err != nil {
			return
		}
		if len(page.NextCursor) > protocol.MaxCursorBytes {
			t.Errorf("accepted cursor is %d bytes, over the %d bound",
				len(page.NextCursor), protocol.MaxCursorBytes)
		}
		if dropped := len(res.Resources) - len(page.Resources); dropped > 0 && len(page.Warnings) == 0 {
			t.Errorf("%d resource(s) were dropped without a warning", dropped)
		}
		for _, r := range page.Resources {
			if r.URI == "" {
				t.Error("accepted a resource with no URI: it could never be read")
			}
		}
	})
}

// FuzzResourceTemplatePageDecode drives the resources/templates/list decode
// path.
func FuzzResourceTemplatePageDecode(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"resourceTemplates":[]}`,
		`{"resourceTemplates":[{"uriTemplate":"x://{a}","name":"a"}]}`,
		`{"resourceTemplates":[{"name":"a"}]}`,
		`{"resourceTemplates":[null]}`,
		`{"resourceTemplates":[],"nextCursor":"` + strings.Repeat("c", protocol.MaxCursorBytes+1) + `"}`,
		``,
		`null`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var res mcp.ListResourceTemplatesResult
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			return
		}
		page, err := protocol.FromSDKResourceTemplatePage(&res, pageBounds)
		if err != nil {
			return
		}
		if len(page.NextCursor) > protocol.MaxCursorBytes {
			t.Errorf("accepted cursor is %d bytes, over the %d bound",
				len(page.NextCursor), protocol.MaxCursorBytes)
		}
		if dropped := len(res.ResourceTemplates) - len(page.Templates); dropped > 0 && len(page.Warnings) == 0 {
			t.Errorf("%d template(s) were dropped without a warning", dropped)
		}
		for _, tpl := range page.Templates {
			if tpl.URITemplate == "" {
				t.Error("accepted a resource template with no URI template")
			}
		}
	})
}
