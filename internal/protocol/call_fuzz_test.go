package protocol_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
)

// FuzzCallToolResultDecode drives arbitrary bytes through the whole tools/call
// decode path a server controls: the SDK's unmarshal, then this module's result
// conversion.
//
// This is the conversion with the most server-controlled surface in the module —
// arbitrary content of arbitrary kinds, plus a structured document that is
// `any` on the wire — and every bound in the design's content-conversion list
// lands here. The assertions are those bounds, stated as properties: nothing
// retained exceeds its limit, nothing vanishes without a warning, and no input
// panics.
func FuzzCallToolResultDecode(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"content":[]}`,
		`{"content":null}`,
		`{"content":[{"type":"text","text":"hello"}]}`,
		`{"content":[{"type":"text","text":""}]}`,
		`{"isError":true,"content":[{"type":"text","text":"it broke"}]}`,
		// Text over the bound: truncated, never fatal.
		`{"content":[{"type":"text","text":"` + strings.Repeat("t", 500) + `"}]}`,
		// Binary kinds, within and over the item bound.
		`{"content":[{"type":"image","mimeType":"image/png","data":"aGk="}]}`,
		`{"content":[{"type":"audio","mimeType":"audio/wav","data":"aGk="}]}`,
		`{"content":[{"type":"image","mimeType":"image/png","data":"` + strings.Repeat("QQ==", 200) + `"}]}`,
		// More binary items than the budget allows.
		`{"content":[{"type":"image","data":"aGk="},{"type":"image","data":"aGk="},{"type":"image","data":"aGk="}]}`,
		// Embedded resources, text and blob.
		`{"content":[{"type":"resource","resource":{"uri":"x://a","text":"body"}}]}`,
		`{"content":[{"type":"resource","resource":{"uri":"x://a","blob":"aGk="}}]}`,
		`{"content":[{"type":"resource"}]}`,
		// Kinds this module does not model: bounded metadata, never a panic.
		`{"content":[{"type":"resource_link","uri":"x://a","name":"a"}]}`,
		`{"content":[{"type":"tool_use","id":"1","name":"t"}]}`,
		`{"content":[{"type":"tool_result","toolUseId":"1"}]}`,
		`{"content":[{"type":"something_new_entirely"}]}`,
		`{"content":[null]}`,
		// Structured content: absent, null, small, huge, deep.
		`{"structuredContent":{"ok":true}}`,
		`{"structuredContent":null}`,
		`{"structuredContent":{"pad":"` + strings.Repeat("s", 500) + `"}}`,
		`{"structuredContent":` + strings.Repeat(`{"a":`, 20) + `1` + strings.Repeat(`}`, 20) + `}`,
		`{"structuredContent":[1,2,3]}`,
		`{"structuredContent":"a string"}`,
		`{"structuredContent":42}`,
		// Both halves at once.
		`{"isError":true,"content":[{"type":"text","text":"x"}],"structuredContent":{"a":1}}`,
		// Malformed and hostile.
		``,
		`null`,
		`[]`,
		`{"content":`,
		"{\"content\":[{\"type\":\"text\",\"text\":\"\xff\xfe\"}]}",
		`{"content":[{"type":"text","text":"x"}],"unknownField":true}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var res mcp.CallToolResult
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			// The SDK refused it before we saw it.
			return
		}

		got, err := protocol.FromSDKCallToolResult(&res, resultBounds)
		if err != nil {
			// A rejected result must be wholly rejected.
			if len(got.Content) != 0 || got.Structured != nil {
				t.Errorf("a rejected result still carried %d content items and %d structured bytes",
					len(got.Content), len(got.Structured))
			}
			return
		}

		// Structured content: within the bound, valid JSON, and never silently
		// dropped.
		if len(got.Structured) > resultBounds.MaxStructuredBytes {
			t.Errorf("structured content is %d bytes, over the %d bound",
				len(got.Structured), resultBounds.MaxStructuredBytes)
		}
		if got.Structured != nil {
			if !json.Valid(got.Structured) {
				t.Errorf("retained structured content is not valid JSON: %s", got.Structured)
			}
			if err := limits.CheckJSONDepth(got.Structured, resultBounds.MaxSchemaDepth); err != nil {
				t.Errorf("retained structured content is too deep: %v", err)
			}
		}
		if res.StructuredContent != nil && got.Structured == nil && len(got.Warnings) == 0 {
			// The one legitimate silent case is JSON null, which is absence
			// rather than a defect.
			if raw, ok := res.StructuredContent.(json.RawMessage); !ok ||
				strings.TrimSpace(string(raw)) != "null" {
				t.Errorf("structured content was dropped without a warning (input %q)", body)
			}
		}
		if len(got.Warnings) > protocol.MaxWarnings {
			t.Errorf("Warnings = %d, want at most %d", len(got.Warnings), protocol.MaxWarnings)
		}

		// Content: the list keeps its length, so a caller can always tell which
		// item it lost, and every retained item is within its bound.
		if len(got.Content) != len(res.Content) {
			t.Errorf("content list changed length: %d in, %d out (an item vanished)",
				len(res.Content), len(got.Content))
		}
		assertContentBounded(t, got.Content, resultBounds)
	})
}

// FuzzContentDecode drives arbitrary content lists through the conversion,
// independently of a tool result. Content also arrives on prompts and
// resources, so the properties are asserted against the converter itself rather
// than only through one of its callers.
func FuzzContentDecode(f *testing.F) {
	seeds := []string{
		`[]`,
		`[{"type":"text","text":"hi"}]`,
		`[{"type":"image","mimeType":"image/png","data":"aGk="}]`,
		`[{"type":"audio","mimeType":"audio/wav","data":"aGk="}]`,
		`[{"type":"resource","resource":{"uri":"x://a","text":"body"}}]`,
		`[{"type":"resource","resource":{"uri":"x://a","blob":"aGk="}}]`,
		`[{"type":"resource_link","uri":"x://a"}]`,
		`[{"type":"unknown_kind"}]`,
		`[null]`,
		`[{"type":"text","text":"` + strings.Repeat("x", 500) + `"}]`,
		`[{"type":"image","data":"aGk="},{"type":"image","data":"aGk="},{"type":"image","data":"aGk="},{"type":"image","data":"aGk="}]`,
		`null`,
		``,
		`{}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var content []mcp.Content
		if err := json.Unmarshal([]byte(body), &content); err != nil {
			return
		}
		got, err := protocol.FromSDKContents(content, resultBounds)
		if err != nil {
			return
		}
		if len(got) != len(content) {
			t.Errorf("content list changed length: %d in, %d out", len(content), len(got))
		}
		assertContentBounded(t, got, resultBounds)
	})
}

// FuzzGetPromptResultDecode drives the prompts/get decode path. A prompt's
// messages are external content and must be bounded like any other.
func FuzzGetPromptResultDecode(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"messages":[]}`,
		`{"description":"d","messages":[{"role":"user","content":{"type":"text","text":"hi"}}]}`,
		`{"messages":[{"role":"assistant","content":{"type":"text","text":"` + strings.Repeat("m", 500) + `"}}]}`,
		`{"description":"` + strings.Repeat("d", 500) + `"}`,
		`{"messages":[{"role":"user"}]}`,
		`{"messages":[null]}`,
		`{"messages":[{"role":"user","content":{"type":"image","data":"aGk="}}]}`,
		`{"messages":[{"role":"user","content":{"type":"unknown"}}]}`,
		``,
		`null`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var res mcp.GetPromptResult
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			return
		}
		got, err := protocol.FromSDKGetPromptResult(&res, resultBounds)
		if err != nil {
			return
		}
		if len(got.Description) > resultBounds.MaxTextBytes {
			t.Errorf("Description is %d bytes, over the %d bound",
				len(got.Description), resultBounds.MaxTextBytes)
		}
		for i, m := range got.Messages {
			if len(m.Role) > resultBounds.MaxTextBytes {
				t.Errorf("message %d role is %d bytes, over the %d bound", i, len(m.Role), resultBounds.MaxTextBytes)
			}
			if m.Content == nil {
				t.Errorf("message %d has nil content: a caller type-switching on it would panic", i)
				continue
			}
			assertContentBounded(t, []protocol.Content{m.Content}, resultBounds)
		}
	})
}

// FuzzReadResourceResultDecode drives the resources/read decode path.
func FuzzReadResourceResultDecode(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"contents":[]}`,
		`{"contents":[{"uri":"x://a","text":"body"}]}`,
		`{"contents":[{"uri":"x://a","blob":"aGk="}]}`,
		`{"contents":[{"uri":"x://a","text":"` + strings.Repeat("t", 500) + `"}]}`,
		`{"contents":[{"uri":"x://a","blob":"` + strings.Repeat("QQ==", 200) + `"}]}`,
		`{"contents":[{"uri":"1","blob":"aGk="},{"uri":"2","blob":"aGk="},{"uri":"3","blob":"aGk="}]}`,
		`{"contents":[null]}`,
		`{"contents":[{}]}`,
		``,
		`null`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var res mcp.ReadResourceResult
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			return
		}
		got, err := protocol.FromSDKReadResourceResult(&res, resultBounds)
		if err != nil {
			return
		}
		binary := 0
		for i, c := range got.Contents {
			if len(c.Text) > resultBounds.MaxTextBytes {
				t.Errorf("contents[%d] text is %d bytes, over the %d bound", i, len(c.Text), resultBounds.MaxTextBytes)
			}
			if len(c.Data) > resultBounds.MaxBinaryItemBytes {
				t.Errorf("contents[%d] blob is %d bytes, over the %d bound", i, len(c.Data), resultBounds.MaxBinaryItemBytes)
			}
			if len(c.Data) > 0 {
				binary++
			}
		}
		if binary > resultBounds.MaxBinaryItems {
			t.Errorf("retained %d binary items, over the %d bound", binary, resultBounds.MaxBinaryItems)
		}
	})
}

// FuzzLogParamsDecode drives the logging notification decode path. A log
// payload is `any` on the wire, so a server can put anything at all here.
func FuzzLogParamsDecode(f *testing.F) {
	seeds := []string{
		`{"level":"info","data":"hello"}`,
		`{"level":"error","logger":"srv","data":{"k":"v"}}`,
		`{"level":"debug","data":null}`,
		`{"level":"info","data":42}`,
		`{"level":"info","data":[1,2,3]}`,
		`{"level":"info","data":"` + strings.Repeat("x", 5000) + `"}`,
		`{"level":"info","logger":"` + strings.Repeat("l", 5000) + `","data":"x"}`,
		`{"level":"","data":""}`,
		`{}`,
		``,
		`null`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		var params mcp.LoggingMessageParams
		if err := json.Unmarshal([]byte(body), &params); err != nil {
			return
		}
		// No error return: a log must never fail a connection, only be bounded.
		got := protocol.FromSDKLogParams(&params, resultBounds)
		if len(got.Text) > resultBounds.MaxLogBytes {
			t.Errorf("log text is %d bytes, over the %d bound: a server can make a log line a memory problem",
				len(got.Text), resultBounds.MaxLogBytes)
		}
		if len(got.Logger) > resultBounds.MaxLogBytes {
			t.Errorf("logger name is %d bytes, over the %d bound", len(got.Logger), resultBounds.MaxLogBytes)
		}
	})
}

// assertContentBounded checks every property the design's content-conversion
// section requires of a converted list.
func assertContentBounded(t *testing.T, content []protocol.Content, b protocol.Bounds) {
	t.Helper()

	binary := 0
	for i, c := range content {
		if c == nil {
			t.Errorf("content[%d] is nil: a caller exhausting the union would panic on it", i)
			continue
		}
		switch v := c.(type) {
		case protocol.TextContent:
			if len(v.Text) > b.MaxTextBytes {
				t.Errorf("content[%d] text is %d bytes, over the %d bound", i, len(v.Text), b.MaxTextBytes)
			}
		case protocol.ImageContent:
			if len(v.Data) > b.MaxBinaryItemBytes {
				t.Errorf("content[%d] image is %d bytes, over the %d bound", i, len(v.Data), b.MaxBinaryItemBytes)
			}
			binary++
		case protocol.AudioContent:
			if len(v.Data) > b.MaxBinaryItemBytes {
				t.Errorf("content[%d] audio is %d bytes, over the %d bound", i, len(v.Data), b.MaxBinaryItemBytes)
			}
			binary++
		case protocol.EmbeddedResourceContent:
			if len(v.Text) > b.MaxTextBytes {
				t.Errorf("content[%d] embedded text is %d bytes, over the %d bound", i, len(v.Text), b.MaxTextBytes)
			}
			if len(v.Data) > b.MaxBinaryItemBytes {
				t.Errorf("content[%d] embedded blob is %d bytes, over the %d bound", i, len(v.Data), b.MaxBinaryItemBytes)
			}
			if len(v.Data) > 0 {
				binary++
			}
		case protocol.UnsupportedContent:
			// The stand-in must say what it stood in for, or an operator cannot
			// tell a refused image from a refused anything.
			if v.Kind == "" {
				t.Errorf("content[%d] is Unsupported with no Kind: the caller cannot tell what was refused", i)
			}
			if v.Bytes < 0 {
				t.Errorf("content[%d] reports a negative size (%d)", i, v.Bytes)
			}
		default:
			t.Errorf("content[%d] is %T, outside the sealed union: a caller's type switch cannot handle it", i, c)
		}
	}
	if binary > b.MaxBinaryItems {
		t.Errorf("retained %d binary items, over the %d bound", binary, b.MaxBinaryItems)
	}
}
