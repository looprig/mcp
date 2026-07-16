package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
)

// FuzzFromSDKToolSchema drives arbitrary bytes through the tool converter as a
// server-supplied schema — the shape an untrusted MCP server controls. The
// converter must never panic, and anything it accepts must be valid JSON
// within the configured byte and depth bounds.
func FuzzFromSDKToolSchema(f *testing.F) {
	seeds := []string{
		``,
		`{}`,
		`{"type":"object"}`,
		`{"type":"object","properties":{"a":{"type":"string"}}}`,
		`[]`,
		`null`,
		`42`,
		`"str"`,
		`{"a":{"b":{"c":{"d":{"e":{}}}}}}`,
		`{"unterminated":`,
		`{"s":"}}}}]]]]"}`,
		`{"s":"\\"}`,
		"{\"\xff\xfe\":1}",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	const (
		maxBytes = 256
		maxDepth = 5
	)
	bounds := protocol.Bounds{
		MaxSchemaBytes:     maxBytes,
		MaxSchemaDepth:     maxDepth,
		MaxTextBytes:       256,
		MaxStructuredBytes: 256,
		MaxBinaryItemBytes: 256,
		MaxBinaryItems:     4,
	}

	f.Fuzz(func(t *testing.T, schema string) {
		// As input schema: accepted values must be within bounds.
		got, err := protocol.FromSDKTool(&mcp.Tool{
			Name:        "t",
			InputSchema: json.RawMessage(schema),
		}, bounds)
		if err == nil {
			assertSchemaWithinBounds(t, "InputSchema", got.InputSchema, maxBytes, maxDepth)
			if len(got.InputSchema) == 0 {
				t.Errorf("accepted tool has an empty InputSchema for %q", schema)
			}
		}

		// As output schema: a bad one is dropped with a warning rather than
		// failing the tool, but a retained one is still within bounds.
		got, err = protocol.FromSDKTool(&mcp.Tool{
			Name:         "t",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			OutputSchema: json.RawMessage(schema),
		}, bounds)
		if err == nil {
			if got.OutputSchema != nil {
				assertSchemaWithinBounds(t, "OutputSchema", got.OutputSchema, maxBytes, maxDepth)
			}
			if len(got.Warnings) > protocol.MaxWarnings {
				t.Errorf("Warnings = %d entries, want at most %d",
					len(got.Warnings), protocol.MaxWarnings)
			}
		}
	})
}

func assertSchemaWithinBounds(t *testing.T, field string, raw json.RawMessage, maxBytes, maxDepth int) {
	t.Helper()
	if len(raw) > maxBytes {
		t.Errorf("%s is %d bytes, exceeds the %d-byte bound", field, len(raw), maxBytes)
	}
	if err := limits.CheckJSONDepth(raw, maxDepth); err != nil {
		t.Errorf("%s exceeds the depth bound: %v", field, err)
	}
	if !json.Valid(raw) {
		t.Errorf("%s = %q is not valid JSON", field, raw)
	}
}
