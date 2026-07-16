package protocol_test

import (
	"encoding/json"
	"strings"
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
		// Over the byte and depth bounds below: as an output schema these
		// must be dropped, never fatal. Seeds run on every `go test`, so
		// these pin the tolerance whether or not the fuzzer is engaged.
		`{"pad":"` + strings.Repeat("x", 600) + `"}`,
		strings.Repeat(`{"x":`, 20) + `{}` + strings.Repeat(`}`, 20),
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

		// As output schema, alongside a known-good input schema: no server-
		// controlled output schema may fail the tool. Whatever the bytes, the
		// conversion must succeed — dropping the schema with a warning — so
		// this asserts err == nil rather than merely tolerating an error.
		got, err = protocol.FromSDKTool(&mcp.Tool{
			Name:         "t",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			OutputSchema: json.RawMessage(schema),
		}, bounds)
		if err != nil {
			t.Fatalf("a defective output schema must be tolerated, got error: %v (schema %q)",
				err, schema)
		}
		// A retained output schema is still within bounds; a dropped one
		// leaves a bounded warning behind.
		if got.OutputSchema != nil {
			assertSchemaWithinBounds(t, "OutputSchema", got.OutputSchema, maxBytes, maxDepth)
		} else if len(got.Warnings) == 0 && !isAbsent(schema) {
			t.Errorf("output schema %q was dropped without a warning", schema)
		}
		if len(got.Warnings) > protocol.MaxWarnings {
			t.Errorf("Warnings = %d entries, want at most %d",
				len(got.Warnings), protocol.MaxWarnings)
		}
		// The input schema is good, so the tool always survives intact.
		if len(got.InputSchema) == 0 {
			t.Errorf("valid InputSchema was lost for output schema %q", schema)
		}
	})
}

// isAbsent reports whether a schema is JSON null, which means "the server sent
// no schema" rather than "the server sent a bad one" — the one drop that is
// not a defect and so carries no warning.
func isAbsent(schema string) bool {
	return strings.TrimSpace(schema) == "null"
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
