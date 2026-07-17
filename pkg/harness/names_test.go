package mcpharness

import (
	"errors"
	"strings"
	"testing"

	"github.com/looprig/mcp/pkg/client"
)

// spec builds a ToolSpec carrying only the two fields the name table reads.
// The rest of a ToolSpec is the tool's schema and prose, which the table does
// not index.
func spec(rawName, modelName string) client.ToolSpec {
	return client.ToolSpec{RawName: rawName, ModelName: modelName}
}

func TestNameTableRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		binding string
		spec    client.ToolSpec
	}{
		{
			name:    "plain name",
			binding: "github",
			spec:    spec("search_issues", "mcp__github__search_issues"),
		},
		{
			name:    "hyphenated binding and tool",
			binding: "my-server-2",
			spec:    spec("do-thing-9", "mcp__my-server-2__do-thing-9"),
		},
		{
			name:    "digest-suffixed name round-trips like any other",
			binding: "srv",
			spec:    spec("a.b", "mcp__srv__a_b_1c2d3e4f"),
		},
		{
			name:    "raw name differs from the sanitized model name",
			binding: "srv",
			spec:    spec("café", "mcp__srv__caf_"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tbl := newNameTable()
			if err := tbl.add(tt.binding, tt.spec); err != nil {
				t.Fatalf("add(%q, %q) = %v, want nil", tt.binding, tt.spec.ModelName, err)
			}

			binding, rawTool, ok := tbl.lookup(tt.spec.ModelName)
			if !ok {
				t.Fatalf("lookup(%q) not found after add", tt.spec.ModelName)
			}
			if binding != tt.binding {
				t.Errorf("lookup(%q) binding = %q, want %q", tt.spec.ModelName, binding, tt.binding)
			}
			// The raw name is what goes back on the wire. It must come back
			// exactly as the server sent it, never as the sanitized form the
			// model saw.
			if rawTool != tt.spec.RawName {
				t.Errorf("lookup(%q) rawTool = %q, want %q", tt.spec.ModelName, rawTool, tt.spec.RawName)
			}
		})
	}
}

// TestNameTableRejectsAmbiguousFraming is the reason this file exists.
//
// Binding names permit '_' after the first byte (client.Name.Validate), and a
// model name frames its segments as "mcp__<binding>__<raw>" (internal/catalog
// identity.go). The framing is therefore ambiguous by construction: an
// underscore in a binding name is indistinguishable from the separator.
//
// Both names below are produced with no truncation, no sanitization, and no
// digest involved — sanitizeNamePart preserves '_' — so neither binding is
// defective and neither catalog can detect the clash. A catalog enforces
// uniqueness only across the one binding's own tools, which is the whole set it
// can see. The clash exists only in the union, so only the union can refuse it.
func TestNameTableRejectsAmbiguousFraming(t *testing.T) {
	t.Parallel()

	const contested = "mcp__a__b__c"

	tbl := newNameTable()
	// binding "a__b" + raw "c" -> "mcp__" + "a__b" + "__" + "c"
	if err := tbl.add("a__b", spec("c", contested)); err != nil {
		t.Fatalf("add of first tool = %v, want nil", err)
	}
	// binding "a" + raw "b__c" -> "mcp__" + "a" + "__" + "b__c"
	err := tbl.add("a", spec("b__c", contested))
	if err == nil {
		t.Fatalf("add of a second tool claiming %q returned nil; a model-facing name that resolves to two different tools on two different servers is a misrouting hazard", contested)
	}

	var dup *DuplicateModelNameError
	if !errors.As(err, &dup) {
		t.Fatalf("add error = %T (%v), want *DuplicateModelNameError so the Manager can degrade the offending binding", err, err)
	}
	if dup.ModelName != contested {
		t.Errorf("ModelName = %q, want %q", dup.ModelName, contested)
	}
	if dup.Binding != "a" {
		t.Errorf("Binding = %q, want %q (the binding that was rejected)", dup.Binding, "a")
	}
	if dup.OtherBinding != "a__b" {
		t.Errorf("OtherBinding = %q, want %q (the binding that already holds the name)", dup.OtherBinding, "a__b")
	}

	// The rejected tool must not have displaced the incumbent, and must not
	// have been recorded alongside it. Last-writer-wins here would silently
	// route binding "a__b"'s traffic to binding "a".
	binding, rawTool, ok := tbl.lookup(contested)
	if !ok {
		t.Fatalf("lookup(%q) not found; the rejection dropped the incumbent", contested)
	}
	if binding != "a__b" || rawTool != "c" {
		t.Errorf("lookup(%q) = (%q, %q), want (%q, %q); the rejected tool displaced the incumbent", contested, binding, rawTool, "a__b", "c")
	}
	if tbl.len() != 1 {
		t.Errorf("len = %d, want 1; a refused tool must not be recorded", tbl.len())
	}
}

// TestNameTableRejectsDuplicateWithinOneBinding covers a binding offering one
// name twice. A catalog should never emit that, so it is a defect rather than a
// collision — but the table refuses it anyway rather than trusting a layer below
// it to have been correct.
func TestNameTableRejectsDuplicateWithinOneBinding(t *testing.T) {
	t.Parallel()

	tbl := newNameTable()
	if err := tbl.add("srv", spec("search", "mcp__srv__search")); err != nil {
		t.Fatalf("add of first tool = %v, want nil", err)
	}
	err := tbl.add("srv", spec("other_raw_name", "mcp__srv__search"))

	var dup *DuplicateModelNameError
	if !errors.As(err, &dup) {
		t.Fatalf("add error = %T (%v), want *DuplicateModelNameError", err, err)
	}
	if dup.Binding != "srv" || dup.OtherBinding != "srv" {
		t.Errorf("Binding/OtherBinding = %q/%q, want srv/srv", dup.Binding, dup.OtherBinding)
	}
	if _, rawTool, _ := tbl.lookup("mcp__srv__search"); rawTool != "search" {
		t.Errorf("lookup rawTool = %q, want %q; the duplicate displaced the incumbent", rawTool, "search")
	}
}

// TestNameTableDistinctBindingsShareRawName is the case that must NOT be
// refused: the same tool name on two servers is the ordinary reason model names
// are binding-qualified at all. Qualification already separated them, so the
// duplicate guard must not fire.
func TestNameTableDistinctBindingsShareRawName(t *testing.T) {
	t.Parallel()

	tbl := newNameTable()
	if err := tbl.add("github", spec("search", "mcp__github__search")); err != nil {
		t.Fatalf("add(github) = %v, want nil", err)
	}
	if err := tbl.add("gitlab", spec("search", "mcp__gitlab__search")); err != nil {
		t.Fatalf("add(gitlab) = %v, want nil; two servers offering the same raw tool name is the normal case", err)
	}
	if tbl.len() != 2 {
		t.Fatalf("len = %d, want 2", tbl.len())
	}

	for _, want := range []struct{ model, binding string }{
		{"mcp__github__search", "github"},
		{"mcp__gitlab__search", "gitlab"},
	} {
		binding, rawTool, ok := tbl.lookup(want.model)
		if !ok {
			t.Fatalf("lookup(%q) not found", want.model)
		}
		if binding != want.binding {
			t.Errorf("lookup(%q) binding = %q, want %q", want.model, binding, want.binding)
		}
		if rawTool != "search" {
			t.Errorf("lookup(%q) rawTool = %q, want %q", want.model, rawTool, "search")
		}
	}
}

func TestNameTableLookupFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		qualified string
	}{
		{name: "name nobody added", qualified: "mcp__github__delete_everything"},
		{name: "empty name", qualified: ""},
		{name: "the raw name rather than the model name", qualified: "search_issues"},
		// A caller that reparsed "mcp__github__search_issues" down to its
		// binding must not find a tool under the fragment.
		{name: "a prefix of a known name", qualified: "mcp__github"},
		{name: "known name with a suffix", qualified: "mcp__github__search_issues_x"},
	}

	tbl := newNameTable()
	if err := tbl.add("github", spec("search_issues", "mcp__github__search_issues")); err != nil {
		t.Fatalf("add = %v, want nil", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			binding, rawTool, ok := tbl.lookup(tt.qualified)
			if ok {
				t.Fatalf("lookup(%q) = (%q, %q, true), want not found; an unresolvable name must never resolve to a guess", tt.qualified, binding, rawTool)
			}
			if binding != "" || rawTool != "" {
				t.Errorf("lookup(%q) = (%q, %q), want empty on failure", tt.qualified, binding, rawTool)
			}
		})
	}
}

func TestNameTableAddRejectsDegenerateSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		binding string
		spec    client.ToolSpec
	}{
		{
			name:    "no binding",
			binding: "",
			spec:    spec("search", "mcp__srv__search"),
		},
		{
			name:    "no raw name leaves nothing to put on the wire",
			binding: "srv",
			spec:    spec("", "mcp__srv__search"),
		},
		{
			name:    "no model name means no catalog ever assigned one",
			binding: "srv",
			spec:    spec("search", ""),
		},
		{
			name:    "zero spec",
			binding: "srv",
			spec:    client.ToolSpec{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tbl := newNameTable()
			if err := tbl.add(tt.binding, tt.spec); err == nil {
				t.Fatalf("add(%q, %+v) = nil, want an error", tt.binding, tt.spec)
			}
			if tbl.len() != 0 {
				t.Errorf("len = %d, want 0; a refused tool must not be recorded", tbl.len())
			}
			// Most importantly, an empty model name must not become a lookup key
			// that answers for every unnamed tool.
			if _, _, ok := tbl.lookup(""); ok {
				t.Error(`lookup("") resolved; an empty name must never route`)
			}
		})
	}
}

func TestDuplicateModelNameErrorMessage(t *testing.T) {
	t.Parallel()

	err := &DuplicateModelNameError{
		ModelName:    "mcp__a__b__c",
		Binding:      "a",
		OtherBinding: "a__b",
	}
	got := err.Error()
	for _, want := range []string{"mcp__a__b__c", `"a"`, `"a__b"`} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, want it to name %s", got, want)
		}
	}
}
