package catalog_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/looprig/mcp/internal/catalog"
	"github.com/looprig/mcp/internal/protocol"
)

// TestInvalidOutputSchemaIsGatedByPolicy: dropping a defective optional output
// schema is a tolerance, so it happens only when a profile permits it. Under a
// strict policy the generation is rejected — all of it, not just the tool: a
// catalog silently missing one tool is indistinguishable from a server that
// removed it.
func TestInvalidOutputSchemaIsGatedByPolicy(t *testing.T) {
	t.Parallel()

	spoiled := toolSpec("search")
	spoiled.OutputSchemaDefect = "not a JSON object"

	t.Run("tolerated", func(t *testing.T) {
		t.Parallel()
		g, err := catalog.Builder{
			Binding:    "b",
			Tools:      []protocol.ToolSpec{spoiled},
			Tolerances: catalog.Tolerances{InvalidOutputSchema: true},
		}.Build()
		if err != nil {
			t.Fatalf("Build() error = %v, want the defect to be tolerated", err)
		}
		tool, ok := g.ToolByRawName("search")
		if !ok {
			t.Fatal("the tool was dropped along with its schema")
		}
		// The tool survives without the schema, and the input schema — the one
		// that constrains what a model may send — is untouched.
		if tool.OutputSchema != nil {
			t.Error("the defective output schema was retained")
		}
		if len(tool.InputSchema) == 0 {
			t.Error("the input schema was dropped: a tolerance widened the arguments")
		}
		// Reported, per the design: every applied tolerance reaches diagnostics.
		if got := g.AppliedTolerances(); !slices.Contains(got, catalog.ToleranceInvalidOutputSchema) {
			t.Errorf("AppliedTolerances() = %v, want it to record %v", got, catalog.ToleranceInvalidOutputSchema)
		}
		if !hasWarning(g.Warnings(), "invalid_output_schema") {
			t.Errorf("Warnings() = %v, want one naming the applied tolerance", g.Warnings())
		}
	})

	t.Run("not tolerated", func(t *testing.T) {
		t.Parallel()
		_, err := catalog.Builder{
			Binding: "b",
			Tools:   []protocol.ToolSpec{spoiled, toolSpec("other")},
			// The zero policy: strict.
		}.Build()
		if err == nil {
			t.Fatal("Build() error = nil, want a strict profile to reject a defective output schema")
		}
		var defect *catalog.DefectError
		if !errors.As(err, &defect) {
			t.Errorf("Build() error = %v (%T), want a *catalog.DefectError", err, err)
		}
	})
}

// TestNormalizationIsGatedByPolicy: rewriting a raw name into one an inference
// provider will accept is a tolerance too. Qualification is not — every name is
// prefixed and binding-qualified regardless, because that is this module's own
// namespacing rather than a concession to a server.
func TestNormalizationIsGatedByPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rawName   string
		needsTol  bool
		wantModel string
	}{
		{
			name:      "a provider-compatible name needs no tolerance",
			rawName:   "search_issues",
			needsTol:  false,
			wantModel: "mcp__b__search_issues",
		},
		{
			name:     "a name with characters providers reject needs one",
			rawName:  "search/issues",
			needsTol: true,
		},
		{
			name:     "a name too long to show needs one",
			rawName:  strings.Repeat("a", 80),
			needsTol: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Permitted: it builds, and says whether the tolerance was needed.
			g, err := catalog.Builder{
				Binding:    "b",
				Tools:      []protocol.ToolSpec{toolSpec(tt.rawName)},
				Tolerances: catalog.Tolerances{NormalizeDisplayNames: true},
			}.Build()
			if err != nil {
				t.Fatalf("Build() with normalization permitted: error = %v", err)
			}
			applied := slices.Contains(g.AppliedTolerances(), catalog.ToleranceNormalizedDisplayName)
			if applied != tt.needsTol {
				t.Errorf("AppliedTolerances() records normalization = %v, want %v", applied, tt.needsTol)
			}
			tool, ok := g.ToolByRawName(tt.rawName)
			if !ok {
				t.Fatal("the tool is not reachable by its raw name")
			}
			// The raw name is preserved whatever happened to the display name:
			// that is the half of this tolerance that makes it safe.
			if tool.RawName != tt.rawName {
				t.Errorf("RawName = %q, want the server's own %q", tool.RawName, tt.rawName)
			}
			if tt.wantModel != "" && tool.ModelName != tt.wantModel {
				t.Errorf("ModelName = %q, want %q", tool.ModelName, tt.wantModel)
			}

			// Refused: a tool that cannot be shown as it stands is rejected
			// rather than renamed. One that needs nothing builds either way.
			_, err = catalog.Builder{
				Binding: "b",
				Tools:   []protocol.ToolSpec{toolSpec(tt.rawName)},
			}.Build()
			if tt.needsTol && err == nil {
				t.Error("Build() error = nil, want a strict profile to reject a name it would have to normalize")
			}
			if !tt.needsTol && err != nil {
				t.Errorf("Build() error = %v, want a name that needs no tolerance to build under a strict profile", err)
			}
		})
	}
}

// TestToleratedCatalogRecordsEveryTolerance: the design requires every applied
// tolerance to be reported. Both, when both were needed — not just the first one
// noticed.
func TestToleratedCatalogRecordsEveryTolerance(t *testing.T) {
	t.Parallel()

	spoiled := toolSpec("search/issues")
	spoiled.OutputSchemaDefect = "not a JSON object"

	g, err := catalog.Builder{
		Binding:    "b",
		Tools:      []protocol.ToolSpec{spoiled},
		Tolerances: catalog.Tolerances{InvalidOutputSchema: true, NormalizeDisplayNames: true},
	}.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	got := g.AppliedTolerances()
	for _, want := range []catalog.Tolerance{catalog.ToleranceInvalidOutputSchema, catalog.ToleranceNormalizedDisplayName} {
		if !slices.Contains(got, want) {
			t.Errorf("AppliedTolerances() = %v, want it to include %v", got, want)
		}
	}
	if len(got) != 2 {
		t.Errorf("AppliedTolerances() = %v, want exactly the two that were applied", got)
	}
}

// TestFaithfulServerNeedsNoTolerance: a server that implements the spec
// correctly produces an empty tolerance record under any profile. Otherwise the
// report would be noise, and "this binding tolerated something" would stop
// meaning anything.
func TestFaithfulServerNeedsNoTolerance(t *testing.T) {
	t.Parallel()

	for name, tol := range map[string]catalog.Tolerances{
		"strict":     {},
		"permissive": {InvalidOutputSchema: true, NormalizeDisplayNames: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g, err := catalog.Builder{
				Binding:    "b",
				Tools:      []protocol.ToolSpec{toolSpec("echo"), toolSpec("search_issues")},
				Tolerances: tol,
			}.Build()
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if got := g.AppliedTolerances(); len(got) != 0 {
				t.Errorf("AppliedTolerances() = %v for a faithful server, want none", got)
			}
		})
	}
}

// TestToleranceStringsAreExhaustive keeps the identifiers that reach
// diagnostics and configuration identity honest.
func TestToleranceStringsAreExhaustive(t *testing.T) {
	t.Parallel()

	want := map[catalog.Tolerance]string{
		catalog.ToleranceInvalidOutputSchema:   "invalid_output_schema",
		catalog.ToleranceNormalizedDisplayName: "display_name_normalization",
	}
	for tol, id := range want {
		if got := tol.String(); got != id {
			t.Errorf("Tolerance(%d).String() = %q, want %q", tol, got, id)
		}
	}
	for _, tol := range []catalog.Tolerance{0, catalog.Tolerance(200)} {
		if got := tol.String(); got != "unknown" {
			t.Errorf("Tolerance(%d).String() = %q, want %q", tol, got, "unknown")
		}
	}
}

// hasWarning reports whether any warning mentions sub.
func hasWarning(warnings []string, sub string) bool {
	for _, w := range warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
