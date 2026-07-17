package catalog_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/looprig/mcp/internal/catalog"
	"github.com/looprig/mcp/internal/protocol"
)

func TestBuildRejects(t *testing.T) {
	t.Parallel()

	schema := json.RawMessage(`{"type":"object"}`)

	tests := []struct {
		name    string
		builder catalog.Builder
		want    string
	}{
		{
			name:    "empty binding",
			builder: catalog.Builder{},
			want:    "binding name is empty",
		},
		{
			name: "duplicate tool name",
			builder: catalog.Builder{Binding: "b", Tools: []protocol.ToolSpec{
				{RawName: "dup", InputSchema: schema},
				{RawName: "dup", InputSchema: schema},
			}},
			want: "duplicate tool name",
		},
		{
			name: "duplicate prompt name",
			builder: catalog.Builder{Binding: "b", Prompts: []protocol.PromptSpec{
				{RawName: "dup"}, {RawName: "dup"},
			}},
			want: "duplicate prompt name",
		},
		{
			name: "duplicate resource URI",
			builder: catalog.Builder{Binding: "b", Resources: []protocol.ResourceSpec{
				{URI: "x://a"}, {URI: "x://a"},
			}},
			want: "duplicate resource URI",
		},
		{
			name: "duplicate resource template",
			builder: catalog.Builder{Binding: "b", ResourceTemplates: []protocol.ResourceTemplateSpec{
				{URITemplate: "x://a/{v}"}, {URITemplate: "x://a/{v}"},
			}},
			want: "duplicate resource template",
		},
		{
			name: "empty tool name",
			builder: catalog.Builder{Binding: "b", Tools: []protocol.ToolSpec{
				{RawName: "", InputSchema: schema},
			}},
			want: "identifier is empty",
		},
		{
			name: "oversized tool name",
			builder: catalog.Builder{Binding: "b", Tools: []protocol.ToolSpec{
				{RawName: strings.Repeat("a", catalog.MaxRawNameBytes+1), InputSchema: schema},
			}},
			want: "max 512",
		},
		{
			name: "control character in tool name",
			builder: catalog.Builder{Binding: "b", Tools: []protocol.ToolSpec{
				{RawName: "esc\x1b[31m", InputSchema: schema},
			}},
			want: "control character",
		},
		{
			name: "newline in tool name",
			builder: catalog.Builder{Binding: "b", Tools: []protocol.ToolSpec{
				{RawName: "a\nb", InputSchema: schema},
			}},
			want: "control character",
		},
		{
			name: "invalid UTF-8 in tool name",
			builder: catalog.Builder{Binding: "b", Tools: []protocol.ToolSpec{
				{RawName: "bad\xff\xfename", InputSchema: schema},
			}},
			want: "not valid UTF-8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g, err := tt.builder.Build()
			if err == nil {
				t.Fatalf("Build() = %v, want error containing %q", g, tt.want)
			}
			if g != nil {
				t.Errorf("Build() returned a generation alongside its error: a failed build must publish nothing")
			}
			var defect *catalog.DefectError
			if !errors.As(err, &defect) {
				t.Fatalf("Build() error = %T (%v), want *catalog.DefectError", err, err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Build() error = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// TestBuildBoundedAtLimits covers the boundary values: an empty catalog is
// valid, and a name at exactly MaxRawNameBytes is accepted.
func TestBuildBoundedAtLimits(t *testing.T) {
	t.Parallel()

	t.Run("empty catalog is valid", func(t *testing.T) {
		t.Parallel()
		g := mustBuild(t, catalog.Builder{Binding: "b"})
		if g.ToolCount() != 0 {
			t.Errorf("ToolCount() = %d, want 0", g.ToolCount())
		}
		if g.Digest().IsZero() {
			t.Error("an empty catalog still has a digest; got the zero value")
		}
	})

	t.Run("name at exactly the limit is accepted", func(t *testing.T) {
		t.Parallel()
		name := strings.Repeat("a", catalog.MaxRawNameBytes)
		// Permissive: a name this long cannot be shown to a model as it stands,
		// so it needs the normalization tolerance. What is under test here is
		// the raw-name bound, not the policy.
		g := mustBuild(t, catalog.Builder{Binding: "b", Tolerances: permissive, Tools: []protocol.ToolSpec{
			{RawName: name, InputSchema: json.RawMessage(`{"type":"object"}`)},
		}})
		if _, ok := g.ToolByRawName(name); !ok {
			t.Error("a tool named at exactly MaxRawNameBytes was rejected")
		}
	})

	t.Run("warnings are capped", func(t *testing.T) {
		t.Parallel()
		many := make([]string, catalog.MaxWarnings+10)
		for i := range many {
			many[i] = "w"
		}
		g := mustBuild(t, catalog.Builder{Binding: "b", Warnings: many})
		got := g.Warnings()
		if len(got) != catalog.MaxWarnings {
			t.Errorf("len(Warnings()) = %d, want %d", len(got), catalog.MaxWarnings)
		}
		if last := got[len(got)-1]; !strings.Contains(last, fmt.Sprintf("%d raised in all", len(many))) {
			t.Errorf("last warning = %q, want it to report all %d warnings raised", last, len(many))
		}
	})

	t.Run("warnings dropped before Build are counted in the summary", func(t *testing.T) {
		t.Parallel()
		// Discovery bounds each family as it fetches, so by the time Build sees
		// a list the list may already be short. The count it carries is what
		// keeps the summary's total the true one rather than a per-layer one.
		g := mustBuild(t, catalog.Builder{Binding: "b", Warnings: []string{"w"}, DroppedWarnings: 500})
		got := g.Warnings()
		if len(got) != 2 {
			t.Fatalf("Warnings() = %v, want the warning plus a summary", got)
		}
		if last := got[1]; !strings.Contains(last, "501 raised in all") || !strings.Contains(last, "500 further") {
			t.Errorf("summary = %q, want it to count the 500 dropped before Build", last)
		}
	})
}

// TestGenerationIsImmutable is the package's central invariant: a Generation is
// shared across goroutines with no lock, which is only sound if nothing can
// reach in and change it. Every accessor must hand back a copy.
func TestGenerationIsImmutable(t *testing.T) {
	t.Parallel()

	b := richBuilder()
	g := mustBuild(t, b)
	want := g.Digest()

	t.Run("mutating the builder after Build does not affect the generation", func(t *testing.T) {
		b.Binding = "hijacked"
		b.Tools[0].RawName = "hijacked"
		b.Tools[0].InputSchema[0] = 'X'
		b.Prompts[0].Arguments[0].Name = "hijacked"
		b.Resources[0].URI = "hijacked"
		b.Instructions = "hijacked"
		if got := g.Digest(); got != want {
			t.Errorf("digest changed to %s after the builder was mutated: Build did not copy its input", got)
		}
		if g.Binding() != "github" {
			t.Errorf("Binding() = %q, want %q", g.Binding(), "github")
		}
	})

	t.Run("mutating a returned tool does not affect the generation", func(t *testing.T) {
		// search_issues, not Tools()[0]: it is the entry richBuilder gives
		// warnings and annotations, which are the fields with something to
		// alias.
		i := indexOf(t, g.Tools(), "search_issues")

		tools := g.Tools()
		tools[i].RawName = "hijacked"
		tools[i].Warnings[0] = "hijacked"
		tools[i].InputSchema[0] = 'X'
		tools[i].Annotations.ReadOnlyHint = !tools[i].Annotations.ReadOnlyHint
		tools[i].Annotations.DestructiveHint = ptr(true)

		again := g.Tools()
		if again[i].RawName == "hijacked" {
			t.Error("Tools() aliases the generation's tool: a caller can rename a tool in place")
		}
		if again[i].InputSchema[0] == 'X' {
			t.Error("Tools() aliases the generation's input schema: a caller can rewrite a schema in place")
		}
		if again[i].Warnings[0] == "hijacked" {
			t.Error("Tools() aliases the generation's warnings")
		}
		if a := again[i].Annotations; a.DestructiveHint == nil || *a.DestructiveHint {
			t.Error("Tools() aliases the generation's annotations: a caller can flip a destructive hint")
		}
		if got := g.Digest(); got != want {
			t.Errorf("digest changed to %s after a returned tool was mutated", got)
		}
	})

	t.Run("mutating returned collections does not affect the generation", func(t *testing.T) {
		g.Prompts()[0].Arguments[0].Name = "hijacked"
		g.Resources()[0].URI = "hijacked"
		g.ResourceTemplates()[0].URITemplate = "hijacked"
		g.Warnings()[0] = "hijacked"
		g.Decisions()[0].Family = catalog.FamilyPrompts

		if got := g.Prompts()[0].Arguments[0].Name; got == "hijacked" {
			t.Error("Prompts() aliases the generation's prompt arguments")
		}
		if got := g.Resources()[0].URI; got == "hijacked" {
			t.Error("Resources() aliases the generation's resources")
		}
		if got := g.ResourceTemplates()[0].URITemplate; got == "hijacked" {
			t.Error("ResourceTemplates() aliases the generation's templates")
		}
		if got := g.Warnings()[0]; got == "hijacked" {
			t.Error("Warnings() aliases the generation's warnings")
		}
		if got := g.Decisions()[0].Family; got == catalog.FamilyPrompts {
			t.Error("Decisions() aliases the generation's decisions")
		}
		if got := g.Digest(); got != want {
			t.Errorf("digest changed to %s after returned collections were mutated", got)
		}
	})

	t.Run("mutating a looked-up tool does not affect the generation", func(t *testing.T) {
		tool, ok := g.ToolByRawName("search_issues")
		if !ok {
			t.Fatal("ToolByRawName(search_issues) not found")
		}
		tool.RawName = "hijacked"
		tool.Warnings[0] = "hijacked"

		again, _ := g.ToolByRawName("search_issues")
		if again.RawName != "search_issues" || again.Warnings[0] == "hijacked" {
			t.Error("ToolByRawName aliases the generation's tool")
		}
	})
}

// TestGenerationAccessors covers the read surface, including the canonical
// ordering callers depend on and the reverse mapping routing depends on.
func TestGenerationAccessors(t *testing.T) {
	t.Parallel()

	g := mustBuild(t, richBuilder())

	t.Run("scalars round-trip", func(t *testing.T) {
		t.Parallel()
		if g.Binding() != "github" {
			t.Errorf("Binding() = %q", g.Binding())
		}
		if g.Number() != 4 {
			t.Errorf("Number() = %d, want 4", g.Number())
		}
		if g.ProtocolVersion() != "2025-06-18" {
			t.Errorf("ProtocolVersion() = %q", g.ProtocolVersion())
		}
		if g.Instructions() != "be careful" {
			t.Errorf("Instructions() = %q", g.Instructions())
		}
		if g.Server().Name != "srv" {
			t.Errorf("Server().Name = %q", g.Server().Name)
		}
		if !g.Capabilities().Tools || !g.Capabilities().ResourcesSubscribe {
			t.Errorf("Capabilities() = %+v, want the advertised flags preserved", g.Capabilities())
		}
	})

	t.Run("tools are in canonical raw-name order", func(t *testing.T) {
		t.Parallel()
		tools := g.Tools()
		// richBuilder supplies search_issues before create_issue.
		if len(tools) != 2 || tools[0].RawName != "create_issue" || tools[1].RawName != "search_issues" {
			t.Fatalf("Tools() = %v, want them sorted by raw name", names(tools))
		}
		if g.ToolCount() != len(tools) {
			t.Errorf("ToolCount() = %d, len(Tools()) = %d", g.ToolCount(), len(tools))
		}
	})

	t.Run("schema digests track the schema", func(t *testing.T) {
		t.Parallel()
		search, _ := g.ToolByRawName("search_issues")
		if search.InputSchemaDigest != catalog.DigestBytes(search.InputSchema) {
			t.Error("InputSchemaDigest does not match its schema")
		}
		if search.OutputSchemaDigest.IsZero() {
			t.Error("a tool with an output schema has a zero OutputSchemaDigest")
		}
		create, _ := g.ToolByRawName("create_issue")
		if !create.OutputSchemaDigest.IsZero() {
			t.Error("a tool with no output schema must have the zero OutputSchemaDigest, which is how absence is spelled")
		}
	})

	t.Run("lookups miss cleanly", func(t *testing.T) {
		t.Parallel()
		if _, ok := g.ToolByRawName("nope"); ok {
			t.Error("ToolByRawName found a tool that does not exist")
		}
		if _, ok := g.ToolByModelName("nope"); ok {
			t.Error("ToolByModelName found a tool that does not exist")
		}
		// A model name must not be findable by its raw name and vice versa: the
		// two namespaces are separate, which is why both indexes exist.
		if _, ok := g.ToolByRawName("mcp__github__search_issues"); ok {
			t.Error("ToolByRawName resolved a model name")
		}
		if _, ok := g.ToolByModelName("search_issues"); ok {
			t.Error("ToolByModelName resolved a raw name")
		}
	})

	t.Run("reverse mapping resolves every tool", func(t *testing.T) {
		t.Parallel()
		for _, want := range g.Tools() {
			got, ok := g.ToolByModelName(want.ModelName)
			if !ok {
				t.Errorf("ToolByModelName(%q) not found, but the tool is in the catalog", want.ModelName)
				continue
			}
			if got.RawName != want.RawName {
				t.Errorf("ToolByModelName(%q).RawName = %q, want %q", want.ModelName, got.RawName, want.RawName)
			}
		}
	})
}

// indexOf finds a tool by raw name, failing the test when it is absent: a
// silent miss would turn an aliasing assertion into a no-op.
func indexOf(t *testing.T, tools []catalog.Tool, rawName string) int {
	t.Helper()
	for i, tool := range tools {
		if tool.RawName == rawName {
			return i
		}
	}
	t.Fatalf("tool %q not in the catalog", rawName)
	return -1
}

func names(tools []catalog.Tool) []string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t.RawName
	}
	return out
}

func TestFamilyAndActionStrings(t *testing.T) {
	t.Parallel()

	families := map[catalog.Family]string{
		catalog.FamilyTools:             "tools",
		catalog.FamilyPrompts:           "prompts",
		catalog.FamilyResources:         "resources",
		catalog.FamilyResourceTemplates: "resource_templates",
		catalog.Family(0):               "unknown",
		catalog.Family(200):             "unknown",
	}
	for f, want := range families {
		if got := f.String(); got != want {
			t.Errorf("Family(%d).String() = %q, want %q", f, got, want)
		}
	}

	actions := map[catalog.DecisionAction]string{
		catalog.ActionFetched:              "fetched",
		catalog.ActionSkippedNotAdvertised: "skipped_not_advertised",
		catalog.DecisionAction(0):          "unknown",
		catalog.DecisionAction(200):        "unknown",
	}
	for a, want := range actions {
		if got := a.String(); got != want {
			t.Errorf("DecisionAction(%d).String() = %q, want %q", a, got, want)
		}
	}
}

func TestDefectErrorMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *catalog.DefectError
		want string
	}{
		{"with family", &catalog.DefectError{Family: catalog.FamilyTools, Reason: "bad"}, "catalog: tools: bad"},
		{"without family", &catalog.DefectError{Reason: "bad"}, "catalog: bad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}
