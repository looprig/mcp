package catalog_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/looprig/mcp/internal/catalog"
	"github.com/looprig/mcp/internal/protocol"
)

// permissive is the compatibility policy of the module's default profile: the
// safe tolerances, all applied. Name construction is only exercised at all under
// a policy that permits normalizing a name — a strict profile rejects such a
// tool outright, which is what TestNormalizationIsGatedByPolicy covers.
var permissive = catalog.Tolerances{InvalidOutputSchema: true, NormalizeDisplayNames: true}

// buildTools is a shorthand for a catalog of nothing but tools with the given
// raw names.
func buildTools(t *testing.T, binding string, rawNames ...string) *catalog.Generation {
	t.Helper()
	b := catalog.Builder{Binding: binding, Tolerances: permissive}
	for _, n := range rawNames {
		b.Tools = append(b.Tools, protocol.ToolSpec{
			RawName:     n,
			InputSchema: json.RawMessage(`{"type":"object"}`),
		})
	}
	return mustBuild(t, b)
}

func modelNameOf(t *testing.T, g *catalog.Generation, rawName string) string {
	t.Helper()
	tool, ok := g.ToolByRawName(rawName)
	if !ok {
		t.Fatalf("tool %q not in the catalog", rawName)
	}
	return tool.ModelName
}

func TestModelNameConstruction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		binding string
		rawName string
		want    string
	}{
		{
			name:    "the design's worked example",
			binding: "github",
			rawName: "search_issues",
			want:    "mcp__github__search_issues",
		},
		{
			name:    "hyphens and digits survive",
			binding: "my-server-2",
			rawName: "do-thing-9",
			want:    "mcp__my-server-2__do-thing-9",
		},
		{
			name:    "case is preserved",
			binding: "srv",
			rawName: "SearchIssues",
			want:    "mcp__srv__SearchIssues",
		},
		{
			name:    "a dotted name is sanitized",
			binding: "srv",
			rawName: "files.read",
			want:    "mcp__srv__files_read",
		},
		{
			name:    "a slashed name is sanitized",
			binding: "srv",
			rawName: "a/b",
			want:    "mcp__srv__a_b",
		},
		{
			name:    "spaces are sanitized",
			binding: "srv",
			rawName: "search issues",
			want:    "mcp__srv__search_issues",
		},
		{
			name:    "a multi-byte rune becomes one underscore",
			binding: "srv",
			rawName: "café",
			want:    "mcp__srv__caf_",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := buildTools(t, tt.binding, tt.rawName)
			if got := modelNameOf(t, g, tt.rawName); got != tt.want {
				t.Errorf("model name = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestModelNameIsDeterministic pins the design's first requirement: name
// construction must not depend on anything but the binding and the tool set.
func TestModelNameIsDeterministic(t *testing.T) {
	t.Parallel()

	// Includes a colliding pair and an over-long name, so the digest-suffix
	// paths are covered too, not just the trivial ones.
	raw := []string{"a.b", "a-b", "a_b", strings.Repeat("long", 30), "plain"}
	first := buildTools(t, "srv", raw...)

	for i := range 16 {
		// Feed them in a rotated order: the result must not move.
		rotated := append(append([]string{}, raw[i%len(raw):]...), raw[:i%len(raw)]...)
		g := buildTools(t, "srv", rotated...)
		for _, n := range raw {
			want := modelNameOf(t, first, n)
			if got := modelNameOf(t, g, n); got != want {
				t.Fatalf("rotation %d: model name for %q = %q, want %q: naming depends on input order", i, n, got, want)
			}
		}
	}
}

// TestModelNameCollisionsAreDisambiguated is the sanitization hazard the digest
// suffix exists for: three distinct raw names that all sanitize onto one
// candidate must still be three distinct, resolvable tools. Without a suffix
// two of them would be unreachable — or worse, route to each other.
func TestModelNameCollisionsAreDisambiguated(t *testing.T) {
	t.Parallel()

	raw := []string{"a.b", "a/b", "a b", "a:b"}
	g := buildTools(t, "srv", raw...)

	seen := make(map[string]string, len(raw))
	for _, n := range raw {
		got := modelNameOf(t, g, n)
		if prev, dup := seen[got]; dup {
			t.Fatalf("tools %q and %q share the model name %q", prev, n, got)
		}
		seen[got] = n

		if len(got) > catalog.MaxModelNameBytes {
			t.Errorf("model name %q is %d bytes, over the %d limit", got, len(got), catalog.MaxModelNameBytes)
		}
		// Every member of the colliding group is suffixed, including the one
		// that sorted first: there is no arbitrary winner.
		if got == "mcp__srv__a_b" {
			t.Errorf("tool %q kept the unsuffixed name %q; every member of a colliding group must be suffixed", n, got)
		}
		// The reverse mapping must resolve it back to the right tool.
		tool, ok := g.ToolByModelName(got)
		if !ok || tool.RawName != n {
			t.Errorf("ToolByModelName(%q) = %q, %v; want %q", got, tool.RawName, ok, n)
		}
	}
}

// TestModelNameCollisionSuffixDependsOnRawNameOnly proves the suffix
// distinguishes the thing sanitization destroyed. Two colliding tools must get
// different suffixes because their raw names differ — not because of their
// position.
func TestModelNameCollisionSuffixDependsOnRawNameOnly(t *testing.T) {
	t.Parallel()

	// The same colliding pair, discovered alongside different other tools.
	a := buildTools(t, "srv", "a.b", "a/b")
	b := buildTools(t, "srv", "a.b", "a/b", "unrelated", "another.one")

	for _, n := range []string{"a.b", "a/b"} {
		if got, want := modelNameOf(t, b, n), modelNameOf(t, a, n); got != want {
			t.Errorf("tool %q: model name = %q with unrelated siblings, %q without: the suffix depends on more than the raw name", n, got, want)
		}
	}
}

// TestModelNameTruncation covers the other reason a suffix appears: a name too
// long for a provider's limit.
func TestModelNameTruncation(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 200)
	g := buildTools(t, "srv", long, "short")

	got := modelNameOf(t, g, long)
	if len(got) != catalog.MaxModelNameBytes {
		t.Errorf("truncated model name = %q (%d bytes), want exactly %d", got, len(got), catalog.MaxModelNameBytes)
	}
	if !strings.HasPrefix(got, "mcp__srv__x") {
		t.Errorf("truncated model name = %q, want it to keep the readable prefix", got)
	}
	// The suffix is what keeps a truncated name unique, so it must be there.
	if suffix := got[len(got)-9:]; suffix[0] != '_' {
		t.Errorf("truncated model name = %q, want a %q-separated digest suffix", got, "_")
	}
	// A name that fits is left alone: the suffix is a cost paid only when
	// something forces it.
	if short := modelNameOf(t, g, "short"); short != "mcp__srv__short" {
		t.Errorf("model name for a short tool = %q, want it unsuffixed", short)
	}

	t.Run("two long names that share a prefix stay distinct", func(t *testing.T) {
		t.Parallel()
		// Identical for far longer than the truncation point: only the digest
		// can tell them apart.
		a := strings.Repeat("y", 200) + "-a"
		b := strings.Repeat("y", 200) + "-b"
		g := buildTools(t, "srv", a, b)
		if modelNameOf(t, g, a) == modelNameOf(t, g, b) {
			t.Error("two long names sharing a prefix truncated onto the same model name")
		}
	})
}

// TestModelNameFitsProviderLimitAlways sweeps the name construction against
// hostile inputs: whatever a server sends, the result must be a usable
// identifier within the provider bound.
func TestModelNameFitsProviderLimitAlways(t *testing.T) {
	t.Parallel()

	bindings := []string{"b", "srv", strings.Repeat("b", 64)}
	raws := []string{
		"x",
		"tool",
		strings.Repeat("a", 512),
		"日本語のツール",
		"...",
		"-",
		"_",
		strings.Repeat("é", 100),
		"a b c d e f g",
	}
	for _, binding := range bindings {
		for i, raw := range raws {
			t.Run(fmt.Sprintf("%d-%d", len(binding), i), func(t *testing.T) {
				t.Parallel()
				g := buildTools(t, binding, raw)
				name := modelNameOf(t, g, raw)
				if name == "" {
					t.Fatal("model name is empty")
				}
				if len(name) > catalog.MaxModelNameBytes {
					t.Errorf("model name %q is %d bytes, over the %d limit", name, len(name), catalog.MaxModelNameBytes)
				}
				for _, r := range name {
					ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
						(r >= '0' && r <= '9') || r == '_' || r == '-'
					if !ok {
						t.Errorf("model name %q contains %#U, outside the permitted character set", name, r)
					}
				}
				if _, ok := g.ToolByModelName(name); !ok {
					t.Errorf("model name %q does not resolve back to its tool", name)
				}
			})
		}
	}
}

// TestModelNamesAreBindingQualified is the reason for the prefix: two servers
// offering the same tool must not be confusable.
func TestModelNamesAreBindingQualified(t *testing.T) {
	t.Parallel()

	a := buildTools(t, "github", "search")
	b := buildTools(t, "gitlab", "search")

	if got, other := modelNameOf(t, a, "search"), modelNameOf(t, b, "search"); got == other {
		t.Errorf("both bindings named their tool %q: names are not binding-qualified", got)
	}
	if !strings.HasPrefix(modelNameOf(t, a, "search"), "mcp__") {
		t.Error("model names must carry the mcp__ prefix that separates them from native host tools")
	}
}
