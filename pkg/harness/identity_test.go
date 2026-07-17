// The identity digest's tests. They are the catalog digest's tests
// (internal/catalog/digest_test.go) applied to this package's encoding, and
// deliberately so: the two digests share a framing (internal/canonical), so they
// share a threat model and should share the shape of the evidence against it.
//
// Four properties, each needing a different kind of test:
//
//   - Determinism — the same configuration digests the same however it arrived.
//   - Sensitivity — every field that is identity moves the digest. Swept
//     reflectively, so a field added later and forgotten in computeDigest fails
//     here rather than silently dropping out of identity.
//   - Unambiguity — no two different configurations encode to the same bytes.
//     Pairs, because a single-field mutation cannot see a framing bug.
//   - Known answer — the encoding has not drifted. Golden, because neither
//     sensitivity nor collision testing can see a dropped field tag.
//
// And one this package has that the catalog's does not: the secret probe. It is
// the reason ConfigIdentity exists in the form it does.

package mcpharness

import (
	"context"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/looprig/core/uuid"
	"github.com/looprig/mcp/internal/secrettest"
	"github.com/looprig/mcp/pkg/auth"
	"github.com/looprig/mcp/pkg/client"
	"github.com/looprig/mcp/pkg/transport/stdio"
	"github.com/looprig/mcp/pkg/transport/streamablehttp"
)

// richIdentity returns a BindingIdentity with every digested field set to a
// distinctive non-zero value.
//
// Every field matters: the sensitivity sweep mutates each one in turn and
// demands the digest move, which it can only do reliably if the starting value
// is not already the zero the mutation might collide with.
func richIdentity() BindingIdentity {
	return BindingIdentity{
		Name:              "github",
		Scope:             ScopeSession,
		Loop:              uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		SelectorDigest:    digestSelector(Named("operator", "reviewer")),
		TransportKind:     "stdio",
		RedactedOrigin:    "stdio:///usr/bin/github-mcp",
		Required:          true,
		CapabilityDigest:  digestCapabilities(client.ClientCapabilities{Elicitation: true}),
		FilterDigest:      digestFilter(client.ToolFilter{Allow: []string{"search_issues"}}),
		LimitsDigest:      digestLimits(client.Timeouts{Startup: time.Second}, client.DefaultLimits()),
		CompatDigest:      client.ProfileDefault.Digest(),
		Server:            client.ServerIdentity{Name: "srv", Version: "1.2.3", Title: "Server"},
		ProtocolVersion:   "2025-06-18",
		CatalogGeneration: 4,
		CatalogDigest:     "28a3791f06547176ac6d39a18628782043c3061a2e6c55c15dc21736cd6a763f",
		Tools: []ToolIdentity{
			{
				RawName:            "search_issues",
				ModelName:          "mcp__github__search_issues",
				InputSchemaDigest:  "aaaa791f06547176ac6d39a18628782043c3061a2e6c55c15dc21736cd6a7601",
				OutputSchemaDigest: "bbbb791f06547176ac6d39a18628782043c3061a2e6c55c15dc21736cd6a7602",
			},
			{
				RawName:           "create_issue",
				ModelName:         "mcp__github__create_issue",
				InputSchemaDigest: "cccc791f06547176ac6d39a18628782043c3061a2e6c55c15dc21736cd6a7603",
			},
		},
	}
}

// TestBindingIdentityDigestIsSensitiveToEveryField sweeps BindingIdentity
// reflectively and demands that mutating any field the digest is supposed to
// cover changes it.
//
// The sweep is the point. A hand-written list only tests the fields someone
// remembered; this walks the struct, so a field added to BindingIdentity later
// and forgotten in computeDigest fails here rather than silently dropping out of
// the binding's identity. The exclusion list is the inverse contract — a field
// named there is asserted NOT to matter — so a new field is covered by default
// and can only escape the digest by someone deliberately naming it.
func TestBindingIdentityDigestIsSensitiveToEveryField(t *testing.T) {
	t.Parallel()

	// The fields computeDigest deliberately excludes, with the reason. Anything
	// not named here must move the digest.
	excluded := map[string]string{
		"CatalogGeneration": "an ordinal, not content: see the field's doc",
		"Digest":            "the digest is the output, not an input to itself",
	}
	isExcluded := func(path string) bool {
		clean := strings.ReplaceAll(path, "[0]", "")
		for prefix := range excluded {
			if clean == prefix || strings.HasPrefix(clean, prefix+".") {
				return true
			}
		}
		return false
	}

	base := richIdentity().computeDigest()

	swept := 0
	for _, path := range identityLeafPaths(t, reflect.TypeOf(BindingIdentity{}), "") {
		if isExcluded(path) {
			continue
		}
		t.Run(path, func(t *testing.T) {
			id := richIdentity()
			if !mutateIdentityAt(reflect.ValueOf(&id).Elem(), path) {
				t.Fatalf("could not mutate %s: the sweep is not exercising this field", path)
			}
			if id.computeDigest() == base {
				t.Errorf("mutating %s did not change the binding identity digest: the field is missing from computeDigest", path)
			}
		})
		swept++
	}
	if swept == 0 {
		t.Fatal("the sweep covered no fields and would pass vacuously")
	}
	t.Logf("swept %d field path(s)", swept)
}

// TestExcludedIdentityFieldsDoNotMoveTheDigest is the inverse contract of the
// sweep's exclusion list: a field named there is asserted NOT to be identity, so
// that "excluded" is a claim under test rather than a comment.
func TestExcludedIdentityFieldsDoNotMoveTheDigest(t *testing.T) {
	t.Parallel()

	want := richIdentity().computeDigest()

	id := richIdentity()
	id.CatalogGeneration = 99
	if got := id.computeDigest(); got != want {
		t.Errorf("digest = %s, want %s: the catalog generation ordinal must not be part of the binding identity digest", got, want)
	}
}

// TestBindingIdentityDigestHasNoCollisions is the unambiguity half of the
// digest's contract: no two *different* configurations may encode to the same
// bytes.
//
// It is a table of PAIRS because that property cannot be tested one field at a
// time. The sweep mutates a single field and demands the digest move, which it
// does under any framing at all — change a byte and some byte changes. The bug
// class this test exists for is the opposite shape: the framing itself. Drop the
// length prefix from Str and {Name:"ab", RedactedOrigin:""} and {Name:"a",
// RedactedOrigin:"b"} become the same bytes. Every pair below is configuration
// two bindings genuinely differ on, chosen so that the *only* thing keeping
// their encodings apart is a delimiter or a count.
//
// The pairs are deliberately adjacent-field slides. A slide across a fixed-width
// field (a bool, a count) cannot collide however the strings are framed, so
// those are not the interesting cases and are not here.
func TestBindingIdentityDigestHasNoCollisions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// why records the framing property the pair pins, so a failure says
		// which guarantee was dropped rather than only that two digests met.
		why  string
		a, b func(*BindingIdentity)
	}{
		{
			name: "transport kind and redacted origin slide",
			why:  "Str is length-delimited, so a transport kind cannot borrow its origin's first byte",
			a:    func(id *BindingIdentity) { id.TransportKind, id.RedactedOrigin = "ab", "c" },
			b:    func(id *BindingIdentity) { id.TransportKind, id.RedactedOrigin = "a", "bc" },
		},
		{
			name: "transport kind empty versus origin empty",
			why:  "an empty string is a distinct encoding, not an absence that lets the next field slide up",
			a:    func(id *BindingIdentity) { id.TransportKind, id.RedactedOrigin = "", "x" },
			b:    func(id *BindingIdentity) { id.TransportKind, id.RedactedOrigin = "x", "" },
		},
		{
			name: "server name and version slide",
			why:  "the server identity's three fields are separately delimited",
			a: func(id *BindingIdentity) {
				id.Server = client.ServerIdentity{Name: "srv", Version: "1.2.3", Title: "T"}
			},
			b: func(id *BindingIdentity) {
				id.Server = client.ServerIdentity{Name: "srv1", Version: ".2.3", Title: "T"}
			},
		},
		{
			name: "server version and title slide",
			why:  "the version/title boundary is a delimiter, not a convention",
			a: func(id *BindingIdentity) {
				id.Server = client.ServerIdentity{Name: "srv", Version: "1.0", Title: "X"}
			},
			b: func(id *BindingIdentity) {
				id.Server = client.ServerIdentity{Name: "srv", Version: "1.0X", Title: ""}
			},
		},
		{
			name: "tool raw name and model name slide",
			why:  "a tool's raw name cannot be extended into the name a model sees",
			a:    func(id *BindingIdentity) { id.Tools[0].RawName, id.Tools[0].ModelName = "ab", "c" },
			b:    func(id *BindingIdentity) { id.Tools[0].RawName, id.Tools[0].ModelName = "a", "bc" },
		},
		{
			name: "tool input and output schema digest slide",
			why:  "the schema digests are separately delimited, so an absent output schema cannot be forged by extending the input's",
			a: func(id *BindingIdentity) {
				id.Tools[0].InputSchemaDigest, id.Tools[0].OutputSchemaDigest = "ab", "c"
			},
			b: func(id *BindingIdentity) {
				id.Tools[0].InputSchemaDigest, id.Tools[0].OutputSchemaDigest = "a", "bc"
			},
		},
		{
			name: "tool output schema absent versus empty-adjacent",
			why:  "an output schema a server never sent is a distinct encoding from one whose digest is empty-adjacent",
			a:    func(id *BindingIdentity) { id.Tools[0].OutputSchemaDigest = "" },
			b:    func(id *BindingIdentity) { id.Tools[0].OutputSchemaDigest = "x" },
		},
		{
			name: "catalog digest and protocol version slide",
			why:  "the negotiated protocol cannot run into the catalog digest",
			a:    func(id *BindingIdentity) { id.ProtocolVersion, id.CatalogDigest = "ab", "c" },
			b:    func(id *BindingIdentity) { id.ProtocolVersion, id.CatalogDigest = "a", "bc" },
		},
		{
			name: "binding name and selector digest slide",
			why:  "a binding's name cannot borrow bytes from its visibility digest",
			a:    func(id *BindingIdentity) { id.Name, id.SelectorDigest = "ab", "c" },
			b:    func(id *BindingIdentity) { id.Name, id.SelectorDigest = "a", "bc" },
		},
		{
			name: "one tool versus two tools with concatenated names",
			why:  "the tool list is counted, so two tools cannot be folded into one",
			a: func(id *BindingIdentity) {
				id.Tools = []ToolIdentity{{RawName: "ab"}}
			},
			b: func(id *BindingIdentity) {
				id.Tools = []ToolIdentity{{RawName: "a"}, {RawName: "b"}}
			},
		},
		{
			name: "no tools versus one empty tool",
			why:  "an empty tool list is a distinct encoding from a list holding a zero tool",
			a: func(id *BindingIdentity) {
				id.Tools = nil
			},
			b: func(id *BindingIdentity) {
				id.Tools = []ToolIdentity{{}}
			},
		},
		{
			name: "capability and filter digest slide",
			why:  "the four policy digests are separately delimited",
			a:    func(id *BindingIdentity) { id.CapabilityDigest, id.FilterDigest = "ab", "c" },
			b:    func(id *BindingIdentity) { id.CapabilityDigest, id.FilterDigest = "a", "bc" },
		},
		{
			name: "limits and compat digest slide",
			why:  "the limits/compat boundary is a delimiter",
			a:    func(id *BindingIdentity) { id.LimitsDigest, id.CompatDigest = "ab", "c" },
			b:    func(id *BindingIdentity) { id.LimitsDigest, id.CompatDigest = "a", "bc" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a, b := richIdentity(), richIdentity()
			tt.a(&a)
			tt.b(&b)
			if reflect.DeepEqual(a, b) {
				t.Fatal("the pair is not actually different: the case proves nothing")
			}
			if a.computeDigest() == b.computeDigest() {
				t.Errorf("two different configurations digest the same: %s", tt.why)
			}
		})
	}
}

// TestSubDigestsHaveNoCollisions is the same unambiguity property for the four
// policy digests, whose inputs are structs of their own rather than
// BindingIdentity fields.
func TestSubDigestsHaveNoCollisions(t *testing.T) {
	t.Parallel()

	t.Run("filter allow and deny do not slide", func(t *testing.T) {
		t.Parallel()
		a := digestFilter(client.ToolFilter{Allow: []string{"a", "b"}, Deny: []string{"c"}})
		b := digestFilter(client.ToolFilter{Allow: []string{"a"}, Deny: []string{"b", "c"}})
		if a == b {
			t.Error("a filter's allow and deny sets are counted separately, so a name cannot move between them unnoticed")
		}
	})

	t.Run("filter entry names do not slide", func(t *testing.T) {
		t.Parallel()
		a := digestFilter(client.ToolFilter{Allow: []string{"ab", "c"}})
		b := digestFilter(client.ToolFilter{Allow: []string{"a", "bc"}})
		if a == b {
			t.Error("filter entries are length-delimited, so two names cannot be folded into one")
		}
	})

	t.Run("empty allow is distinct from absent allow", func(t *testing.T) {
		t.Parallel()
		// Not a framing subtlety but a behavioural one: an empty Allow set
		// permits everything (ToolFilter.Permits), so it MUST digest the same as
		// a nil one. This is the pair that must collide.
		a := digestFilter(client.ToolFilter{Allow: []string{}})
		b := digestFilter(client.ToolFilter{})
		if a != b {
			t.Error("an empty Allow set and an absent one permit exactly the same tools, so they must be the same identity")
		}
	})

	t.Run("selector modes do not collide on empty membership", func(t *testing.T) {
		t.Parallel()
		// AllLoops, an ID selector with no ids, and a name selector with no
		// names all have empty membership. Only the mode separates them.
		seen := map[string]string{}
		for _, s := range []struct {
			name string
			sel  LoopSelector
		}{
			{"all", AllLoops()},
			{"ids", Loops()},
			{"names", Named()},
			{"none", LoopSelector{}},
		} {
			d := digestSelector(s.sel)
			if prior, dup := seen[d]; dup {
				t.Errorf("selector %s and %s digest the same: the mode is not part of the selector's identity", s.name, prior)
			}
			seen[d] = s.name
		}
	})

	t.Run("selector ids and names do not slide", func(t *testing.T) {
		t.Parallel()
		a := digestSelector(Named("ab", "c"))
		b := digestSelector(Named("a", "bc"))
		if a == b {
			t.Error("selector names are length-delimited, so two Loop names cannot be folded into one")
		}
	})

	t.Run("timeouts do not slide into limits", func(t *testing.T) {
		t.Parallel()
		// Every value here is fixed-width, so this cannot collide on framing —
		// what it pins is that the two structs are digested at distinct
		// positions rather than as one flat run of integers.
		a := digestLimits(client.Timeouts{Startup: 1}, client.Limits{})
		b := digestLimits(client.Timeouts{}, client.Limits{MaxConcurrentRequests: 1})
		if a == b {
			t.Error("a timeout and a limit occupy distinct positions in the encoding")
		}
	})

	t.Run("domains separate the sub-digests", func(t *testing.T) {
		t.Parallel()
		// Every sub-digest over an all-zero input. Without domain separation
		// these would be four hashes of near-identical short byte strings; with
		// it they cannot collide even when their content does.
		seen := map[string]string{}
		for _, d := range []struct {
			name   string
			digest string
		}{
			{"selector", digestSelector(LoopSelector{})},
			{"capabilities", digestCapabilities(client.ClientCapabilities{})},
			{"filter", digestFilter(client.ToolFilter{})},
			{"limits", digestLimits(client.Timeouts{}, client.Limits{})},
		} {
			if prior, dup := seen[d.digest]; dup {
				t.Errorf("the %s and %s digests collide on empty input: the domains are not separating them", d.name, prior)
			}
			seen[d.digest] = d.name
		}
	})
}

// TestLimitsDigestIsSensitiveToEveryLimit sweeps client.Limits reflectively.
//
// digestLimits writes its fields out by hand — there is no way to digest a
// struct without naming its fields, and naming them is exactly how one gets
// forgotten. Limits has nineteen of them and grows; this is the test that fails
// when the twentieth is added and not digested.
func TestLimitsDigestIsSensitiveToEveryLimit(t *testing.T) {
	t.Parallel()

	base := digestLimits(client.Timeouts{}, client.DefaultLimits())

	swept := 0
	typ := reflect.TypeOf(client.Limits{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		t.Run("Limits."+f.Name, func(t *testing.T) {
			l := client.DefaultLimits()
			reflect.ValueOf(&l).Elem().Field(i).SetInt(reflect.ValueOf(&l).Elem().Field(i).Int() + 1)
			if digestLimits(client.Timeouts{}, l) == base {
				t.Errorf("changing Limits.%s did not change the limits digest: the field is missing from digestLimits", f.Name)
			}
		})
		swept++
	}
	if swept == 0 {
		t.Fatal("the sweep covered no fields and would pass vacuously")
	}
	t.Logf("swept %d limit field(s)", swept)
}

// TestTimeoutsDigestIsSensitiveToEveryTimeout is TestLimitsDigestIsSensitive's
// sibling for Timeouts, and exists for the same reason: the fields are written
// out by hand.
func TestTimeoutsDigestIsSensitiveToEveryTimeout(t *testing.T) {
	t.Parallel()

	base := digestLimits(client.Timeouts{}, client.Limits{})

	swept := 0
	typ := reflect.TypeOf(client.Timeouts{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		t.Run("Timeouts."+f.Name, func(t *testing.T) {
			var to client.Timeouts
			reflect.ValueOf(&to).Elem().Field(i).SetInt(int64(time.Second))
			if digestLimits(to, client.Limits{}) == base {
				t.Errorf("changing Timeouts.%s did not change the limits digest: the field is missing from digestLimits", f.Name)
			}
		})
		swept++
	}
	if swept == 0 {
		t.Fatal("the sweep covered no fields and would pass vacuously")
	}
}

// TestCapabilityDigestIsSensitiveToEveryCapability is the same sweep for
// ClientCapabilities.
func TestCapabilityDigestIsSensitiveToEveryCapability(t *testing.T) {
	t.Parallel()

	base := digestCapabilities(client.ClientCapabilities{})

	swept := 0
	typ := reflect.TypeOf(client.ClientCapabilities{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		t.Run("ClientCapabilities."+f.Name, func(t *testing.T) {
			var c client.ClientCapabilities
			reflect.ValueOf(&c).Elem().Field(i).SetBool(true)
			if digestCapabilities(c) == base {
				t.Errorf("setting ClientCapabilities.%s did not change the capability digest: the field is missing from digestCapabilities", f.Name)
			}
		})
		swept++
	}
	if swept == 0 {
		t.Fatal("the sweep covered no fields and would pass vacuously")
	}
}

// TestSubDigestsAreOrderInsensitive is the determinism property for the sets:
// two configurations that permit the same things are the same configuration
// however they were written.
func TestSubDigestsAreOrderInsensitive(t *testing.T) {
	t.Parallel()

	t.Run("filter", func(t *testing.T) {
		t.Parallel()
		a := digestFilter(client.ToolFilter{Allow: []string{"a", "b", "c"}, Deny: []string{"x", "y"}})
		b := digestFilter(client.ToolFilter{Allow: []string{"c", "a", "b"}, Deny: []string{"y", "x"}})
		if a != b {
			t.Error("a ToolFilter matches by set membership, so the order its entries were written in must not be identity")
		}
	})

	t.Run("filter duplicates", func(t *testing.T) {
		t.Parallel()
		a := digestFilter(client.ToolFilter{Allow: []string{"a", "b"}})
		b := digestFilter(client.ToolFilter{Allow: []string{"a", "b", "b"}})
		if a != b {
			t.Error("a repeated filter entry permits nothing extra, so it must not change identity")
		}
	})

	t.Run("selector names", func(t *testing.T) {
		t.Parallel()
		if digestSelector(Named("a", "b")) != digestSelector(Named("b", "a")) {
			t.Error("a Named selector matches by membership, so its order must not be identity")
		}
	})

	t.Run("selector ids", func(t *testing.T) {
		t.Parallel()
		x := uuid.MustParse("11111111-1111-4111-8111-111111111111")
		y := uuid.MustParse("22222222-2222-4222-8222-222222222222")
		if digestSelector(Loops(x, y)) != digestSelector(Loops(y, x)) {
			t.Error("a Loops selector matches by membership, so its order must not be identity")
		}
	})
}

// TestConfigDigestIsStableUnderBindingOrder is the property ConfigDigest exists
// for: the same configuration digests the same however the application listed
// it. A composition root is free to build its bindings in any order, and a
// restore must not report drift because someone moved a line.
func TestConfigDigestIsStableUnderBindingOrder(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T, bindings []Binding) string {
		t.Helper()
		m, err := NewManager(bindings, testDeps())
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		t.Cleanup(func() { _ = m.Close(context.Background()) })
		return m.ConfigDigest()
	}

	base := []Binding{
		scriptedBinding("alpha", ScopeSession, okTransport("alpha", "one")),
		scriptedBinding("bravo", ScopeSession, okTransport("bravo", "two")),
		scriptedBinding("charlie", ScopeSession, okTransport("charlie", "three")),
		scriptedBinding("delta", ScopeSession, okTransport("delta", "four")),
		scriptedBinding("echo", ScopeSession, okTransport("echo", "five")),
	}
	want := build(t, base)

	for range 8 {
		shuffled := slices.Clone(base)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := build(t, shuffled); got != want {
			t.Fatalf("config digest = %s, want %s: the digest depends on the order the bindings were listed in", got, want)
		}
	}
}

// TestConfigIdentityIsSortedByName pins the order ConfigIdentity reports, which
// a caller rendering it depends on and which ConfigDigest's determinism rests
// on.
func TestConfigIdentityIsSortedByName(t *testing.T) {
	t.Parallel()

	m, err := NewManager([]Binding{
		scriptedBinding("charlie", ScopeSession, okTransport("charlie")),
		scriptedBinding("alpha", ScopeSession, okTransport("alpha")),
		scriptedBinding("bravo", ScopeSession, okTransport("bravo")),
	}, testDeps())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	var names []string
	for _, id := range m.ConfigIdentity() {
		names = append(names, id.Name)
	}
	if want := []string{"alpha", "bravo", "charlie"}; !slices.Equal(names, want) {
		t.Errorf("ConfigIdentity() names = %v, want %v", names, want)
	}
}

// TestConfigDigestIsEmptyWithoutBindings pins the contract
// event.ConfigFingerprint.ExternalCapabilityRev needs: no external capability
// means the empty string, so a session that configures no MCP compares Equal to
// a journal written before the field existed.
func TestConfigDigestIsEmptyWithoutBindings(t *testing.T) {
	t.Parallel()

	m, err := NewManager(nil, testDeps())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	if got := m.ConfigDigest(); got != "" {
		t.Errorf("ConfigDigest() = %q, want \"\": a Manager with no bindings contributes no external capability identity", got)
	}
	if got := m.ConfigIdentity(); len(got) != 0 {
		t.Errorf("ConfigIdentity() = %v, want empty", got)
	}
}

// TestConfigDigestIsNonEmptyWithBindings is the other half of the empty
// contract: a configured Manager must never digest to empty, or "no MCP" and
// "this MCP" would be the same value.
func TestConfigDigestIsNonEmptyWithBindings(t *testing.T) {
	t.Parallel()

	m, err := NewManager([]Binding{
		scriptedBinding("github", ScopeSession, okTransport("github")),
	}, testDeps())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	if got := m.ConfigDigest(); got == "" {
		t.Error("ConfigDigest() is empty for a Manager with a binding: empty must mean \"no external capability\" and nothing else")
	}
}

// TestConfigDigestMovesWithEveryBinding pins that the aggregate covers each
// binding rather than, say, only the first: dropping any one binding must change
// the whole configuration's identity.
func TestConfigDigestMovesWithEveryBinding(t *testing.T) {
	t.Parallel()

	names := []string{"alpha", "bravo", "charlie"}
	build := func(t *testing.T, keep []string) string {
		t.Helper()
		var bindings []Binding
		for _, n := range keep {
			bindings = append(bindings, scriptedBinding(n, ScopeSession, okTransport(n)))
		}
		m, err := NewManager(bindings, testDeps())
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		t.Cleanup(func() { _ = m.Close(context.Background()) })
		return m.ConfigDigest()
	}

	full := build(t, names)
	for _, drop := range names {
		t.Run("without "+drop, func(t *testing.T) {
			kept := slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == drop })
			if build(t, kept) == full {
				t.Errorf("dropping binding %q did not change the config digest", drop)
			}
		})
	}
}

// TestConfigIdentityReportsTheNegotiatedCatalog proves the negotiated half of
// the identity is actually populated from a live connection, and that the digest
// moves when a server's catalog does.
//
// Without it every other test here could pass against an identity that reports
// only what the application declared: the sweep works on a hand-built value, and
// a Manager that never filled Server or Tools in would still digest
// deterministically.
func TestConfigIdentityReportsTheNegotiatedCatalog(t *testing.T) {
	t.Parallel()

	identityFor := func(t *testing.T, tools ...string) BindingIdentity {
		t.Helper()
		b := scriptedBinding("github", ScopeSession, okTransport("github", tools...))
		// Required, so Start waits for discovery. An optional binding is still
		// connecting when Start returns, and its identity would report a zero
		// negotiated half — which is earliness, not drift. See ConfigIdentity.
		b.Required = true
		m, err := NewManager([]Binding{b}, testDeps())
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		t.Cleanup(func() { _ = m.Close(context.Background()) })
		if err := m.Start(context.Background()); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		ids := m.ConfigIdentity()
		if len(ids) != 1 {
			t.Fatalf("ConfigIdentity() returned %d identities, want 1", len(ids))
		}
		return ids[0]
	}

	id := identityFor(t, "search_issues", "create_issue")

	if id.Server.Name == "" {
		t.Error("Server.Name is empty after a successful handshake: the negotiated identity is not being reported")
	}
	if id.ProtocolVersion == "" {
		t.Error("ProtocolVersion is empty after a successful handshake")
	}
	if id.CatalogDigest == "" {
		t.Error("CatalogDigest is empty after discovery")
	}
	if id.CatalogGeneration == 0 {
		t.Error("CatalogGeneration is 0 after discovery")
	}
	if len(id.Tools) != 2 {
		t.Fatalf("Tools = %d, want 2 (the tools the server advertised)", len(id.Tools))
	}
	for _, tool := range id.Tools {
		if tool.RawName == "" || tool.ModelName == "" {
			t.Errorf("tool %+v has an empty name: identity must name a tool both ways", tool)
		}
		if tool.InputSchemaDigest == "" {
			t.Errorf("tool %q has no input schema digest", tool.RawName)
		}
	}

	// A server that drops a tool is a different configuration.
	fewer := identityFor(t, "search_issues")
	if fewer.Digest == id.Digest {
		t.Error("a server that dropped a tool produced the same binding identity digest: the catalog is not part of identity")
	}
}

// TestConfigIdentityReportsTheDeclaredConfiguration pins that the configuration
// half is populated from the Binding — the half that is knowable without a
// server, and the half a restore compares first.
func TestConfigIdentityReportsTheDeclaredConfiguration(t *testing.T) {
	t.Parallel()

	loop := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	m, err := NewManager([]Binding{
		{
			Name:       "shared",
			Scope:      ScopeSession,
			Server:     testDefinition("shared"),
			Visibility: Named("operator"),
			Required:   true,
		},
		{
			Name:   "private",
			Scope:  ScopeLoop,
			Loop:   loop,
			Server: testDefinition("private"),
		},
	}, testDeps())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	ids := m.ConfigIdentity()
	if len(ids) != 2 {
		t.Fatalf("ConfigIdentity() returned %d identities, want 2", len(ids))
	}
	private, shared := ids[0], ids[1]

	if shared.Scope != ScopeSession || !shared.Required {
		t.Errorf("shared identity = %+v: scope and posture must be reported as declared", shared)
	}
	if shared.SelectorDigest == "" {
		t.Error("a session-scoped binding reports no selector digest: its audience is part of its identity")
	}
	if !shared.Loop.IsZero() {
		t.Error("a session-scoped binding reports a Loop: it has no owner Loop")
	}

	if private.Scope != ScopeLoop || private.Loop != loop {
		t.Errorf("private identity = %+v: a loop-scoped binding's owner is its identity", private)
	}
	if private.SelectorDigest != "" {
		t.Error("a loop-scoped binding reports a selector digest: it has no selector")
	}

	for _, id := range ids {
		if id.TransportKind == "" || id.RedactedOrigin == "" {
			t.Errorf("identity %q has no transport identity", id.Name)
		}
		for field, d := range map[string]string{
			"CapabilityDigest": id.CapabilityDigest,
			"FilterDigest":     id.FilterDigest,
			"LimitsDigest":     id.LimitsDigest,
			"CompatDigest":     id.CompatDigest,
			"Digest":           id.Digest,
		} {
			if d == "" {
				t.Errorf("identity %q has an empty %s: every policy digest is always present", id.Name, field)
			}
		}
	}
}

// TestVisibilityIsPartOfIdentity pins the audience as identity. Two Sessions
// with the same servers and different visibility are not the same
// configuration: one shows a server to a Loop that the other does not.
func TestVisibilityIsPartOfIdentity(t *testing.T) {
	t.Parallel()

	digestWith := func(t *testing.T, vis LoopSelector) string {
		t.Helper()
		m, err := NewManager([]Binding{{
			Name:       "shared",
			Scope:      ScopeSession,
			Server:     testDefinition("shared"),
			Visibility: vis,
		}}, testDeps())
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		t.Cleanup(func() { _ = m.Close(context.Background()) })
		return m.ConfigDigest()
	}

	all := digestWith(t, AllLoops())
	one := digestWith(t, Named("operator"))
	other := digestWith(t, Named("reviewer"))

	if all == one || one == other {
		t.Error("changing which Loops may consume a binding did not change the configuration identity")
	}
}

// TestUnsetCompatProfileMatchesTheExplicitDefault pins the resolution
// compatOf performs: "I did not choose a profile" and "I chose the default" are
// the same policy, and an identity that called them different would report drift
// on a configuration nobody changed.
func TestUnsetCompatProfileMatchesTheExplicitDefault(t *testing.T) {
	t.Parallel()

	digestWith := func(t *testing.T, p client.Profile) string {
		t.Helper()
		def := testDefinition("srv")
		def.Compat = p
		m, err := NewManager([]Binding{{
			Name:       "srv",
			Scope:      ScopeSession,
			Server:     def,
			Visibility: AllLoops(),
		}}, testDeps())
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		t.Cleanup(func() { _ = m.Close(context.Background()) })
		return m.ConfigDigest()
	}

	if digestWith(t, client.Profile{}) != digestWith(t, client.ProfileDefault) {
		t.Error("an unset compatibility profile digests differently from the default it resolves to: a restore would report drift on a configuration nobody changed")
	}
	if digestWith(t, client.ProfileDefault) == digestWith(t, client.ProfileLegacy) {
		t.Error("two different compatibility profiles digest the same: the policy is not part of identity")
	}
}

// goldenIdentity is the fixed input TestBindingIdentityDigestIsGolden pins. It
// is a literal, deliberately: it must not move when a fixture elsewhere is
// edited, or the golden constant would be measuring the fixture rather than the
// encoding.
func goldenIdentity() BindingIdentity {
	return BindingIdentity{
		Name:             "github",
		Scope:            ScopeSession,
		Loop:             uuid.UUID{},
		SelectorDigest:   "5e10",
		TransportKind:    "stdio",
		RedactedOrigin:   "stdio:///usr/bin/github-mcp",
		Required:         true,
		CapabilityDigest: "ca9a",
		FilterDigest:     "f117",
		LimitsDigest:     "1131",
		CompatDigest:     "c0a7",
		Server:           client.ServerIdentity{Name: "srv", Version: "1.2.3", Title: "Server"},
		ProtocolVersion:  "2025-06-18",
		// Reported, not digested: the golden would be unaffected by changing it,
		// which TestExcludedIdentityFieldsDoNotMoveTheDigest states outright.
		CatalogGeneration: 4,
		CatalogDigest:     "ca7a",
		Tools: []ToolIdentity{
			{RawName: "search_issues", ModelName: "mcp__github__search_issues", InputSchemaDigest: "1111", OutputSchemaDigest: "2222"},
			{RawName: "create_issue", ModelName: "mcp__github__create_issue", InputSchemaDigest: "3333"},
		},
	}
}

// TestBindingIdentityDigestIsGolden pins the canonical encoding to a known
// answer.
//
// This is the guard the pairwise test structurally cannot be: with every value
// length-delimited, the encoding is already unambiguous, so dropping the field
// tags — or reordering fields, or changing a domain string — makes no two
// configurations collide and no sensitivity or collision test can see it. What
// it does do is silently give existing configurations a new digest, or worse,
// let two builds disagree about the same configuration while
// identitySchemaVersion says they agree.
//
// So this test enforces the contract identitySchemaVersion states: if this
// fails, the encoding changed. That is allowed — but it costs a version bump and
// this constant, together, deliberately. It is not a test to "just update".
func TestBindingIdentityDigestIsGolden(t *testing.T) {
	t.Parallel()

	const want = "aa08cfe9f431598f187f5bec202f211f3bc50325ec3e0415b63aabdcdbf9b5fd"
	if got := goldenIdentity().computeDigest(); got != want {
		t.Errorf("binding identity digest = %s, want %s\n"+
			"The canonical encoding changed. If that was deliberate, bump "+
			"identitySchemaVersion and update this constant in the same change; "+
			"if it was not, the encoding has drifted and every digest an older "+
			"build computed is now wrong.", got, want)
	}
}

// TestConfigDigestIsGolden pins the aggregate's encoding, which the per-binding
// golden does not reach: ConfigDigest has a domain and a framing of its own.
func TestConfigDigestIsGolden(t *testing.T) {
	t.Parallel()

	const want = "55b53f0b46cc411ac1abdc533628d8a4db57e2c202fae09b40187c72c5bc5645"
	// Two bindings, so the count and the per-binding framing are both covered.
	a := goldenIdentity()
	b := goldenIdentity()
	b.Name = "gitlab"
	b.Digest = b.computeDigest()
	a.Digest = a.computeDigest()

	if got := digestConfig([]BindingIdentity{a, b}); got != want {
		t.Errorf("config digest = %s, want %s\n"+
			"The canonical encoding changed. If that was deliberate, bump "+
			"identitySchemaVersion and update this constant in the same change.", got, want)
	}
}

// TestSubDigestsAreGolden pins the four policy encodings. Each has its own
// domain and field order, so each can drift on its own.
func TestSubDigestsAreGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"selector", digestSelector(Named("operator", "reviewer")), "3c134996e17914a102ddddb375f363d0f07bfcd50865fd565b92e9b57b2134bb"},
		{"capabilities", digestCapabilities(client.ClientCapabilities{Elicitation: true, Roots: true}), "7d6210d88c6493a3ca12a82b4d875059ba34099014639efb52481ff509dd5c3d"},
		{"filter", digestFilter(client.ToolFilter{Allow: []string{"search_issues"}, Deny: []string{"delete_repo"}}), "b171cba21fb6d805c167e21f4c5ad6a409f8e86c09a258fc98b60259cffa9a2b"},
		{"limits", digestLimits(client.Timeouts{Startup: time.Second}, client.DefaultLimits()), "f1cdb7d8d460feea75b5366618ee327a0c8d1c7927639e11b6d95b2dbf66cf9b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s digest = %s, want %s\nThe canonical encoding changed; bump identitySchemaVersion if deliberate.", tt.name, tt.got, tt.want)
			}
		})
	}
}

// secretCanary is the string that must not appear in any identity value or reach
// any digest. It is distinctive enough that a substring search for it cannot
// match anything incidental. (events_test.go has its own canary for the event
// surface; these are different exclusion claims about different values.)
const secretCanary = "SUPERSECRET-CANARY-a3f9e2b1c4d7"

// secretBearingBindings returns bindings carrying the secretCanary in every
// secret-bearing input this module has: a stdio child's explicit environment and
// its argv, a static credential header, and an OAuth-shaped HeaderProvider's
// minted token. The secretCanary is also placed in an HTTP endpoint's query string,
// which the transport treats as a credential ("a query string is a place people
// put tokens").
//
// vary distinguishes two otherwise-identical configurations, so the same
// function can build the "same config, different secrets" pair the digest test
// needs.
func secretBearingBindings(t *testing.T, vary string) []Binding {
	t.Helper()

	stdioFactory, err := stdio.New(stdio.Config{
		// A real, resolvable executable: New resolves the command at
		// construction. It is never launched — ConfigIdentity does not dial.
		Command: "/bin/echo",
		Args:    []string{"--token=" + secretCanary + vary},
		Env: stdio.EnvAllowlist{
			Vars: []stdio.Var{
				{Name: "GITHUB_TOKEN", Value: secretCanary + vary},
				{Name: "API_KEY", Value: secretCanary + vary},
			},
			PassThrough: []string{"PATH"},
		},
	})
	if err != nil {
		t.Fatalf("stdio.New() error = %v", err)
	}

	httpFactory, err := streamablehttp.New(streamablehttp.Config{
		Endpoint: "https://mcp.example.test/mcp?access_token=" + secretCanary + vary,
		Headers:  []auth.Header{auth.NewHeader("X-Api-Key", secretCanary+vary)},
		Auth:     canaryProvider{vary: vary},
	})
	if err != nil {
		t.Fatalf("streamablehttp.New() error = %v", err)
	}

	return []Binding{
		{Name: "local", Scope: ScopeSession, Server: client.Definition{Name: "local", Transport: stdioFactory}, Visibility: AllLoops()},
		{Name: "remote", Scope: ScopeSession, Server: client.Definition{Name: "remote", Transport: httpFactory}, Visibility: AllLoops()},
	}
}

// canaryProvider is a HeaderProvider that mints a secretCanary-bearing bearer token,
// standing in for the OAuth provider: what matters to this test is that a live
// credential is reachable through the Definition, not how it was obtained.
type canaryProvider struct{ vary string }

func (p canaryProvider) Headers(context.Context) ([]auth.Header, error) {
	return []auth.Header{auth.NewHeader("Authorization", "Bearer "+secretCanary+p.vary)}, nil
}

// TestConfigIdentityExcludesSecrets is the design's exclusion list under test:
// "credentials, tokens, raw headers, full environment values, resource
// contents, prompt bodies, and tool results are excluded".
//
// It is a secretCanary probe rather than a field review because a review only checks
// the fields someone thought of. The secretCanary is planted in every secret-bearing
// input the module has, and the identity is then attacked with
// internal/secrettest's reflection walker — the adversary the module's
// secret-in-a-closure design is measured against, which reads unexported fields
// and follows pointers. If the secretCanary is anywhere reachable from a
// BindingIdentity, this fails.
func TestConfigIdentityExcludesSecrets(t *testing.T) {
	t.Parallel()

	bindings := secretBearingBindings(t, "")

	// First prove the canary is genuinely THERE, in the bindings the identity is
	// built from. Without this the test is vacuous in the way that matters: an
	// identity derived from configuration that never held a secret trivially
	// leaks none, and would pass while proving nothing about a configuration that
	// does. The walker reads unexported fields and follows pointers, so it
	// reaches into the transport factories the Definitions hold.
	fromBindings := secrettest.Dump(bindings)
	if !strings.Contains(fromBindings, secretCanary) {
		t.Fatal("the canary is not reachable from the bindings: the probe is testing a configuration that holds no secret, and proves nothing")
	}
	if !secrettest.ReachedSecret(fromBindings) {
		t.Fatal("the walker did not reach a secret's hiding place in the bindings: the probe is not exercising the secret-in-a-closure design")
	}

	m, err := NewManager(bindings, testDeps())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	ids := m.ConfigIdentity()
	if len(ids) != 2 {
		t.Fatalf("ConfigIdentity() returned %d identities, want 2", len(ids))
	}

	dumped := secrettest.Dump(ids)
	if strings.Contains(dumped, secretCanary) {
		t.Errorf("a secret reached the configuration identity.\ndump: %s", dumped)
	}
	if strings.Contains(m.ConfigDigest(), secretCanary) {
		t.Error("a secret reached the configuration digest string")
	}

	// The probe must be shown to have actually reached the identity's contents,
	// or it would pass by walking nothing.
	for _, id := range ids {
		if !strings.Contains(dumped, id.Name) || !strings.Contains(dumped, id.Digest) {
			t.Fatalf("the walker did not reach binding %q's fields: the probe proves nothing", id.Name)
		}
	}
}

// TestSecretsDoNotReachTheDigest is the other half of the probe, and it is the
// half that reaches what a dump cannot.
//
// A dump can only inspect what the identity RETAINS. This inspects what the
// digest CONSUMES: two configurations that are identical except for their
// secrets must digest identically. If a credential, an argv token, an
// environment value, or an endpoint's query string had reached the hash, these
// two would differ — the digests are 256 bits, so an accidental collision is not
// a plausible reading of a pass.
func TestSecretsDoNotReachTheDigest(t *testing.T) {
	t.Parallel()

	digestWith := func(t *testing.T, vary string) string {
		t.Helper()
		m, err := NewManager(secretBearingBindings(t, vary), testDeps())
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		t.Cleanup(func() { _ = m.Close(context.Background()) })
		return m.ConfigDigest()
	}

	a := digestWith(t, "-alpha")
	b := digestWith(t, "-bravo")
	if a == "" {
		t.Fatal("the digest is empty: the probe proves nothing")
	}
	if a != b {
		t.Errorf("two configurations that differ only in their secrets digested differently (%s vs %s): a credential is reaching the identity encoding", a, b)
	}
}

// TestSecretProbeCanFail guards the probe itself.
//
// A secretCanary test that cannot fail is worse than no test: it reports safety it
// never checked. This plants the secretCanary somewhere identity DOES cover — a
// binding's redacted origin, which is the value a transport promises never
// contains a credential — and demands the walker find it. If this stops failing
// to find the secretCanary, the probe above has stopped probing.
func TestSecretProbeCanFail(t *testing.T) {
	t.Parallel()

	m, err := NewManager([]Binding{{
		Name:       "leaky",
		Scope:      ScopeSession,
		Server:     client.Definition{Name: "leaky", Transport: fakeTransport{origin: "https://x/?token=" + secretCanary}},
		Visibility: AllLoops(),
	}}, testDeps())
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	if !strings.Contains(secrettest.Dump(m.ConfigIdentity()), secretCanary) {
		t.Fatal("the walker did not find a secretCanary planted in a field the identity demonstrably carries: the secret probe is not probing")
	}
}

// identityLeafPaths enumerates the mutable leaf field paths of a struct type,
// following nested structs, pointers, and the element type of slices. A slice
// leaf is reported both as the slice itself (so "the collection changed" is
// covered) and through its element type (so "one item's field changed" is
// covered).
func identityLeafPaths(t *testing.T, typ reflect.Type, prefix string) []string {
	t.Helper()
	var paths []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		path := f.Name
		if prefix != "" {
			path = prefix + "." + f.Name
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch {
		// uuid.UUID and Scope are named types over arrays/integers: they are
		// leaves, not structures to walk into.
		case ft == reflect.TypeOf(uuid.UUID{}):
			paths = append(paths, path)
		case ft.Kind() == reflect.Struct:
			paths = append(paths, identityLeafPaths(t, ft, path)...)
		case ft.Kind() == reflect.Slice:
			paths = append(paths, path)
			elem := ft.Elem()
			for elem.Kind() == reflect.Pointer {
				elem = elem.Elem()
			}
			if elem.Kind() == reflect.Struct {
				paths = append(paths, identityLeafPaths(t, elem, path+"[0]")...)
			}
		default:
			paths = append(paths, path)
		}
	}
	return paths
}

// mutateIdentityAt changes the value at a dotted path within v, reporting
// whether it managed to. "[0]" selects a slice's first element.
func mutateIdentityAt(v reflect.Value, path string) bool {
	name, rest, _ := strings.Cut(path, ".")
	field, index := name, -1
	if base, ok := strings.CutSuffix(name, "[0]"); ok {
		field, index = base, 0
	}

	fv := v.FieldByName(field)
	if !fv.IsValid() || !fv.CanSet() {
		return false
	}
	if index >= 0 {
		if fv.Len() <= index {
			return false
		}
		fv = fv.Index(index)
	}
	for fv.Kind() == reflect.Pointer {
		if fv.IsNil() {
			return false
		}
		fv = fv.Elem()
	}
	if rest != "" {
		return mutateIdentityAt(fv, rest)
	}
	return mutateLeaf(fv)
}

// mutateLeaf changes a leaf value to something it demonstrably was not.
func mutateLeaf(v reflect.Value) bool {
	if !v.CanSet() {
		return false
	}
	switch {
	case v.Type() == reflect.TypeOf(uuid.UUID{}):
		v.Set(reflect.ValueOf(uuid.MustParse("99999999-9999-4999-8999-999999999999")))
		return true
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(v.String() + "-mutated")
		return true
	case reflect.Bool:
		v.SetBool(!v.Bool())
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(v.Int() + 1)
		return true
	case reflect.Slice:
		// Shrinking is the mutation a slice needs: it proves the collection's
		// length is covered, which a per-element edit does not.
		if v.Len() == 0 {
			return false
		}
		v.Set(v.Slice(0, v.Len()-1))
		return true
	default:
		return false
	}
}
