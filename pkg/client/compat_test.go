package client

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/looprig/mcp/internal/protocol"
)

// TestToleranceSetIsExactlyTheSafeOnes is the load-bearing test of this file.
//
// The design divides deviations into safe and unsafe, and the unsafe ones must
// be impossible rather than merely discouraged. They are impossible here because
// Tolerance is a closed enum that cannot name them — so this asserts the enum's
// declared range, exhaustively. Adding an unsafe member is then a test failure
// at the moment it is written, not a review someone has to remember to do.
func TestToleranceSetIsExactlyTheSafeOnes(t *testing.T) {
	t.Parallel()

	// The design's safe tolerances, and nothing else:
	//   - ignoring an invalid optional output schema, retaining a valid input
	//     schema, and reporting a warning;
	//   - accepting a legacy SSE transport only when explicitly configured;
	//   - normalizing non-provider-compatible display names while preserving raw
	//     names.
	want := map[Tolerance]string{
		TolerateInvalidOutputSchema:      "invalid_output_schema",
		TolerateLegacySSE:                "legacy_sse",
		TolerateDisplayNameNormalization: "display_name_normalization",
	}

	declared := 0
	for tol := TolerateInvalidOutputSchema; tol < toleranceSentinel; tol++ {
		id, ok := want[tol]
		if !ok {
			t.Errorf("Tolerance(%d) (%q) is declared but is not one of the design's safe tolerances.\n"+
				"The unsafe ones — unconstrained arguments, disabled TLS verification, malformed framing, "+
				"retried non-idempotent calls, auth failure as success — must remain unnameable.",
				tol, tol.String())
			continue
		}
		if got := tol.String(); got != id {
			t.Errorf("Tolerance(%d).String() = %q, want %q", tol, got, id)
		}
		declared++
	}
	if declared != len(want) {
		t.Errorf("declared tolerances = %d, want exactly the %d safe ones", declared, len(want))
	}
	for _, tol := range []Tolerance{0, toleranceSentinel, Tolerance(200)} {
		if got := tol.String(); got != "unknown" {
			t.Errorf("Tolerance(%d).String() = %q, want %q", tol, got, "unknown")
		}
		if tol.valid() {
			t.Errorf("Tolerance(%d).valid() = true, want false", tol)
		}
	}
}

// TestShippedProfiles pins what each named profile permits. A profile is
// configuration identity, so a change here is a change to what a recorded
// "default/v1" meant — which must be a deliberate edit with a version bump, not
// a drift.
func TestShippedProfiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		profile Profile
		want    []Tolerance
	}{
		{ProfileStrict, nil},
		{ProfileDefault, []Tolerance{TolerateInvalidOutputSchema, TolerateDisplayNameNormalization}},
		{ProfileLegacy, []Tolerance{TolerateInvalidOutputSchema, TolerateDisplayNameNormalization, TolerateLegacySSE}},
	}
	for _, tt := range tests {
		t.Run(tt.profile.Name, func(t *testing.T) {
			t.Parallel()
			if err := tt.profile.validate(); err != nil {
				t.Fatalf("a shipped profile does not validate: %v", err)
			}
			if !slices.Equal(tt.profile.Tolerances, tt.want) {
				t.Errorf("%s tolerances = %v, want %v", tt.profile, tt.profile.Tolerances, tt.want)
			}
			for tol := TolerateInvalidOutputSchema; tol < toleranceSentinel; tol++ {
				if got, want := tt.profile.Permits(tol), slices.Contains(tt.want, tol); got != want {
					t.Errorf("%s.Permits(%v) = %v, want %v", tt.profile, tol, got, want)
				}
			}
		})
	}

	// The default profile does not quietly enable a legacy transport: a wire
	// protocol is a deliberate choice.
	if ProfileDefault.Permits(TolerateLegacySSE) {
		t.Error("ProfileDefault permits legacy SSE: a binding must not acquire an older wire protocol by default")
	}
	// And strict really is strict.
	for tol := TolerateInvalidOutputSchema; tol < toleranceSentinel; tol++ {
		if ProfileStrict.Permits(tol) {
			t.Errorf("ProfileStrict permits %v", tol)
		}
	}
}

// TestProfileValidation fails closed on anything that would make a profile
// unrecordable or unknown.
func TestProfileValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile Profile
		wantErr bool
	}{
		{"a shipped profile", ProfileDefault, false},
		{"an application's own", Profile{Name: "acme", Version: 3, Tolerances: []Tolerance{TolerateLegacySSE}}, false},
		{"a named profile with no tolerances is strict, not unset", Profile{Name: "mine", Version: 1}, false},
		{"unnamed", Profile{Version: 1}, true},
		{"unversioned", Profile{Name: "mine"}, true},
		{"negative version", Profile{Name: "mine", Version: -1}, true},
		{"over-long name", Profile{Name: strings.Repeat("a", MaxProfileNameBytes+1), Version: 1}, true},
		{"an undeclared tolerance", Profile{Name: "mine", Version: 1, Tolerances: []Tolerance{Tolerance(200)}}, true},
		{"the zero tolerance", Profile{Name: "mine", Version: 1, Tolerances: []Tolerance{0}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.profile.validate(); (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDefinitionRejectsAnInvalidProfile: a profile is configuration, so it is
// checked where configuration is checked — before anything is launched or
// contacted.
func TestDefinitionRejectsAnInvalidProfile(t *testing.T) {
	t.Parallel()

	def := okDefinition(newFakeTransport(okConn()))
	def.Compat = Profile{Name: "mine", Version: 1, Tolerances: []Tolerance{Tolerance(200)}}

	err := def.Validate()
	if class, ok := ClassOf(err); !ok || class != FailureInvalidConfig {
		t.Errorf("Validate() error = %v (class %v), want FailureInvalidConfig", err, class)
	}
	// And Connect refuses it too, without dialing.
	tr := newFakeTransport(okConn())
	def.Transport = tr
	if _, err := Connect(context.Background(), def, Handlers{}); err == nil {
		t.Error("Connect() accepted an invalid compatibility profile")
	}
	if got := tr.connectCalls(); got != 0 {
		t.Errorf("the transport was dialed %d times for an invalid profile, want 0", got)
	}
}

// TestLegacySSERequiresExplicitConfiguration is the design's SSE tolerance,
// enforced rather than documented: the legacy transport is refused unless a
// profile names it.
func TestLegacySSERequiresExplicitConfiguration(t *testing.T) {
	t.Parallel()

	sseTransport := func() *fakeTransport {
		tr := newFakeTransport(okConn())
		tr.kind = "sse"
		tr.origin = "sse://server"
		return tr
	}

	tests := []struct {
		name    string
		profile Profile
		wantErr bool
	}{
		{"the default profile refuses it", ProfileDefault, true},
		{"a strict profile refuses it", ProfileStrict, true},
		{"an unset profile refuses it (the default applies)", Profile{}, true},
		{"the legacy profile permits it", ProfileLegacy, false},
		{"an application's own profile may permit it", Profile{
			Name: "acme", Version: 1, Tolerances: []Tolerance{TolerateLegacySSE},
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr := sseTransport()
			def := okDefinition(tr)
			def.Compat = tt.profile

			err := def.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if class, ok := ClassOf(err); !ok || class != FailureInvalidConfig {
					t.Errorf("Validate() class = %v, want FailureInvalidConfig", class)
				}
				// Refused before anything is contacted.
				if _, err := Connect(context.Background(), def, Handlers{}); err == nil {
					t.Error("Connect() accepted a legacy SSE transport under a profile that forbids it")
				}
				if got := tr.connectCalls(); got != 0 {
					t.Errorf("an SSE transport was dialed %d times under a profile that forbids it, want 0", got)
				}
			}
		})
	}

	// A non-SSE transport is unaffected by the tolerance either way: the gate is
	// about one legacy wire protocol, not about transports in general.
	def := okDefinition(newFakeTransport(okConn()))
	def.Compat = ProfileStrict
	if err := def.Validate(); err != nil {
		t.Errorf("Validate() error = %v for a stdio-shaped transport under a strict profile, want nil", err)
	}
}

// TestProfileDigestIsCanonical: the digest is configuration identity, so it must
// depend on what a profile *is* and not on how it was written.
func TestProfileDigestIsCanonical(t *testing.T) {
	t.Parallel()

	base := Profile{Name: "acme", Version: 2, Tolerances: []Tolerance{
		TolerateInvalidOutputSchema, TolerateDisplayNameNormalization,
	}}

	t.Run("order does not matter", func(t *testing.T) {
		t.Parallel()
		reordered := Profile{Name: "acme", Version: 2, Tolerances: []Tolerance{
			TolerateDisplayNameNormalization, TolerateInvalidOutputSchema,
		}}
		if base.Digest() != reordered.Digest() {
			t.Error("two profiles permitting the same tolerances in a different order have different digests")
		}
	})

	t.Run("duplicates do not matter", func(t *testing.T) {
		t.Parallel()
		dup := Profile{Name: "acme", Version: 2, Tolerances: []Tolerance{
			TolerateInvalidOutputSchema, TolerateInvalidOutputSchema, TolerateDisplayNameNormalization,
		}}
		if base.Digest() != dup.Digest() {
			t.Error("a repeated tolerance changed a profile's digest")
		}
	})

	t.Run("it is deterministic across independent values", func(t *testing.T) {
		t.Parallel()
		// Two separately constructed profiles, not one value digested twice:
		// the claim is that the digest is a function of the policy, and a value
		// compared with itself would prove only that sha256 is a function.
		again := Profile{Name: "acme", Version: 2, Tolerances: []Tolerance{
			TolerateInvalidOutputSchema, TolerateDisplayNameNormalization,
		}}
		if base.Digest() != again.Digest() {
			t.Errorf("Digest() = %q for one profile and %q for an identical one", base.Digest(), again.Digest())
		}
	})
}

// TestProfileDigestIsGolden pins the profile encoding to a known answer.
//
// It is the guard the canonicality and difference tests structurally cannot be:
// with every value length-delimited, no reordering of fields and no change of
// domain string can make two profiles collide, so neither of those tests can see
// an encoding change. What such a change does do is silently give existing
// profiles new digests — and a profile digest is now part of a binding's
// configuration identity (pkg/harness), so a drifted encoding means a restore
// reporting drift on a policy nobody touched.
//
// If this fails, the encoding changed. That is allowed — but it costs a
// profileDigestVersion bump and these constants, together, deliberately. It is
// not a test to "just update".
func TestProfileDigestIsGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile Profile
		want    string
	}{
		{"default", ProfileDefault, "118175c29c30a4606b21d48e21790762c86c71f61de243b0fc1ab61aee10f88f"},
		{"legacy", ProfileLegacy, "826a7612e5f3f8d196507c0c49a8466ff473f314b7408bbe404a50dadcefe408"},
		{"strict", ProfileStrict, "3981209efa03132092dc91ae7fdccfdd475de5d71e86ca1e383e5cd61b449892"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.profile.Digest(); got != tt.want {
				t.Errorf("%s profile digest = %s, want %s\n"+
					"The canonical encoding changed. If that was deliberate, bump "+
					"profileDigestVersion and update this constant in the same change; "+
					"if it was not, the encoding has drifted and every digest an older "+
					"build computed is now wrong.", tt.name, got, tt.want)
			}
		})
	}
}

// TestProfileDigestDistinguishesEveryDifference: two profiles that differ in any
// way a manifest would care about must digest differently. A digest that misses
// a difference reports no drift when a policy changed.
func TestProfileDigestDistinguishesEveryDifference(t *testing.T) {
	t.Parallel()

	base := Profile{Name: "acme", Version: 2, Tolerances: []Tolerance{TolerateInvalidOutputSchema}}

	tests := []struct {
		name  string
		other Profile
	}{
		{"a different name", Profile{Name: "other", Version: 2, Tolerances: base.Tolerances}},
		{"a different version", Profile{Name: "acme", Version: 3, Tolerances: base.Tolerances}},
		{"one more tolerance", Profile{Name: "acme", Version: 2, Tolerances: []Tolerance{
			TolerateInvalidOutputSchema, TolerateLegacySSE,
		}}},
		{"a different tolerance", Profile{Name: "acme", Version: 2, Tolerances: []Tolerance{TolerateLegacySSE}}},
		{"no tolerances", Profile{Name: "acme", Version: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if base.Digest() == tt.other.Digest() {
				t.Errorf("%s did not change the profile digest", tt.name)
			}
		})
	}

	// The shipped profiles are all distinct from each other.
	seen := map[string]string{}
	for _, p := range []Profile{ProfileStrict, ProfileDefault, ProfileLegacy} {
		if other, dup := seen[p.Digest()]; dup {
			t.Errorf("%s and %s share a digest", p, other)
		}
		seen[p.Digest()] = p.String()
	}
}

// TestProfileDigestCarriesNoSecrets: a profile is secret-free by construction —
// a name, a version, and enum values — and the digest is what reaches a
// manifest. This is cheap insurance on both claims.
func TestProfileDigestIsHex(t *testing.T) {
	t.Parallel()

	got := ProfileDefault.Digest()
	if len(got) != 64 {
		t.Errorf("Digest() = %q (%d chars), want 64 hex characters", got, len(got))
	}
	for _, r := range got {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("Digest() = %q, want lowercase hex", got)
		}
	}
}

// TestUnsetProfileBecomesTheDefault: a Definition that names no profile gets
// ProfileDefault, and a *named* profile with no tolerances is a real strict
// policy that must not be silently replaced by it.
func TestUnsetProfileBecomesTheDefault(t *testing.T) {
	t.Parallel()

	t.Run("unset", func(t *testing.T) {
		t.Parallel()
		got := okDefinition(newFakeTransport(okConn())).normalized().Compat
		if got.String() != ProfileDefault.String() {
			t.Errorf("an unset Compat normalized to %s, want %s", got, ProfileDefault)
		}
	})

	t.Run("a named strict profile survives", func(t *testing.T) {
		t.Parallel()
		def := okDefinition(newFakeTransport(okConn()))
		def.Compat = ProfileStrict
		got := def.normalized().Compat
		if got.String() != ProfileStrict.String() {
			t.Errorf("Compat normalized to %s, want the configured %s", got, ProfileStrict)
		}
		if len(got.Tolerances) != 0 {
			t.Errorf("a strict profile gained tolerances: %v", got.Tolerances)
		}
	})

	t.Run("the profile is detached from the caller's slice", func(t *testing.T) {
		t.Parallel()
		tolerances := []Tolerance{TolerateInvalidOutputSchema}
		def := okDefinition(newFakeTransport(okConn()))
		def.Compat = Profile{Name: "mine", Version: 1, Tolerances: tolerances}

		norm := def.normalized()
		// A caller that keeps its slice must not be able to rewrite what was
		// validated — the same rule the ToolFilter follows.
		tolerances[0] = TolerateLegacySSE
		if norm.Compat.Tolerances[0] != TolerateInvalidOutputSchema {
			t.Error("a caller's slice rewrote a normalized Definition's compatibility policy")
		}
	})
}

// TestProfileGovernsDiscovery is the profile doing its job end to end: the same
// server, the same catalog, two profiles, two outcomes.
func TestProfileGovernsDiscovery(t *testing.T) {
	t.Parallel()

	// A server whose tool has a defective optional output schema — the design's
	// first safe tolerance, and the common shape of a real server's imperfection.
	spoiled := func() *fakeConn {
		conn := okConn()
		tool := fakeTool("echo")
		tool.OutputSchemaDefect = "not a JSON object"
		conn.setTools(tool)
		return conn
	}

	t.Run("the default profile tolerates it and reports it", func(t *testing.T) {
		t.Parallel()

		c, err := Connect(context.Background(), okDefinition(newFakeTransport(spoiled())), Handlers{})
		if err != nil {
			t.Fatalf("Connect() error = %v, want the default profile to tolerate the defect", err)
		}
		defer func() { _ = c.Close(context.Background()) }()

		cat := c.Catalog()
		tool, ok := cat.ToolByRawName("echo")
		if !ok {
			t.Fatal("the tool was dropped along with its schema")
		}
		if tool.OutputSchema != nil {
			t.Error("the defective output schema was retained")
		}
		// The input schema — the one that constrains what a model may send — is
		// never widened by a tolerance.
		if len(tool.InputSchema) == 0 {
			t.Error("the input schema was dropped: a compatibility fallback widened the arguments")
		}
		// Reported, per the design: every applied tolerance reaches diagnostics
		// and the binding's catalog identity.
		if !slices.Contains(cat.AppliedTolerances, TolerateInvalidOutputSchema) {
			t.Errorf("Catalog.AppliedTolerances = %v, want it to name the applied tolerance", cat.AppliedTolerances)
		}
		if !hasSubstring(cat.Warnings, "invalid_output_schema") {
			t.Errorf("Catalog.Warnings = %v, want one naming the applied tolerance", cat.Warnings)
		}
		if got := c.Status().CompatProfile; got != ProfileDefault.String() {
			t.Errorf("Status().CompatProfile = %q, want %q", got, ProfileDefault.String())
		}
	})

	t.Run("a strict profile refuses it", func(t *testing.T) {
		t.Parallel()

		def := okDefinition(newFakeTransport(spoiled()))
		def.Compat = ProfileStrict

		c, err := Connect(context.Background(), def, Handlers{})
		if err == nil {
			_ = c.Close(context.Background())
			t.Fatal("Connect() succeeded under a strict profile against a server with a defective schema")
		}
		if class, ok := ClassOf(err); !ok || class != FailureCatalogInvalid {
			t.Errorf("Connect() error = %v (class %v), want FailureCatalogInvalid", err, class)
		}
	})

	t.Run("a faithful server needs no tolerance under either", func(t *testing.T) {
		t.Parallel()

		for _, profile := range []Profile{ProfileDefault, ProfileStrict} {
			def := okDefinition(newFakeTransport(okConn()))
			def.Compat = profile

			c, err := Connect(context.Background(), def, Handlers{})
			if err != nil {
				t.Fatalf("Connect() under %s: error = %v", profile, err)
			}
			if got := c.Catalog().AppliedTolerances; len(got) != 0 {
				t.Errorf("under %s a faithful server reported tolerances %v, want none", profile, got)
			}
			_ = c.Close(context.Background())
		}
	})
}

// TestProfileGovernsNameNormalization: the third safe tolerance, at the client's
// boundary. The raw name is preserved either way — that is what makes
// normalizing safe — and a strict binding refuses rather than renames.
func TestProfileGovernsNameNormalization(t *testing.T) {
	t.Parallel()

	awkward := func() *fakeConn {
		conn := okConn()
		conn.setTools(protocol.ToolSpec{
			RawName:     "search/issues",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		})
		return conn
	}

	t.Run("tolerated", func(t *testing.T) {
		t.Parallel()

		c, err := Connect(context.Background(), okDefinition(newFakeTransport(awkward())), Handlers{})
		if err != nil {
			t.Fatalf("Connect() error = %v", err)
		}
		defer func() { _ = c.Close(context.Background()) }()

		cat := c.Catalog()
		tool, ok := cat.ToolByRawName("search/issues")
		if !ok {
			t.Fatal("the tool is not reachable by the name the server gave it")
		}
		if tool.RawName != "search/issues" {
			t.Errorf("RawName = %q, want the server's own %q", tool.RawName, "search/issues")
		}
		if strings.Contains(tool.ModelName, "/") {
			t.Errorf("ModelName = %q, want a normalized, provider-compatible name", tool.ModelName)
		}
		if !slices.Contains(cat.AppliedTolerances, TolerateDisplayNameNormalization) {
			t.Errorf("Catalog.AppliedTolerances = %v, want it to name the normalization", cat.AppliedTolerances)
		}
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()

		def := okDefinition(newFakeTransport(awkward()))
		def.Compat = ProfileStrict

		c, err := Connect(context.Background(), def, Handlers{})
		if err == nil {
			_ = c.Close(context.Background())
			t.Fatal("Connect() succeeded under a strict profile against a name it would have to normalize")
		}
		if class, ok := ClassOf(err); !ok || class != FailureCatalogInvalid {
			t.Errorf("Connect() error = %v (class %v), want FailureCatalogInvalid", err, class)
		}
	})
}

// hasSubstring reports whether any element contains sub.
func hasSubstring(all []string, sub string) bool {
	for _, s := range all {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
