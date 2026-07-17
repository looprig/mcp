package mcpharness

import (
	"testing"

	"github.com/looprig/core/uuid"
)

var (
	loopA = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	loopB = uuid.MustParse("22222222-2222-4222-8222-222222222222")
	loopC = uuid.MustParse("33333333-3333-4333-8333-333333333333")
)

func TestLoopSelectorPermits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector LoopSelector
		loopID   uuid.UUID
		loopName string
		want     bool
	}{
		// The zero selector is the guard the whole type is built around: a
		// Visibility nobody set must reach nothing, not everything.
		{name: "zero selector permits nothing", selector: LoopSelector{}, loopID: loopA, loopName: "researcher", want: false},
		{name: "zero selector permits nothing even for a zero loop", selector: LoopSelector{}, want: false},

		{name: "all permits a named loop", selector: AllLoops(), loopID: loopA, loopName: "researcher", want: true},
		{name: "all permits a loop with no name", selector: AllLoops(), loopID: loopA, want: true},

		{name: "ids permits a listed id", selector: Loops(loopA, loopB), loopID: loopB, loopName: "operator", want: true},
		{name: "ids denies an unlisted id", selector: Loops(loopA, loopB), loopID: loopC, loopName: "operator", want: false},
		// A name must not smuggle a loop past an ID selector, and vice versa:
		// each mode selects on its own identifier and ignores the other.
		{name: "ids ignores the name", selector: Loops(loopA), loopID: loopC, loopName: "researcher", want: false},
		{name: "ids denies the zero id", selector: Loops(loopA), loopName: "researcher", want: false},
		// Absent identity is not identity. Validate rejects a zero entry, but
		// Permits is the authorization decision and must not depend on having
		// been validated first: an unvalidated selector listing the zero UUID
		// would otherwise admit every Loop that has no ID.
		{name: "ids denies the zero id against a zero entry", selector: Loops(uuid.UUID{}), loopName: "researcher", want: false},

		{name: "names permits a listed name", selector: Named("researcher", "operator"), loopID: loopA, loopName: "operator", want: true},
		{name: "names denies an unlisted name", selector: Named("researcher"), loopID: loopA, loopName: "operator", want: false},
		{name: "names is case-sensitive", selector: Named("researcher"), loopID: loopA, loopName: "Researcher", want: false},
		{name: "names ignores the id", selector: Named("researcher"), loopID: loopA, loopName: "operator", want: false},
		{name: "names denies an empty name", selector: Named("researcher"), loopID: loopA, want: false},
		// Absent identity is not identity: an empty name must not match an
		// empty entry that a caller managed to construct.
		{name: "names denies an empty name against an empty entry", selector: LoopSelector{mode: selectNames, names: []string{""}}, loopID: loopA, want: false},

		{name: "empty ids set permits nothing", selector: Loops(), loopID: loopA, loopName: "researcher", want: false},
		{name: "empty names set permits nothing", selector: Named(), loopID: loopA, loopName: "researcher", want: false},
		{name: "unknown mode permits nothing", selector: LoopSelector{mode: selectorMode(200)}, loopID: loopA, loopName: "researcher", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.selector.Permits(tt.loopID, tt.loopName); got != tt.want {
				t.Errorf("Permits(%v, %q) = %v, want %v", tt.loopID, tt.loopName, got, tt.want)
			}
		})
	}
}

// TestLoopSelectorConstructorsCopy proves a selector is immutable against the
// caller's backing array. A selector is an authorization decision; if a caller
// could mutate the set after handing it over, the binding's audience would be
// whatever the caller last wrote, not what it declared.
func TestLoopSelectorConstructorsCopy(t *testing.T) {
	t.Parallel()

	ids := []uuid.UUID{loopA}
	byID := Loops(ids...)
	ids[0] = loopC
	if !byID.Permits(loopA, "") {
		t.Error("Loops: mutating the caller's slice revoked loopA")
	}
	if byID.Permits(loopC, "") {
		t.Error("Loops: mutating the caller's slice admitted loopC")
	}

	names := []string{"researcher"}
	byName := Named(names...)
	names[0] = "operator"
	if !byName.Permits(loopA, "researcher") {
		t.Error("Named: mutating the caller's slice revoked researcher")
	}
	if byName.Permits(loopA, "operator") {
		t.Error("Named: mutating the caller's slice admitted operator")
	}
}

func TestLoopSelectorValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector LoopSelector
		wantErr  bool
	}{
		{name: "all is valid", selector: AllLoops()},
		{name: "ids is valid", selector: Loops(loopA)},
		{name: "names is valid", selector: Named("researcher")},
		{name: "zero selector is rejected", selector: LoopSelector{}, wantErr: true},
		// A selector that can never permit anything is dead configuration, and
		// a connection maintained for nobody is worse than a startup error.
		{name: "empty ids set is rejected", selector: Loops(), wantErr: true},
		{name: "empty names set is rejected", selector: Named(), wantErr: true},
		{name: "zero id entry is rejected", selector: Loops(loopA, uuid.UUID{}), wantErr: true},
		{name: "empty name entry is rejected", selector: Named("researcher", ""), wantErr: true},
		{name: "unknown mode is rejected", selector: LoopSelector{mode: selectorMode(200)}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.selector.validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestLoopSelectorStringIsBounded proves String describes the selector without
// dumping its members: it is a log line, and a selector may list dozens of IDs.
func TestLoopSelectorStringIsBounded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		selector LoopSelector
		want     string
	}{
		{name: "zero", selector: LoopSelector{}, want: "none"},
		{name: "all", selector: AllLoops(), want: "all-loops"},
		{name: "ids", selector: Loops(loopA, loopB), want: "loops(2)"},
		{name: "names", selector: Named("researcher"), want: "named(1)"},
		{name: "unknown", selector: LoopSelector{mode: selectorMode(200)}, want: "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.selector.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}

	if got := Loops(loopA, loopB).String(); got == loopA.String() {
		t.Error("String() rendered a member ID")
	}
	if got := Named("secret-loop").String(); got != "named(1)" {
		t.Errorf("String() = %q, want it to omit the member name", got)
	}
}
