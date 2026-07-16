// This file is the package's only internal test. It exists to reach the
// unexported sentinel constants that terminate the State and Class const
// blocks — the mechanism that makes an enum's exhaustiveness a compile-adjacent
// fact rather than a hope. Everything else about this package is tested from
// outside, against the exported surface a consumer sees.

package auth

import "testing"

// allStates lists every declared State exactly once. Keep in sync with the
// const block in status.go; TestStateExhaustive proves it is exhaustive by
// comparing its length against stateSentinel, the unexported marker that must
// remain the final const in the block — any state appended before the sentinel
// bumps its value and fails the guard until it is listed here.
var allStates = []State{
	StateAnonymous,
	StateRequired,
	StateAuthenticated,
	StateExpired,
	StateDenied,
	StateFailed,
}

// allClasses lists every declared Class exactly once, under the same contract
// as allStates above.
var allClasses = []Class{
	ClassInvalidConfig,
	ClassNoToken,
	ClassRequired,
	ClassDenied,
	ClassExpired,
	ClassFailed,
}

func TestStateExhaustive(t *testing.T) {
	t.Parallel()

	if got, want := len(allStates), int(stateSentinel-1); got != want {
		t.Fatalf("allStates has %d entries but %d states are declared; list every state", got, want)
	}
	seen := make(map[string]State, len(allStates))
	for _, state := range allStates {
		got := state.String()
		if got == "unknown" {
			t.Errorf("State(%d).String() = %q, want a declared identifier", state, got)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("State(%d) and State(%d) both render %q; identifiers must be unique", prev, state, got)
		}
		seen[got] = state
	}
}

func TestStateSentinelIsNotAState(t *testing.T) {
	t.Parallel()

	if got := stateSentinel.String(); got != "unknown" {
		t.Errorf("stateSentinel.String() = %q, want %q: the sentinel is a marker, not a state", got, "unknown")
	}
}

func TestClassExhaustive(t *testing.T) {
	t.Parallel()

	if got, want := len(allClasses), int(classSentinel-1); got != want {
		t.Fatalf("allClasses has %d entries but %d classes are declared; list every class", got, want)
	}
	seen := make(map[string]Class, len(allClasses))
	for _, class := range allClasses {
		got := class.String()
		if got == "unknown" {
			t.Errorf("Class(%d).String() = %q, want a declared identifier", class, got)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("Class(%d) and Class(%d) both render %q; identifiers must be unique", prev, class, got)
		}
		seen[got] = class
	}
}

func TestClassSentinelIsNotAClass(t *testing.T) {
	t.Parallel()

	if got := classSentinel.String(); got != "unknown" {
		t.Errorf("classSentinel.String() = %q, want %q: the sentinel is a marker, not a class", got, "unknown")
	}
}
