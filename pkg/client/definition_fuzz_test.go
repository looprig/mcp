package client

import (
	"regexp"
	"strings"
	"testing"
)

// namePattern is an independent oracle for the documented Name grammar,
// deliberately expressed as a regexp rather than reusing the byte loop under
// test.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// FuzzNameValidate feeds Name.Validate arbitrary strings: it must never
// panic, and whenever it accepts a value the value must be at most
// MaxNameBytes, match the documented pattern, and validate again.
func FuzzNameValidate(f *testing.F) {
	for _, seed := range []string{
		"",
		"a",
		"7",
		"abc-123_x",
		strings.Repeat("a", MaxNameBytes),
		strings.Repeat("a", MaxNameBytes+1),
		"-abc",
		"_abc",
		"Abc",
		"a b",
		"a.b",
		"sérver",
		"a\x00b",
		"\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if err := Name(s).Validate(); err != nil {
			return
		}
		if len(s) == 0 || len(s) > MaxNameBytes {
			t.Fatalf("Validate accepted %q with length %d, want 1..%d bytes", s, len(s), MaxNameBytes)
		}
		if !namePattern.MatchString(s) {
			t.Fatalf("Validate accepted %q, which does not match %s", s, namePattern)
		}
		if err := Name(s).Validate(); err != nil {
			t.Fatalf("re-validation of accepted %q failed: %v", s, err)
		}
	})
}
