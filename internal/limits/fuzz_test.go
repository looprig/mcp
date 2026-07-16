package limits_test

import (
	"errors"
	"math"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/looprig/mcp/internal/limits"
)

// Valid, programmatically deep JSON must fail a small depth budget and pass
// its exact depth.
func TestCheckJSONDepthDeepDocument(t *testing.T) {
	t.Parallel()
	const depth = 500
	raw := []byte(strings.Repeat("[", depth) + strings.Repeat("]", depth))
	if err := limits.CheckJSONDepth(raw, 3); err == nil {
		t.Error("depth-500 document passed maxDepth 3")
	}
	if err := limits.CheckJSONDepth(raw, depth-1); err == nil {
		t.Error("depth-500 document passed maxDepth 499")
	}
	if err := limits.CheckJSONDepth(raw, depth); err != nil {
		t.Errorf("depth-500 document failed maxDepth 500: %v", err)
	}
}

func FuzzCheckJSONDepth(f *testing.F) {
	f.Add([]byte(`{"a":[{"b":[]}]}`), 4)
	f.Add([]byte(`"a\\\"{["`), 0)
	f.Add([]byte(`{{{{[[[["`), 2)
	f.Add([]byte(strings.Repeat("[", 64)+strings.Repeat("]", 64)), 8)
	f.Add([]byte(nil), 0)
	f.Fuzz(func(t *testing.T, data []byte, d int) {
		err := limits.CheckJSONDepth(data, d) // must never panic
		if err == nil {
			if d < math.MaxInt {
				if err2 := limits.CheckJSONDepth(data, d+1); err2 != nil {
					t.Errorf("not monotone: nil at maxDepth %d but %v at %d", d, err2, d+1)
				}
			}
			return
		}
		var over *limits.OverLimitError
		if !errors.As(err, &over) {
			t.Fatalf("err = %v (%T), want *OverLimitError", err, err)
		}
		if over.What != limits.WhatJSONDepth || over.Limit != d {
			t.Errorf("OverLimitError = %+v, want What=%q Limit=%d", over, limits.WhatJSONDepth, d)
		}
	})
}

func FuzzTruncateText(f *testing.F) {
	f.Add("hello, world", 5)
	f.Add("aé€𝄞", 6)
	f.Add("", 0)
	f.Add(strings.Repeat("x", 100), len(limits.TruncationMarker))
	f.Add("\xff\xfe invalid utf8", 10)
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 {
			return // max < 0 is out of contract
		}
		got, truncated := limits.TruncateText(s, max)
		if len(got) > max {
			t.Errorf("TruncateText(%q, %d) = %q (%d bytes), exceeds max", s, max, got, len(got))
		}
		if !truncated && got != s {
			t.Errorf("truncated=false but output %q differs from input %q", got, s)
		}
		if truncated && len(s) <= max {
			t.Errorf("truncated=true but input already fit (%d bytes <= max %d)", len(s), max)
		}
		if utf8.ValidString(s) && !utf8.ValidString(got) {
			t.Errorf("valid UTF-8 in, invalid out: %q -> %q", s, got)
		}
	})
}
