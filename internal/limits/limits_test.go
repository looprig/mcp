package limits_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"

	"github.com/looprig/mcp/internal/limits"
)

func TestOverLimitErrorError(t *testing.T) {
	t.Parallel()
	err := &limits.OverLimitError{What: "read", Limit: 42}
	got := err.Error()
	if !strings.Contains(got, "read") || !strings.Contains(got, "42") {
		t.Errorf("Error() = %q, want it to contain the what and the limit", got)
	}
}

func TestBoundedReader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		max      int
		wrap     func(io.Reader) io.Reader // optional underlying-reader shaping
		want     string                    // bytes readable before EOF/error
		wantOver bool                      // want *OverLimitError from ReadAll
	}{
		{name: "under limit", input: "abc", max: 10, want: "abc"},
		{name: "exactly max then EOF", input: "abcde", max: 5, want: "abcde"},
		{name: "one over limit", input: "abcdef", max: 5, want: "abcde", wantOver: true},
		{name: "far over limit", input: strings.Repeat("x", 100), max: 5, want: "xxxxx", wantOver: true},
		{name: "empty source", input: "", max: 1, want: ""},
		{
			name:  "exact max with data+EOF in one read",
			input: "abcde", max: 5, want: "abcde",
			wrap: iotest.DataErrReader,
		},
		{
			name:  "one-byte-at-a-time over limit",
			input: "abcdef", max: 5, want: "abcde", wantOver: true,
			wrap: iotest.OneByteReader,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var src io.Reader = strings.NewReader(tt.input)
			if tt.wrap != nil {
				src = tt.wrap(src)
			}
			r := limits.BoundedReader(src, tt.max)
			got, err := io.ReadAll(r)
			if string(got) != tt.want {
				t.Errorf("read %q, want %q", got, tt.want)
			}
			var over *limits.OverLimitError
			if tt.wantOver {
				if !errors.As(err, &over) {
					t.Fatalf("err = %v, want *OverLimitError", err)
				}
				if over.What != limits.WhatRead || over.Limit != tt.max {
					t.Errorf("OverLimitError = %+v, want What=%q Limit=%d", over, limits.WhatRead, tt.max)
				}
			} else if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
}

// A read that would cross the boundary returns the allowed remainder first;
// the *OverLimitError arrives on the following Read.
func TestBoundedReaderCrossingReadReturnsRemainderFirst(t *testing.T) {
	t.Parallel()
	r := limits.BoundedReader(strings.NewReader("0123456789"), 5)
	buf := make([]byte, 8)
	n, err := r.Read(buf)
	if n != 5 || err != nil {
		t.Fatalf("first Read = (%d, %v), want (5, nil)", n, err)
	}
	if got := string(buf[:n]); got != "01234" {
		t.Fatalf("first Read data = %q, want %q", got, "01234")
	}
	n, err = r.Read(buf)
	var over *limits.OverLimitError
	if n != 0 || !errors.As(err, &over) {
		t.Fatalf("second Read = (%d, %v), want (0, *OverLimitError)", n, err)
	}
}

func TestBoundedReaderErrorIsSticky(t *testing.T) {
	t.Parallel()
	r := limits.BoundedReader(strings.NewReader("abcdef"), 3)
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("ReadAll err = nil, want *OverLimitError")
	}
	buf := make([]byte, 4)
	for i := 0; i < 3; i++ {
		n, err := r.Read(buf)
		var over *limits.OverLimitError
		if n != 0 || !errors.As(err, &over) {
			t.Fatalf("Read after failure #%d = (%d, %v), want (0, *OverLimitError)", i, n, err)
		}
	}
}

func TestBoundedReaderPropagatesUnderlyingError(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	r := limits.BoundedReader(io.MultiReader(strings.NewReader("ab"), iotest.ErrReader(boom)), 10)
	got, err := io.ReadAll(r)
	if string(got) != "ab" || !errors.Is(err, boom) {
		t.Fatalf("ReadAll = (%q, %v), want (%q, %v)", got, err, "ab", boom)
	}
}

func TestBoundedReaderPanicsOnInvalidMax(t *testing.T) {
	t.Parallel()
	for _, max := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("BoundedReader(r, %d) did not panic", max)
				}
			}()
			limits.BoundedReader(strings.NewReader(""), max)
		}()
	}
}

func TestCheckJSONDepth(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		raw      string
		maxDepth int
		wantErr  bool
	}{
		{name: "empty object depth 1 allowed", raw: `{}`, maxDepth: 1},
		{name: "empty object depth 0 rejected", raw: `{}`, maxDepth: 0, wantErr: true},
		{name: "empty array depth 1 allowed", raw: `[]`, maxDepth: 1},
		{name: "empty array depth 0 rejected", raw: `[]`, maxDepth: 0, wantErr: true},
		{name: "number scalar depth 0", raw: `42`, maxDepth: 0},
		{name: "string scalar depth 0", raw: `"hello"`, maxDepth: 0},
		{name: "bool scalar depth 0", raw: `true`, maxDepth: 0},
		{name: "null scalar depth 0", raw: `null`, maxDepth: 0},
		{name: "empty input", raw: ``, maxDepth: 0},
		{name: "braces inside string ignored", raw: `"a{[["`, maxDepth: 0},
		{name: "escaped quote does not end string", raw: `"a\"{["`, maxDepth: 0},
		{name: "escaped backslash ends escape", raw: `"a\\"`, maxDepth: 0},
		{name: "escaped backslash then real container", raw: `["\\", {}]`, maxDepth: 2},
		{name: "escaped backslash then real container over", raw: `["\\", {}]`, maxDepth: 1, wantErr: true},
		{name: "nested mixed depth 4 allowed", raw: `{"a":[{"b":[]}]}`, maxDepth: 4},
		{name: "nested mixed depth 4 rejected at 3", raw: `{"a":[{"b":[]}]}`, maxDepth: 3, wantErr: true},
		{name: "siblings do not accumulate", raw: `[[],[],[]]`, maxDepth: 2},
		{name: "malformed deep opens still bounded", raw: `{{{{{`, maxDepth: 3, wantErr: true},
		{name: "unclosed string with braces", raw: `"{{{`, maxDepth: 0},
		{name: "unbalanced closers then opens", raw: `]]]{`, maxDepth: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := limits.CheckJSONDepth([]byte(tt.raw), tt.maxDepth)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckJSONDepth(%q, %d) error = %v, wantErr %v", tt.raw, tt.maxDepth, err, tt.wantErr)
			}
			if tt.wantErr {
				var over *limits.OverLimitError
				if !errors.As(err, &over) {
					t.Fatalf("err = %v, want *OverLimitError", err)
				}
				if over.What != limits.WhatJSONDepth || over.Limit != tt.maxDepth {
					t.Errorf("OverLimitError = %+v, want What=%q Limit=%d", over, limits.WhatJSONDepth, tt.maxDepth)
				}
			}
		})
	}
}

func TestCheckJSONDepthDoesNotAllocateProportionally(t *testing.T) {
	// Not parallel: testing.AllocsPerRun forbids parallel tests.
	raw := bytes.Repeat([]byte(`{"a":1}`), 1<<16) // ~448 KiB, shallow
	allocs := testing.AllocsPerRun(5, func() {
		if err := limits.CheckJSONDepth(raw, 8); err != nil {
			t.Fatalf("CheckJSONDepth error = %v", err)
		}
	})
	if allocs > 2 {
		t.Errorf("CheckJSONDepth allocates %v times per run, want O(1)", allocs)
	}
}

func TestTruncateText(t *testing.T) {
	t.Parallel()
	marker := limits.TruncationMarker
	tests := []struct {
		name          string
		s             string
		max           int
		want          string
		wantTruncated bool
	}{
		{name: "shorter than max", s: "abc", max: 100, want: "abc"},
		{name: "exactly max", s: "abcde", max: 5, want: "abcde"},
		{name: "empty input", s: "", max: 0, want: ""},
		{
			name: "one over max",
			s:    strings.Repeat("a", 30), max: 29,
			want: strings.Repeat("a", 29-len(marker)) + marker, wantTruncated: true,
		},
		{
			name: "multibyte cut lands on rune boundary",
			// After the marker, 2 bytes remain for text — that would split
			// the 2-byte é, so the cut backs up and only "a" survives.
			s: "aé" + strings.Repeat("x", 50), max: len(marker) + 2,
			want: "a" + marker, wantTruncated: true,
		},
		{
			name: "max equals marker length hard cuts",
			s:    strings.Repeat("b", 40), max: len(marker),
			want: strings.Repeat("b", len(marker)), wantTruncated: true,
		},
		{
			name: "max below marker length hard cuts",
			s:    "abcdefgh", max: 3,
			want: "abc", wantTruncated: true,
		},
		{
			name: "hard cut respects rune boundary",
			s:    "€€€€", max: 4, // € is 3 bytes; 4 would split the second €
			want: "€", wantTruncated: true,
		},
		{name: "max zero", s: "abc", max: 0, want: "", wantTruncated: true},
		{name: "max negative treated as zero", s: "abc", max: -5, want: "", wantTruncated: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, truncated := limits.TruncateText(tt.s, tt.max)
			if got != tt.want || truncated != tt.wantTruncated {
				t.Fatalf("TruncateText(%q, %d) = (%q, %v), want (%q, %v)",
					tt.s, tt.max, got, truncated, tt.want, tt.wantTruncated)
			}
			// A negative max is documented as equivalent to 0, so the
			// budget the result must respect is max clamped at zero.
			budget := max(tt.max, 0)
			if len(got) > budget {
				t.Errorf("result is %d bytes, exceeds max %d", len(got), budget)
			}
			if !utf8.ValidString(got) {
				t.Errorf("result %q is not valid UTF-8", got)
			}
		})
	}
}
