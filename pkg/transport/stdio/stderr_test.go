// Tests for the bounded stderr capture. The property under test is the one
// that makes it safe to point at an untrusted process: no sequence of writes,
// of any size, grows it past its capacity — and what survives is the end.

package stdio

import (
	"io"
	"strings"
	"sync"
	"testing"
)

func TestRing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		capacity    int
		writes      []string
		wantTail    string
		wantLen     int
		wantDropped int64
	}{
		{
			name:     "empty ring holds nothing",
			capacity: 8,
			wantTail: "",
			wantLen:  0,
		},
		{
			name:     "write under capacity is kept whole",
			capacity: 8,
			writes:   []string{"abc"},
			wantTail: "abc",
			wantLen:  3,
		},
		{
			name:     "write of exactly capacity is kept whole",
			capacity: 4,
			writes:   []string{"abcd"},
			wantTail: "abcd",
			wantLen:  4,
		},
		{
			name:        "write over capacity keeps its own tail",
			capacity:    4,
			writes:      []string{"abcdefg"},
			wantTail:    "defg",
			wantLen:     4,
			wantDropped: 3,
		},
		{
			name:        "writes that overflow drop the oldest",
			capacity:    4,
			writes:      []string{"ab", "cd", "ef"},
			wantTail:    "cdef",
			wantLen:     4,
			wantDropped: 2,
		},
		{
			name:        "a write that wraps the buffer",
			capacity:    5,
			writes:      []string{"abcd", "efg"},
			wantTail:    "cdefg",
			wantLen:     5,
			wantDropped: 2,
		},
		{
			name:        "many wraps",
			capacity:    3,
			writes:      []string{"ab", "cd", "ef", "gh", "ij"},
			wantTail:    "hij",
			wantLen:     3,
			wantDropped: 7,
		},
		{
			name:        "an oversized write displaces everything held",
			capacity:    4,
			writes:      []string{"xy", "abcdef"},
			wantTail:    "cdef",
			wantLen:     4,
			wantDropped: 4, // the 2 held, plus the 2 the write itself lost
		},
		{
			name:     "empty writes change nothing",
			capacity: 4,
			writes:   []string{"ab", "", "cd"},
			wantTail: "abcd",
			wantLen:  4,
		},
		{
			name:     "capacity of one",
			capacity: 1,
			writes:   []string{"abc"},
			wantTail: "c",
			wantLen:  1,
			// 3 written, 1 kept.
			wantDropped: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newRing(tt.capacity)
			for _, w := range tt.writes {
				n, err := r.Write([]byte(w))
				if err != nil {
					t.Fatalf("Write(%q) error = %v", w, err)
				}
				if n != len(w) {
					t.Fatalf("Write(%q) = %d, want %d: a short write would stall the child", w, n, len(w))
				}
			}
			if got := string(r.Tail(tt.capacity)); got != tt.wantTail {
				t.Errorf("Tail() = %q, want %q", got, tt.wantTail)
			}
			if got := r.Len(); got != tt.wantLen {
				t.Errorf("Len() = %d, want %d", got, tt.wantLen)
			}
			if got := r.Len(); got > tt.capacity {
				t.Errorf("Len() = %d exceeds capacity %d", got, tt.capacity)
			}
			if got := r.Dropped(); got != tt.wantDropped {
				t.Errorf("Dropped() = %d, want %d", got, tt.wantDropped)
			}
		})
	}
}

func TestRingTailBounds(t *testing.T) {
	t.Parallel()
	r := newRing(8)
	if _, err := r.Write([]byte("abcdefgh")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	tests := []struct {
		name string
		n    int
		want string
	}{
		{name: "zero", n: 0, want: ""},
		{name: "negative", n: -5, want: ""},
		{name: "part", n: 3, want: "fgh"},
		{name: "all", n: 8, want: "abcdefgh"},
		{name: "more than held", n: 99, want: "abcdefgh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := string(r.Tail(tt.n)); got != tt.want {
				t.Errorf("Tail(%d) = %q, want %q", tt.n, got, tt.want)
			}
		})
	}
}

// TestRingTailOfWrappedBuffer checks the read path across the wrap seam, which
// is the one place the index arithmetic can be wrong without any test noticing.
func TestRingTailOfWrappedBuffer(t *testing.T) {
	t.Parallel()
	r := newRing(6)
	for _, w := range []string{"abcd", "ef", "gh"} {
		if _, err := r.Write([]byte(w)); err != nil {
			t.Fatalf("Write(%q) error = %v", w, err)
		}
	}
	// Held: "cdefgh", starting mid-buffer.
	if got := string(r.Tail(6)); got != "cdefgh" {
		t.Fatalf("Tail(6) = %q, want %q", got, "cdefgh")
	}
	if got := string(r.Tail(2)); got != "gh" {
		t.Errorf("Tail(2) = %q, want %q", got, "gh")
	}
	if got := string(r.Tail(4)); got != "efgh" {
		t.Errorf("Tail(4) = %q, want %q", got, "efgh")
	}
}

// TestRingBoundsAnUnboundedSource is the property that matters: a source that
// never stops cannot make the capture grow.
func TestRingBoundsAnUnboundedSource(t *testing.T) {
	t.Parallel()
	const capacity = 64
	r := newRing(capacity)

	// A megabyte of chatter through the same io.Copy the transport uses.
	src := strings.NewReader(strings.Repeat("noise\n", 1<<17))
	n, err := io.Copy(r, src)
	if err != nil {
		t.Fatalf("io.Copy error = %v", err)
	}
	if r.Len() != capacity {
		t.Errorf("Len() = %d, want the capacity %d", r.Len(), capacity)
	}
	if len(r.Tail(1<<20)) != capacity {
		t.Errorf("Tail() returned %d bytes, want at most the capacity %d", len(r.Tail(1<<20)), capacity)
	}
	if want := n - capacity; r.Dropped() != want {
		t.Errorf("Dropped() = %d, want %d", r.Dropped(), want)
	}
}

// TestRingConcurrentUse: the copier writes while a failure path reads. Run with
// -race, this is the test that says so.
func TestRingConcurrentUse(t *testing.T) {
	t.Parallel()
	r := newRing(32)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if _, err := r.Write([]byte("chatter")); err != nil {
					t.Errorf("Write() error = %v", err)
					return
				}
			}
		}()
	}
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				_ = r.Tail(16)
				_ = r.Len()
				_ = r.Dropped()
			}
		}()
	}
	wg.Wait()

	if r.Len() != 32 {
		t.Errorf("Len() = %d, want the capacity 32", r.Len())
	}
}

func TestNewRingRejectsNonPositiveCapacity(t *testing.T) {
	t.Parallel()
	// A non-positive capacity is unreachable — New rejects a negative
	// StderrLimit and substitutes the default for zero — so the ring treats it
	// as the programmer error it would be.
	defer func() {
		if recover() == nil {
			t.Error("newRing(0) did not panic")
		}
	}()
	newRing(0)
}
