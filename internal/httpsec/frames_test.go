// Tests for the per-frame bound on an SSE stream.
//
// The two claims that matter pull in opposite directions, which is why both are
// tested here rather than assumed: a stream of many frames must be readable
// without limit (or a healthy session dies at an arbitrary hour), and a single
// frame must not exceed the bound (or a hostile server allocates without
// limit). A reader that only did one of those would look correct in production
// right up until it wasn't.

package httpsec

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/looprig/mcp/internal/limits"
)

// readAll drains r, returning what it read and the error that stopped it.
func readAll(r io.Reader) (string, error) {
	var b strings.Builder
	buf := make([]byte, 64)
	for {
		n, err := r.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return b.String(), nil
			}
			return b.String(), err
		}
	}
}

func TestFrameReader(t *testing.T) {
	t.Parallel()

	// frame builds an SSE event of the given payload size, terminated by the
	// blank line that ends a frame.
	frame := func(n int) string { return "data: " + strings.Repeat("x", n) + "\n\n" }

	tests := []struct {
		name    string
		input   string
		limit   int
		wantErr bool
		// wantSurfaced is how many bytes an erroring stream may hand up before
		// it stops. It is not always the limit: the bound is per frame, so a
		// stream whose third frame overruns has legitimately surfaced the first
		// two in full. It is stated per case rather than derived, so that a
		// reader which quietly started surfacing more has to change a number
		// here to stay green.
		wantSurfaced int
	}{
		{name: "empty stream", input: "", limit: 16},
		{name: "one small frame", input: frame(4), limit: 64},
		{
			name:  "a frame exactly at the bound",
			input: "data: xx\n\n",
			limit: len("data: xx\n"),
		},
		{
			name:         "one oversized frame",
			input:        frame(128),
			limit:        32,
			wantErr:      true,
			wantSurfaced: 32,
		},
		{
			// The claim that a total would break: many frames, far more bytes
			// than the bound between them, none of them individually over it.
			name:  "many frames totalling far more than the bound",
			input: strings.Repeat(frame(8), 500),
			limit: 64,
		},
		{
			// The first frame is complete and within the bound, so it is
			// surfaced in full (16 bytes); the second overruns and is cut at
			// the bound. Per-frame means exactly this.
			name:         "a small frame followed by an oversized one",
			input:        frame(8) + frame(256),
			limit:        64,
			wantErr:      true,
			wantSurfaced: len(frame(8)) + 64,
		},
		{
			name:  "crlf line endings",
			input: "data: hello\r\n\r\n" + "data: world\r\n\r\n",
			limit: 32,
		},
		{
			name:  "bare cr line endings",
			input: "data: hello\r\r" + "data: world\r\r",
			limit: 32,
		},
		{
			name:  "multi-line frame under the bound",
			input: "id: 1\nevent: message\ndata: hello\n\n",
			limit: 64,
		},
		{
			name:         "multi-line frame over the bound",
			input:        "id: 1\nevent: message\ndata: " + strings.Repeat("x", 128) + "\n\n",
			limit:        32,
			wantErr:      true,
			wantSurfaced: 32,
		},
		{
			// A server that never terminates a frame: the case a per-frame bound
			// exists for, and the one a total would also catch — eventually.
			name:         "a frame that never ends",
			input:        strings.Repeat("x", 4096),
			limit:        64,
			wantErr:      true,
			wantSurfaced: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := &Diagnostics{}
			got, err := readAll(NewFrameReader(strings.NewReader(tt.input), tt.limit, d, 0, nil))

			if (err != nil) != tt.wantErr {
				t.Fatalf("read error = %v, wantErr %v (read %d bytes)", err, tt.wantErr, len(got))
			}
			if !tt.wantErr {
				if got != tt.input {
					t.Errorf("the reader altered the stream: got %q, want %q", got, tt.input)
				}
				if d.LimitError() != nil {
					t.Errorf("a stream within its bound recorded a limit error: %v", d.LimitError())
				}
				return
			}

			var over *limits.OverLimitError
			if !errors.As(err, &over) {
				t.Fatalf("error = %v (%T), want *limits.OverLimitError", err, err)
			}
			if over.Limit != tt.limit {
				t.Errorf("OverLimitError.Limit = %d, want %d", over.Limit, tt.limit)
			}
			// Recorded as well as returned: the SDK flattens this error's chain
			// on the way up, so Diagnostics is what classify actually reads.
			if d.LimitError() == nil {
				t.Error("the over-limit read was not recorded in Diagnostics")
			}
			// Nothing beyond what the per-frame bound allows was ever surfaced.
			if len(got) != tt.wantSurfaced {
				t.Errorf("the reader surfaced %d bytes, want %d (bound %d per frame)", len(got), tt.wantSurfaced, tt.limit)
			}
		})
	}
}

// TestFrameReaderErrorIsSticky — once a stream has overrun, it is poisoned. A
// reader that recovered at the next frame boundary would let a server smuggle
// an unbounded frame past and carry on as if nothing had happened.
func TestFrameReaderErrorIsSticky(t *testing.T) {
	t.Parallel()

	r := NewFrameReader(strings.NewReader(strings.Repeat("x", 512)+"\n\ndata: ok\n\n"), 16, &Diagnostics{}, 0, nil)
	if _, err := readAll(r); err == nil {
		t.Fatal("read succeeded past the bound")
	}
	for i := 0; i < 3; i++ {
		var over *limits.OverLimitError
		if _, err := r.Read(make([]byte, 8)); !errors.As(err, &over) {
			t.Fatalf("Read() #%d after the bound = %v, want a sticky *limits.OverLimitError", i+1, err)
		}
	}
}

// TestFrameReaderSplitCRLF is the reason afterCR exists. A CRLF straddling two
// reads must stay one line terminator: counted as two, it reads as the blank
// line that ends a frame, which would reset the budget — letting a server defeat
// the bound by choosing where to flush.
func TestFrameReaderSplitCRLF(t *testing.T) {
	t.Parallel()

	// One frame, well over the bound, whose every CRLF is split across a read.
	body := "data: " + strings.Repeat("x", 256) + "\r\n" + "data: " + strings.Repeat("y", 256) + "\r\n\r\n"
	r := NewFrameReader(&crSplitter{s: body}, 64, &Diagnostics{}, 0, nil)
	if got, err := readAll(r); err == nil {
		t.Errorf("read %d bytes without error; a split CRLF must not reset the frame budget", len(got))
	}
}

// TestFrameReaderCountsEveryByte pins the accounting: a frame is measured by
// the bytes it actually occupies, line terminators included.
//
// The case is chosen to catch the undercount an implementation falls into when
// it treats a CRLF as one counted byte rather than two: 39 raw bytes against a
// bound of 30 must fail, but an implementation skipping the LF of each CRLF
// counts only 26 and lets it through. Every other test here passes either way,
// which is exactly why this one is separate — a 2x undercount is not a rounding
// error, it is the bound being off by double.
func TestFrameReaderCountsEveryByte(t *testing.T) {
	t.Parallel()

	const limit = 30
	// 13 lines of "a\r\n" — 39 bytes, no blank line, so it is all one frame.
	body := strings.Repeat("a\r\n", 13)
	if len(body) <= limit {
		t.Fatalf("the fixture is %d bytes, which does not exceed the %d byte bound", len(body), limit)
	}

	got, err := readAll(NewFrameReader(strings.NewReader(body), limit, &Diagnostics{}, 0, nil))
	if err == nil {
		t.Fatalf("read all %d bytes of a %d byte frame without error; the bound was %d — "+
			"line terminators must be counted", len(got), len(body), limit)
	}
	if len(got) != limit {
		t.Errorf("surfaced %d bytes, want %d", len(got), limit)
	}
}

// crSplitter returns the stream one byte at a time, which is the worst case for
// any reader that has to recognize a two-byte sequence: every pair straddles a
// read boundary.
type crSplitter struct {
	s string
	i int
}

func (c *crSplitter) Read(p []byte) (int, error) {
	if c.i >= len(c.s) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = c.s[c.i]
	c.i++
	return 1, nil
}

func TestNewFrameReaderRejectsANonPositiveBound(t *testing.T) {
	t.Parallel()

	for _, limit := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewFrameReader(_, %d, _) did not panic; a bound that cannot bound is a bug at the call site", limit)
				}
			}()
			NewFrameReader(strings.NewReader(""), limit, &Diagnostics{}, 0, nil)
		}()
	}
}
