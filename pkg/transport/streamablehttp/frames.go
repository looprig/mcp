// This file bounds an SSE stream.
//
// The bound cannot be a total. A standalone SSE stream is opened once and lives
// as long as the MCP session — hours, carrying every notification the server
// sends — so a cap on the bytes it may carry is not a limit on anything hostile;
// it is a countdown to killing a healthy session. The unit that must be bounded
// is the frame: one event, one JSON-RPC message, one allocation.
//
// So this is a reader that resets its budget at every frame boundary. A server
// may send a million small events and be read forever; a server that sends one
// event that never ends is cut off at the bound, which is the case that would
// otherwise buffer without limit inside the SDK's event scanner.

package streamablehttp

import (
	"io"

	"github.com/looprig/mcp/internal/limits"
)

// frameReader bounds each SSE frame in a stream, independently.
//
// It is a byte filter, not a parser. It does not decode events — the SDK does
// that, downstream — and it deliberately understands only one thing about the
// wire format: where a frame ends. Anything more would be a second, divergent
// implementation of a parser this package already delegates.
//
// The bound is on the frame as it appears on the wire, including its field
// names and its line endings, which slightly over-counts the payload. That is
// the safe direction, and the difference is tens of bytes against a bound of
// megabytes.
type frameReader struct {
	r     io.Reader
	limit int
	diags *diagnostics

	// used is how many bytes of the current frame have been read.
	used int
	// pending is how many line terminators have been seen with nothing but line
	// terminators since. A frame ends at a blank line, which is two in a row.
	pending int
	// afterCR records that the previous byte was a CR, so that an LF following
	// it is recognized as that CR's other half rather than counted as a
	// terminator of its own. Without it, every CRLF reads as a blank line and
	// resets the budget — which would let a server defeat the bound entirely,
	// and would do it on ordinary well-formed traffic rather than only on an
	// attack.
	afterCR bool
	// err is sticky: once a frame overruns, the stream is poisoned and no
	// further data is ever surfaced. A stream that has smuggled one unbounded
	// frame past is not a stream to keep reading.
	err error
}

// newFrameReader returns a reader over r that fails once any single SSE frame
// exceeds limit bytes.
//
// limit must be positive; wireLimits guarantees it. A non-positive bound is not
// "unbounded" anywhere in this module, and here it has no sensible meaning at
// all — it would reject the empty frame.
func newFrameReader(r io.Reader, limit int, d *diagnostics) io.Reader {
	if limit <= 0 {
		// Mirrors limits.BoundedReader: a bound that cannot bound is a
		// programmer error at the call site, and failing loudly here beats
		// rejecting every frame at 3am.
		panic("streamablehttp: frame limit must be positive")
	}
	return &frameReader{r: r, limit: limit, diags: d}
}

// Read passes bytes through, counting them against the current frame's budget
// and resetting that budget at each frame boundary.
//
// It never reads ahead and never buffers: the bytes go straight to the caller,
// and the only state kept is the counter and where the frame delimiter got to.
// That matters for a streaming transport — a reader that buffered a frame to
// measure it would add the very latency SSE exists to avoid, and would have to
// hold the frame it is trying not to hold.
func (f *frameReader) Read(p []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	n, err := f.r.Read(p)
	if n > 0 {
		ok, scanErr := f.scan(p[:n])
		if scanErr != nil {
			f.err = scanErr
			f.diags.recordLimitError(scanErr)
			// Only the bytes still within the frame's budget are surfaced; the
			// rest of this read is dropped on the floor with the stream. The
			// error lands on the next Read, which is limits.BoundedReader's
			// contract — matching it keeps the two interchangeable to a caller,
			// and keeps the promise exact: nothing past the bound is ever
			// handed up, not even the tail of the read that discovered it.
			return ok, nil
		}
	}
	return n, err
}

// scan accounts for one chunk of bytes. It returns how many of them are within
// the current frame's budget, and an error if the frame crossed the bound
// inside this chunk.
//
// When it returns an error, the returned count is where the overrun began: the
// caller surfaces that much and poisons the stream. The state left behind by the
// bytes after it does not matter — the error is sticky, so nothing reads them.
//
// The frame delimiter is a blank line. SSE line terminators are CRLF, LF or a
// bare CR (the HTML spec's event-stream grammar allows all three, and so does
// the SDK's scanner), so this counts terminators rather than matching a literal:
// a CR followed by an LF is one terminator, and two in a row with nothing
// between them is the blank line that ends a frame.
func (f *frameReader) scan(chunk []byte) (int, error) {
	for i := 0; i < len(chunk); i++ {
		terminator := false
		switch chunk[i] {
		case '\r':
			terminator = true
			f.afterCR = true
		case '\n':
			if f.afterCR {
				// The LF completing a CRLF, which is one terminator and was
				// counted with its CR. This is the only reason the flag exists,
				// and it is a field rather than a lookahead because the pair
				// straddles a read whenever the server chooses to flush between
				// them — at which point a lookahead sees nothing and counts two.
				f.afterCR = false
			} else {
				terminator = true
			}
		default:
			f.afterCR = false
			f.pending = 0
		}

		if terminator {
			f.pending++
			if f.pending >= 2 {
				// A blank line: this frame is over, and the next one starts
				// with a fresh budget. This is the only place used is reset,
				// and resetting it is the whole design — see the file comment.
				f.used = 0
				f.pending = 0
				continue
			}
		}

		// Every byte that is part of the current frame is counted, the
		// terminators included. Counting them is the safe direction: a frame is
		// bounded by what it costs to hold, and a line ending costs the same as
		// any other byte.
		f.used++
		if f.used > f.limit {
			return i, &limits.OverLimitError{What: limits.WhatRead, Limit: f.limit}
		}
	}
	return len(chunk), nil
}
