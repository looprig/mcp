package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
)

// Serve runs the server over stdio-shaped streams. The reader and writer may
// be ordinary io.Reader/io.Writer values; if they also implement io.Closer,
// cancellation closes them so a blocked SDK read is released. A frame is
// newline-delimited, as required by the SDK's stdio transport.
func (s *Server) Serve(ctx context.Context, reader io.Reader, writer io.Writer) error {
	if s == nil {
		return ErrInvalidConfig
	}
	if ctx == nil || reader == nil || writer == nil {
		return errors.New("server: nil serve argument")
	}

	return s.wire.Serve(ctx, &ownedReader{Reader: reader, Closer: readerCloser(reader)}, &ownedWriter{Writer: writer, Closer: writerCloser(writer)})
}

// Run serves the process's stdin/stdout. It is the convenience entry point
// for a stdio executable; tests and embedded callers should use Serve.
func (s *Server) Run(ctx context.Context) error { return s.Serve(ctx, os.Stdin, os.Stdout) }

// ServeStdio is the explicit-stream spelling used by callers that want to
// make the stdio boundary visible in their composition code.
func (s *Server) ServeStdio(ctx context.Context, reader io.Reader, writer io.Writer) error {
	return s.Serve(ctx, reader, writer)
}

type ownedReader struct {
	io.Reader
	io.Closer
}
type ownedWriter struct {
	io.Writer
	io.Closer
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func readerCloser(value io.Reader) io.Closer {
	if closer, ok := value.(io.Closer); ok {
		return closer
	}
	return nopCloser{}
}

func writerCloser(value io.Writer) io.Closer {
	if closer, ok := value.(io.Closer); ok {
		return closer
	}
	return nopCloser{}
}

// boundedFrameReader exposes one or more complete newline-delimited frames
// while refusing a frame whose JSON bytes exceed max. The terminating '\n' is
// not counted. It never buffers more than max+1 bytes from the current frame.
type boundedFrameReader struct {
	reader   io.ByteReader
	max      int
	frame    []byte
	pending  []byte
	sticky   error
	frameErr error
}

func newBoundedFrameReader(reader io.Reader, max int) *boundedFrameReader {
	br := bufio.NewReader(reader)
	return &boundedFrameReader{reader: br, max: max}
}

func (r *boundedFrameReader) Read(p []byte) (int, error) {
	if r.sticky != nil {
		return 0, r.sticky
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		if err := r.readFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	if len(r.pending) == 0 && r.frameErr != nil {
		return n, r.frameErr
	}
	return n, nil
}

func (r *boundedFrameReader) limitExceeded() bool { return errors.Is(r.sticky, ErrInputLimit) }

func (r *boundedFrameReader) readFrame() error {
	r.frame = r.frame[:0]
	for {
		b, err := r.reader.ReadByte()
		if err != nil {
			if len(r.frame) == 0 {
				return err
			}
			r.pending = append(r.pending[:0], r.frame...)
			r.frame = r.frame[:0]
			r.frameErr = err
			return nil
		}
		r.frame = append(r.frame, b)
		if b != '\n' && len(r.frame) > r.max {
			r.sticky = ErrInputLimit
			return r.sticky
		}
		if b != '\n' {
			continue
		}
		if err := validateRequestEnvelope(r.frame[:len(r.frame)-1]); err != nil {
			r.sticky = err
			return err
		}
		r.pending = append(r.pending[:0], r.frame...)
		r.frame = r.frame[:0]
		return nil
	}
}

func validateRequestEnvelope(frame []byte) error {
	trimmed := bytes.TrimSpace(frame)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return ErrBatchUnsupported
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(frame, &envelope); err != nil {
		// The SDK owns JSON-RPC parse errors; this seam only rejects valid frames
		// whose echoed identity would violate the response bound.
		return nil
	}
	rawID, hasID := envelope["id"]
	if !hasID {
		return nil
	}
	var decodedID any
	if err := json.Unmarshal(rawID, &decodedID); err != nil {
		return ErrInputEnvelope
	}
	var canonicalID any
	switch value := decodedID.(type) {
	case string:
		canonicalID = value
	case float64:
		// This mirrors the SDK's jsonrpc2.MakeID conversion before its
		// response encoder writes the echoed ID.
		canonicalID = int64(value)
	default:
		// null, booleans, arrays, and objects are not call IDs for this
		// server. Reject them before a handler can run without a response
		// correlation key.
		return ErrInputEnvelope
	}
	canonical, err := canonicalJSON(canonicalID)
	if err != nil || len(canonical) > MaxRequestIDBytes {
		return ErrInputEnvelope
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// boundedFrameWriter refuses an oversized SDK frame before it reaches the
// process's stdout. The terminating '\n' is not counted. SDK writes are
// serialized, but the mutex also makes this helper safe if it is reused by a
// custom transport.
type boundedFrameWriter struct {
	mu     sync.Mutex
	writer io.Writer
	max    int
}

func newBoundedFrameWriter(writer io.Writer, max int) *boundedFrameWriter {
	return &boundedFrameWriter{writer: writer, max: max}
}

func (w *boundedFrameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	frameBytes := len(p)
	if frameBytes > 0 && p[frameBytes-1] == '\n' {
		frameBytes--
	}
	if frameBytes > w.max {
		return 0, ErrOutputLimit
	}
	n, err := w.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}
