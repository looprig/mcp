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

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

	fr := newBoundedFrameReader(reader, s.cfg.MaxMessageBytes)
	fw := newBoundedFrameWriter(writer, s.cfg.MaxMessageBytes)
	frc := &boundedReadCloser{reader: fr, closer: readerCloser(reader)}
	fwc := &boundedWriteCloser{writer: fw, closer: writerCloser(writer)}
	return s.sdk.Run(ctx, &mcp.IOTransport{Reader: frc, Writer: fwc})
}

// Run serves the process's stdin/stdout. It is the convenience entry point
// for a stdio executable; tests and embedded callers should use Serve.
func (s *Server) Run(ctx context.Context) error { return s.Serve(ctx, os.Stdin, os.Stdout) }

// ServeStdio is the explicit-stream spelling used by callers that want to
// make the stdio boundary visible in their composition code.
func (s *Server) ServeStdio(ctx context.Context, reader io.Reader, writer io.Writer) error {
	return s.Serve(ctx, reader, writer)
}

type boundedReadCloser struct {
	reader *boundedFrameReader
	closer io.Closer
}

func (r *boundedReadCloser) Read(p []byte) (int, error) { return r.reader.Read(p) }
func (r *boundedReadCloser) Close() error               { return r.closer.Close() }

type boundedWriteCloser struct {
	writer *boundedFrameWriter
	closer io.Closer
}

func (w *boundedWriteCloser) Write(p []byte) (int, error) { return w.writer.Write(p) }
func (w *boundedWriteCloser) Close() error                { return w.closer.Close() }

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
	var envelope struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(frame, &envelope); err != nil {
		// The SDK owns JSON-RPC parse errors; this seam only rejects valid frames
		// whose echoed identity would violate the response bound.
		return nil
	}
	if len(envelope.ID) > MaxRequestIDBytes {
		return ErrInputEnvelope
	}
	return nil
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
