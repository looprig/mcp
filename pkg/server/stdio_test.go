package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBoundedFrameReaderRejectsOversizedInput(t *testing.T) {
	t.Parallel()

	r := newBoundedFrameReader(strings.NewReader("123456789\n"), 8)
	buf := make([]byte, 32)
	_, err := io.ReadAll(r)
	if !errors.Is(err, ErrInputLimit) {
		t.Fatalf("ReadAll() error = %v, want ErrInputLimit", err)
	}
	if got := r.limitExceeded(); !got {
		t.Fatal("limitExceeded() = false, want true")
	}
	_ = buf
}

func TestBoundedFrameWriterRejectsOversizedOutputWithoutWriting(t *testing.T) {
	t.Parallel()

	var dst bytes.Buffer
	w := newBoundedFrameWriter(&dst, 8)
	if _, err := w.Write([]byte("123456789\n")); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("Write() error = %v, want ErrOutputLimit", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("destination length = %d, want 0", dst.Len())
	}
}

func TestBoundedFramesExcludeTrailingNewlineFromLimit(t *testing.T) {
	t.Parallel()

	var dst bytes.Buffer
	w := newBoundedFrameWriter(&dst, 8)
	if _, err := w.Write([]byte("12345678\n")); err != nil {
		t.Fatalf("Write() at exact frame limit error = %v", err)
	}
	if _, err := w.Write([]byte("123456789\n")); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("Write() above frame limit error = %v, want ErrOutputLimit", err)
	}

	r := newBoundedFrameReader(strings.NewReader("12345678\n"), 8)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() at exact frame limit error = %v", err)
	}
	if string(got) != "12345678\n" {
		t.Fatalf("ReadAll() = %q, want exact frame", got)
	}
}

func TestServeStdioUsesExplicitStreams(t *testing.T) {
	t.Parallel()

	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.RegisterTool(Tool{Name: "noop", Handler: func(_ context.Context, _ json.RawMessage) (Result, error) {
		return Result{StructuredContent: json.RawMessage(`{"ok":true}`)}, nil
	}}); err != nil {
		t.Fatalf("RegisterTool() error = %v", err)
	}
	if err := s.ServeStdio(context.Background(), strings.NewReader(""), io.Discard); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		t.Fatalf("ServeStdio() error = %v, want stream termination", err)
	}
}

func TestServeCancellationClosesClosableStreams(t *testing.T) {
	t.Parallel()

	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.Serve(ctx, serverConn, serverConn) }()
	cancel()
	select {
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not return after cancellation")
	case err := <-serverErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want cancellation/clean shutdown", err)
		}
	}
}
