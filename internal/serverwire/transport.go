package serverwire

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type readCloser struct {
	io.Reader
	io.Closer
}
type writeCloser struct {
	io.Writer
	io.Closer
}

type boundedTransport struct {
	reader io.ReadCloser
	writer io.WriteCloser
	max    int
	base   mcp.Connection
}

func (t *boundedTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	base, err := (&mcp.IOTransport{Reader: t.reader, Writer: t.writer}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	t.base = base
	return &admissionConn{Connection: base, slots: make(chan struct{}, t.max), max: t.max, held: make(map[jsonrpc.ID]struct{})}, nil
}
func (t *boundedTransport) Close() error {
	if t.base != nil {
		return t.base.Close()
	}
	return nil
}

type admissionConn struct {
	mcp.Connection
	slots chan struct{}
	max   int
	mu    sync.Mutex
	held  map[jsonrpc.ID]struct{}
}

func (c *admissionConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	m, err := c.Connection.Read(ctx)
	if err != nil {
		return nil, err
	}
	if req, ok := m.(*jsonrpc.Request); ok && req.ID.IsValid() && !controlMethod(req.Method) {
		select {
		case c.slots <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if req.ID.IsValid() {
			c.mu.Lock()
			c.held[req.ID] = struct{}{}
			c.mu.Unlock()
		}
	}
	return m, nil
}
func (c *admissionConn) Write(ctx context.Context, m jsonrpc.Message) error {
	err := c.Connection.Write(ctx, m)
	if resp, ok := m.(*jsonrpc.Response); ok && resp.ID.IsValid() {
		c.mu.Lock()
		if _, held := c.held[resp.ID]; held {
			delete(c.held, resp.ID)
			<-c.slots
		}
		c.mu.Unlock()
	}
	return err
}
func (c *admissionConn) Close() error { return c.Connection.Close() }
func controlMethod(method string) bool {
	switch method {
	case "initialize", "ping", "notifications/initialized", "notifications/cancelled", "logging/setLevel":
		return true
	}
	return false
}

type FrameReader struct {
	r       *bufio.Reader
	max     int
	idmax   int
	pending []byte
	sticky  error
}

func NewFrameReader(r io.Reader, max int, idmax ...int) *FrameReader {
	m := 0
	if len(idmax) > 0 {
		m = idmax[0]
	}
	return &FrameReader{r: bufio.NewReader(r), max: max, idmax: m}
}
func (r *FrameReader) Read(p []byte) (int, error) {
	if r.sticky != nil {
		return 0, r.sticky
	}
	if len(r.pending) == 0 {
		if err := r.frame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
func (r *FrameReader) frame() error {
	var b []byte
	for {
		x, e := r.r.ReadByte()
		if e != nil {
			if len(b) == 0 {
				return e
			}
			if err := validateFrame(b, r.idmax); err != nil {
				return err
			}
			r.pending = append(r.pending, b...)
			return nil
		}
		if x == '\n' {
			if err := validateFrame(b, r.idmax); err != nil {
				r.sticky = err
				return err
			}
			r.pending = append(r.pending, b...)
			return nil
		}
		b = append(b, x)
		if len(b) > r.max {
			r.sticky = ErrInputLimit
			return r.sticky
		}
	}
}
func validateFrame(b []byte, idmax int) error {
	t := bytes.TrimSpace(b)
	if len(t) > 0 && t[0] == '[' {
		return ErrBatchUnsupported
	}
	var env map[string]json.RawMessage
	if json.Unmarshal(b, &env) != nil {
		return nil
	}
	raw, ok := env["id"]
	if !ok {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ErrInputEnvelope
	}
	switch v.(type) {
	case string, float64:
	default:
		return ErrInputEnvelope
	}
	if idmax > 0 {
		var enc bytes.Buffer
		e := json.NewEncoder(&enc)
		e.SetEscapeHTML(false)
		if e.Encode(v) != nil {
			return ErrInputEnvelope
		}
		x := bytes.TrimSuffix(enc.Bytes(), []byte{'\n'})
		if len(x) > idmax {
			return ErrInputEnvelope
		}
	}
	return nil
}

type FrameWriter struct {
	mu  sync.Mutex
	w   io.Writer
	max int
}

func NewFrameWriter(w io.Writer, max int) *FrameWriter { return &FrameWriter{w: w, max: max} }
func (w *FrameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	if n > 0 && p[n-1] == '\n' {
		n--
	}
	if n > w.max {
		return 0, ErrOutputLimit
	}
	return w.w.Write(p)
}
