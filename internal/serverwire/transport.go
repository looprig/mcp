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
	if t.max < 1 {
		t.max = 1
	}
	base, err := (&mcp.IOTransport{Reader: t.reader, Writer: t.writer}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	t.base = base
	c := &admissionConn{Connection: base, slots: newSlots(t.max), max: t.max, held: make(map[jsonrpc.ID]struct{}), permits: make(map[jsonrpc.ID]*permit), requests: make(chan jsonrpc.Message, t.max), controls: make(chan jsonrpc.Message, 1), done: make(chan struct{}), stop: make(chan struct{}), released: make(chan struct{}, 1)}
	go c.dispatch()
	return c, nil
}
func (t *boundedTransport) Close() error {
	if t.base != nil {
		return t.base.Close()
	}
	return nil
}

type admissionConn struct {
	mcp.Connection
	slots     chan struct{}
	max       int
	mu        sync.Mutex
	held      map[jsonrpc.ID]struct{}
	permits   map[jsonrpc.ID]*permit
	requests  chan jsonrpc.Message
	controls  chan jsonrpc.Message
	done      chan struct{}
	stop      chan struct{}
	released  chan struct{}
	closeOnce sync.Once
	err       error
}

func (c *admissionConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	select {
	case m := <-c.controls:
		return m, nil
	default:
	}
	select {
	case m := <-c.controls:
		return m, nil
	case m := <-c.requests:
		return m, nil
	case <-c.done:
		c.mu.Lock()
		err := c.err
		c.mu.Unlock()
		if err == nil {
			err = io.EOF
		}
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *admissionConn) Write(ctx context.Context, m jsonrpc.Message) error {
	err := c.Connection.Write(ctx, m)
	if err == nil {
		if resp, ok := m.(*jsonrpc.Response); ok && resp.ID.IsValid() {
			c.mu.Lock()
			if p, held := c.permits[resp.ID]; held {
				delete(c.held, resp.ID)
				delete(c.permits, resp.ID)
				p.release()
			}
			c.mu.Unlock()
		}
	}
	return err
}
func (c *admissionConn) Close() error {
	c.closeOnce.Do(func() { close(c.stop); _ = c.Connection.Close() })
	return nil
}

func (c *admissionConn) dispatch() {
	defer close(c.done)
	for {
		m, err := c.Connection.Read(context.Background())
		if err != nil {
			c.mu.Lock()
			c.err = err
			c.mu.Unlock()
			return
		}
		if req, ok := m.(*jsonrpc.Request); ok && !controlMethod(req.Method) {
			if !c.admit(m) {
				return
			}
			continue
		}
		select {
		case c.controls <- m:
		case <-c.stop:
			return
		}
	}
}

func (c *admissionConn) admit(m jsonrpc.Message) bool {
	for {
		select {
		case <-c.slots:
			select {
			case <-c.released:
			default:
			}
			c.track(m)
			select {
			case c.requests <- m:
				return true
			case <-c.stop:
				return false
			}
		default:
			pending := m
			for {
				nextCh := make(chan readResult, 1)
				go func() { m, err := c.Connection.Read(context.Background()); nextCh <- readResult{m, err} }()
				select {
				case <-c.released:
					select {
					case <-c.slots:
					case <-c.stop:
						return false
					}
					c.track(pending)
					select {
					case c.requests <- pending:
					case <-c.stop:
						return false
					}
					r := <-nextCh
					if r.err != nil {
						c.mu.Lock()
						c.err = r.err
						c.mu.Unlock()
						return false
					}
					if req, ok := r.msg.(*jsonrpc.Request); ok && !controlMethod(req.Method) {
						pending = r.msg
						continue
					}
					select {
					case c.controls <- r.msg:
					case <-c.stop:
						return false
					}
					continue
				case r := <-nextCh:
					if r.err != nil {
						c.mu.Lock()
						c.err = r.err
						c.mu.Unlock()
						return false
					}
					if req, ok := r.msg.(*jsonrpc.Request); ok && !controlMethod(req.Method) {
						select {
						case <-c.released:
						case <-c.stop:
							return false
						}
						select {
						case <-c.slots:
						case <-c.stop:
							return false
						}
						c.track(pending)
						select {
						case c.requests <- pending:
						case <-c.stop:
							return false
						}
						pending = r.msg
						continue
					}
					select {
					case c.controls <- r.msg:
					case <-c.stop:
						return false
					}
				}
			}
		}
	}
}

type readResult struct {
	msg jsonrpc.Message
	err error
}

func newSlots(n int) chan struct{} {
	ch := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		ch <- struct{}{}
	}
	return ch
}

func (c *admissionConn) track(m jsonrpc.Message) {
	if req, ok := m.(*jsonrpc.Request); ok {
		p := &permit{c: c}
		if req.ID.IsValid() {
			c.mu.Lock()
			c.held[req.ID] = struct{}{}
			c.permits[req.ID] = p
			c.mu.Unlock()
		} else {
			req.Extra = &mcp.RequestExtra{CloseSSEStream: func(mcp.CloseSSEStreamArgs) { p.release() }}
		}
	}
}

type permit struct {
	c    *admissionConn
	once sync.Once
}

func (p *permit) release() {
	p.once.Do(func() {
		p.c.slots <- struct{}{}
		select {
		case p.c.released <- struct{}{}:
		default:
		}
	})
}
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
			raw := append([]byte(nil), b...)
			body := b
			if len(body) > 0 && body[len(body)-1] == '\r' {
				body = body[:len(body)-1]
			}
			if len(body) > r.max {
				r.sticky = ErrInputLimit
				return r.sticky
			}
			if err := validateFrame(body, r.idmax); err != nil {
				return err
			}
			r.pending = append(r.pending, raw...)
			return nil
		}
		if x == '\n' {
			raw := append([]byte(nil), b...)
			body := b
			if len(body) > 0 && body[len(body)-1] == '\r' {
				body = body[:len(body)-1]
			}
			if len(body) > r.max {
				r.sticky = ErrInputLimit
				return r.sticky
			}
			if err := validateFrame(body, r.idmax); err != nil {
				r.sticky = err
				return err
			}
			r.pending = append(r.pending, raw...)
			r.pending = append(r.pending, '\n')
			return nil
		}
		b = append(b, x)
		if len(b) > r.max && !(len(b) == r.max+1 && b[len(b)-1] == '\r') {
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
	var canonical any
	switch value := v.(type) {
	case string:
		canonical = value
	case float64:
		canonical = int64(value)
	default:
		return ErrInputEnvelope
	}
	if idmax > 0 {
		var enc bytes.Buffer
		e := json.NewEncoder(&enc)
		e.SetEscapeHTML(false)
		if e.Encode(canonical) != nil {
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
	written, err := w.w.Write(p)
	if err == nil && written != len(p) {
		err = io.ErrShortWrite
	}
	return written, err
}
