package serverwire

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAdmissionSaturationStillDeliversCancellation(t *testing.T) {
	base := newFakeConnection()
	c := &admissionConn{Connection: base, slots: newSlots(8), max: 8, held: make(map[jsonrpc.ID]struct{}), permits: make(map[jsonrpc.ID]*permit), requests: make(chan jsonrpc.Message, 8), controls: make(chan jsonrpc.Message, 1), done: make(chan struct{}), stop: make(chan struct{}), released: make(chan struct{}, 1)}
	go c.dispatch()
	defer c.Close()
	for i := 0; i < 9; i++ {
		id, _ := jsonrpc.MakeID(float64(i + 1))
		base.in <- &jsonrpc.Request{ID: id, Method: "tools/call"}
	}
	for i := 0; i < 8; i++ {
		if _, err := c.Read(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	base.in <- &jsonrpc.Request{Method: "notifications/cancelled"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.(*jsonrpc.Request).Method != "notifications/cancelled" {
		t.Fatalf("got %#v", m)
	}
}

func TestAdmissionCloseUnblocksRead(t *testing.T) {
	base := newFakeConnection()
	c := &admissionConn{Connection: base, slots: newSlots(1), max: 1, held: make(map[jsonrpc.ID]struct{}), permits: make(map[jsonrpc.ID]*permit), requests: make(chan jsonrpc.Message, 1), controls: make(chan jsonrpc.Message, 1), done: make(chan struct{}), stop: make(chan struct{}), released: make(chan struct{}, 1)}
	go c.dispatch()
	got := make(chan error, 1)
	go func() { _, err := c.Read(context.Background()); got <- err }()
	_ = c.Close()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after Close")
	}
}

func TestAdmissionNotificationPermitHeldUntilHandlerCompletion(t *testing.T) {
	base := newFakeConnection()
	c := &admissionConn{Connection: base, slots: newSlots(1), max: 1, held: make(map[jsonrpc.ID]struct{}), permits: make(map[jsonrpc.ID]*permit), requests: make(chan jsonrpc.Message, 1), controls: make(chan jsonrpc.Message, 1), done: make(chan struct{}), stop: make(chan struct{}), released: make(chan struct{}, 1)}
	go c.dispatch()
	defer c.Close()
	base.in <- &jsonrpc.Request{Method: "tools/call"}
	base.in <- &jsonrpc.Request{Method: "tools/call"}
	first, err := c.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	extra, ok := first.(*jsonrpc.Request).Extra.(*mcp.RequestExtra)
	if !ok || extra.CloseSSEStream == nil {
		t.Fatal("missing completion release")
	}
	select {
	case <-c.requests:
		t.Fatal("second notification admitted before first completed")
	case <-time.After(50 * time.Millisecond):
	}
	extra.CloseSSEStream(mcp.CloseSSEStreamArgs{})
	if _, err := c.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionPendingCallIsDeliveredAfterResponseFreesSlot(t *testing.T) {
	base := newFakeConnection()
	c := &admissionConn{Connection: base, slots: newSlots(1), max: 1, held: make(map[jsonrpc.ID]struct{}), permits: make(map[jsonrpc.ID]*permit), requests: make(chan jsonrpc.Message, 1), controls: make(chan jsonrpc.Message, 1), done: make(chan struct{}), stop: make(chan struct{}), released: make(chan struct{}, 1)}
	go c.dispatch()
	defer c.Close()
	id1, _ := jsonrpc.MakeID(float64(1))
	id2, _ := jsonrpc.MakeID(float64(2))
	base.in <- &jsonrpc.Request{ID: id1, Method: "tools/call"}
	base.in <- &jsonrpc.Request{ID: id2, Method: "tools/call"}
	if _, err := c.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	before := len(c.permits)
	c.mu.Unlock()
	if before != 1 {
		t.Fatalf("permits before response=%d", before)
	}
	if err := c.Write(context.Background(), &jsonrpc.Response{ID: id1}); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	held := len(c.permits)
	c.mu.Unlock()
	if held != 0 {
		t.Fatalf("permits after response=%d", held)
	}
	time.Sleep(20 * time.Millisecond)
	if len(c.requests) == 0 {
		t.Fatalf("pending request was not enqueued; released=%d", len(c.released))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.(*jsonrpc.Request).ID != id2 {
		t.Fatalf("got pending request %#v", m)
	}
}

func TestAdmissionDoesNotLoseQueuedCalls(t *testing.T) {
	base := newFakeConnection()
	c := &admissionConn{Connection: base, slots: newSlots(1), max: 1, held: make(map[jsonrpc.ID]struct{}), permits: make(map[jsonrpc.ID]*permit), requests: make(chan jsonrpc.Message, 1), controls: make(chan jsonrpc.Message, 1), done: make(chan struct{}), stop: make(chan struct{}), released: make(chan struct{}, 1)}
	go c.dispatch()
	defer c.Close()
	ids := make([]jsonrpc.ID, 3)
	for i := range ids {
		ids[i], _ = jsonrpc.MakeID(float64(i + 1))
		base.in <- &jsonrpc.Request{ID: ids[i], Method: "tools/call"}
	}
	for i, id := range ids {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		m, err := c.Read(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if m.(*jsonrpc.Request).ID != id {
			t.Fatalf("call %d got id %#v", i, m)
		}
		if err := c.Write(context.Background(), &jsonrpc.Response{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHandlerContextCancelledByServeContext(t *testing.T) {
	a := New(Config{MaxInputBytes: 64, MaxOutputBytes: 64, MaxConcurrentRequests: 1})
	serveCtx, cancel := context.WithCancel(context.Background())
	a.ctx = serveCtx
	started := make(chan struct{})
	stopped := make(chan struct{})
	h := a.handler(func(ctx context.Context, _ json.RawMessage) (Result, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return Result{}, ctx.Err()
	})
	go func() {
		_, _ = h(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{}`)}})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("handler context was not cancelled")
	}
}

type fakeConnection struct {
	in     chan jsonrpc.Message
	closed chan struct{}
	once   sync.Once
}

func newFakeConnection() *fakeConnection {
	return &fakeConnection{in: make(chan jsonrpc.Message, 32), closed: make(chan struct{})}
}
func (f *fakeConnection) Read(context.Context) (jsonrpc.Message, error) {
	select {
	case m := <-f.in:
		return m, nil
	case <-f.closed:
		return nil, io.EOF
	}
}
func (f *fakeConnection) Write(context.Context, jsonrpc.Message) error { return nil }
func (f *fakeConnection) Close() error                                 { f.once.Do(func() { close(f.closed) }); return nil }
func (f *fakeConnection) SessionID() string                            { return "" }

var _ mcp.Connection = (*fakeConnection)(nil)

func TestFrameReaderDelimiterAndEOFBoundaries(t *testing.T) {
	max := 3
	for _, tc := range []struct {
		name, input string
		want        string
		err         error
	}{
		{"lf", "abc\n", "abc\n", nil},
		{"crlf", "abc\r\n", "abc\r\n", nil},
		{"fragmented-crlf", "ab" + "c\r" + "\n", "abc\r\n", nil},
		{"eof", "abc", "abc", nil},
		{"trailing-cr-eof", "abc\r", "abc\r", nil},
		{"over-lf", "abcd\n", "", ErrInputLimit},
		{"over-crlf", "abcd\r\n", "", ErrInputLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewFrameReader(strings.NewReader(tc.input), max)
			got, err := io.ReadAll(r)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err=%v want %v", err, tc.err)
				}
				return
			}
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("err=%v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestFrameWriterShortWriteIsError(t *testing.T) {
	w := NewFrameWriter(shortWriter{}, 64)
	n, err := w.Write([]byte("hello\n"))
	if n != 2 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return 2, nil }

func TestValidateFrameCanonicalNumericIDs(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		wantErr bool
	}{
		{`{"id":1}`, false}, {`{"id":1.9}`, false}, {`{"id":9007199254740993}`, false}, {`{"id":true}`, true}, {`{"id":null}`, true},
	} {
		err := validateFrame([]byte(tc.raw), 32)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s err=%v wantErr=%v", tc.raw, err, tc.wantErr)
		}
	}
}

func TestFrameRejectsUnknownNotificationsBeforeSDK(t *testing.T) {
	for _, raw := range []string{`{"jsonrpc":"2.0","method":"tools/call"}`, `{"jsonrpc":"2.0","method":"notifications/unknown"}`} {
		if err := validateFrame([]byte(raw), 64); !errors.Is(err, ErrInputEnvelope) {
			t.Fatalf("%s err=%v", raw, err)
		}
	}
	for _, raw := range []string{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, `{"jsonrpc":"2.0","method":"notifications/cancelled"}`, `{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}`, `{"jsonrpc":"2.0","method":"notifications/progress"}`} {
		if err := validateFrame([]byte(raw), 64); err != nil {
			t.Fatalf("control %s err=%v", raw, err)
		}
	}
}

func TestAdmissionRejectsDuplicateActiveID(t *testing.T) {
	base := newFakeConnection()
	c := &admissionConn{Connection: base, slots: newSlots(2), max: 2, held: make(map[jsonrpc.ID]struct{}), permits: make(map[jsonrpc.ID]*permit), seen: make(map[jsonrpc.ID]struct{}), requests: make(chan jsonrpc.Message, 2), controls: make(chan jsonrpc.Message, 1), done: make(chan struct{}), stop: make(chan struct{}), released: make(chan struct{}, 1)}
	go c.dispatch()
	defer c.Close()
	id, _ := jsonrpc.MakeID(float64(7))
	base.in <- &jsonrpc.Request{ID: id, Method: "tools/call"}
	base.in <- &jsonrpc.Request{ID: id, Method: "tools/call"}
	if _, err := c.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.Read(ctx); !errors.Is(err, ErrInputEnvelope) {
		t.Fatalf("duplicate err=%v", err)
	}
}

func TestAdmissionPendingCallPrecedesEOF(t *testing.T) {
	base := newFakeConnection()
	c := &admissionConn{Connection: base, slots: newSlots(1), max: 1, held: make(map[jsonrpc.ID]struct{}), permits: make(map[jsonrpc.ID]*permit), seen: make(map[jsonrpc.ID]struct{}), requests: make(chan jsonrpc.Message, 1), controls: make(chan jsonrpc.Message, 1), done: make(chan struct{}), stop: make(chan struct{}), released: make(chan struct{}, 1)}
	go c.dispatch()
	defer c.Close()
	id1, _ := jsonrpc.MakeID(float64(1))
	id2, _ := jsonrpc.MakeID(float64(2))
	base.in <- &jsonrpc.Request{ID: id1, Method: "tools/call"}
	base.in <- &jsonrpc.Request{ID: id2, Method: "tools/call"}
	if _, err := c.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = base.Close()
	_ = c.Write(context.Background(), &jsonrpc.Response{ID: id1})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m, err := c.Read(ctx)
	if err != nil || m.(*jsonrpc.Request).ID != id2 {
		t.Fatalf("pending=%v err=%v", m, err)
	}
	if _, err := c.Read(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF err=%v", err)
	}
}
