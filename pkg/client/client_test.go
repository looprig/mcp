package client

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/lifecycle"
	"github.com/looprig/mcp/internal/protocol"
)

// mustClass fails unless err is an *Error of class want, bound to binding.
func mustClass(t *testing.T, err error, want FailureClass, binding Name) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("want *Error of class %s, got nil", want)
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %T: %v", err, err)
	}
	if e.Class != want {
		t.Fatalf("Class = %s, want %s (err: %v)", e.Class, want, err)
	}
	if e.Binding != binding {
		t.Errorf("Binding = %q, want %q", e.Binding, binding)
	}
	if e.Op == "" {
		t.Errorf("Op is empty; every returned *Error must name an operation (err: %v)", err)
	}
	return e
}

func TestConnectInvalidDefinition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		def  Definition
	}{
		{name: "empty name", def: Definition{Transport: newFakeTransport(okConn())}},
		{name: "nil transport", def: Definition{Name: "srv"}},
		{name: "negative timeout", def: Definition{
			Name:      "srv",
			Transport: newFakeTransport(okConn()),
			Timeouts:  Timeouts{Startup: -time.Second},
		}},
		{name: "negative limit", def: Definition{
			Name:      "srv",
			Transport: newFakeTransport(okConn()),
			Limits:    Limits{MaxFrameBytes: -1},
		}},
		{name: "duplicate tool filter entry", def: Definition{
			Name:       "srv",
			Transport:  newFakeTransport(okConn()),
			ToolFilter: ToolFilter{Allow: []string{"a", "a"}},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := Connect(context.Background(), tt.def, Handlers{})
			if c != nil {
				t.Errorf("Connect returned a client alongside an error")
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("want *Error, got %T: %v", err, err)
			}
			if e.Class != FailureInvalidConfig {
				t.Fatalf("Class = %s, want %s", e.Class, FailureInvalidConfig)
			}
		})
	}
}

// TestConnectCapabilityWithoutHandler proves the client fails closed rather
// than silently downgrading a capability the application asked for.
func TestConnectCapabilityWithoutHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		caps     ClientCapabilities
		handlers Handlers
		wantText string
	}{
		{
			name:     "elicitation requested with no handler",
			caps:     ClientCapabilities{Elicitation: true},
			wantText: "Elicitation",
		},
		{
			name:     "sampling requested with no handler",
			caps:     ClientCapabilities{Sampling: true},
			wantText: "Sampling",
		},
		{
			name:     "roots requested with no handler",
			caps:     ClientCapabilities{Roots: true},
			wantText: "Roots",
		},
		{
			name:     "one handler present, another missing",
			caps:     ClientCapabilities{Elicitation: true, Sampling: true},
			handlers: Handlers{Elicitation: stubElicitation{}},
			wantText: "Sampling",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr := newFakeTransport(okConn())
			def := okDefinition(tr)
			def.Capabilities = tt.caps

			c, err := Connect(context.Background(), def, tt.handlers)
			if c != nil {
				t.Errorf("Connect returned a client alongside an error")
			}
			e := mustClass(t, err, FailureInvalidConfig, def.Name)
			if !strings.Contains(e.Msg, tt.wantText) {
				t.Errorf("Msg = %q, want it to name %q", e.Msg, tt.wantText)
			}
			if tr.connectCalls() != 0 {
				t.Errorf("transport was contacted despite a configuration error")
			}
		})
	}
}

// TestConnectAdvertisesCapabilities is the security-relevant assertion: a
// capability reaches the wire only when the Definition requests it AND a
// handler is installed.
func TestConnectAdvertisesCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		caps     ClientCapabilities
		handlers Handlers
		want     ClientCapabilities
	}{
		{
			name: "nothing requested, nothing advertised",
		},
		{
			name:     "handlers installed but nothing requested advertises nothing",
			handlers: Handlers{Elicitation: stubElicitation{}, Sampling: stubSampling{}, Roots: stubRoots{}},
		},
		{
			name:     "elicitation requested and handled",
			caps:     ClientCapabilities{Elicitation: true},
			handlers: Handlers{Elicitation: stubElicitation{}},
			want:     ClientCapabilities{Elicitation: true},
		},
		{
			name:     "sampling requested and handled",
			caps:     ClientCapabilities{Sampling: true},
			handlers: Handlers{Sampling: stubSampling{}},
			want:     ClientCapabilities{Sampling: true},
		},
		{
			name:     "roots requested and handled",
			caps:     ClientCapabilities{Roots: true},
			handlers: Handlers{Roots: stubRoots{}},
			want:     ClientCapabilities{Roots: true},
		},
		{
			name:     "all three requested and handled",
			caps:     ClientCapabilities{Elicitation: true, Sampling: true, Roots: true},
			handlers: Handlers{Elicitation: stubElicitation{}, Sampling: stubSampling{}, Roots: stubRoots{}},
			want:     ClientCapabilities{Elicitation: true, Sampling: true, Roots: true},
		},
		{
			name:     "surplus handlers do not widen what is requested",
			caps:     ClientCapabilities{Roots: true},
			handlers: Handlers{Elicitation: stubElicitation{}, Sampling: stubSampling{}, Roots: stubRoots{}},
			want:     ClientCapabilities{Roots: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr := newFakeTransport(okConn())
			def := okDefinition(tr)
			def.Capabilities = tt.caps

			c, err := Connect(context.Background(), def, tt.handlers)
			if err != nil {
				t.Fatalf("Connect() error = %v", err)
			}
			t.Cleanup(func() { _ = c.Close(context.Background()) })

			got := tr.lastConfig().Capabilities
			if got.Elicitation != tt.want.Elicitation ||
				got.Sampling != tt.want.Sampling ||
				got.Roots != tt.want.Roots {
				t.Errorf("advertised capabilities = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestConnectConnectConfig checks the rest of what a transport is handed:
// client identity and the bounds derived from the normalized Limits.
func TestConnectConnectConfig(t *testing.T) {
	t.Parallel()

	tr := newFakeTransport(okConn())
	def := okDefinition(tr)
	def.Limits.MaxTextResultBytes = 4096

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	cfg := tr.lastConfig()
	if cfg.Client.Name != ClientName {
		t.Errorf("Client.Name = %q, want %q", cfg.Client.Name, ClientName)
	}
	if cfg.Client.Version != ClientVersion {
		t.Errorf("Client.Version = %q, want %q", cfg.Client.Version, ClientVersion)
	}
	if cfg.Bounds.MaxTextBytes != 4096 {
		t.Errorf("Bounds.MaxTextBytes = %d, want 4096 (from Limits)", cfg.Bounds.MaxTextBytes)
	}
	// Zero Limits fields must arrive as defaults, never as zero (which would
	// mean "reject everything" downstream).
	d := DefaultLimits()
	if cfg.Bounds.MaxSchemaBytes != d.MaxSchemaBytes {
		t.Errorf("Bounds.MaxSchemaBytes = %d, want the default %d", cfg.Bounds.MaxSchemaBytes, d.MaxSchemaBytes)
	}
	if cfg.Bounds.MaxSchemaDepth != d.MaxSchemaDepth {
		t.Errorf("Bounds.MaxSchemaDepth = %d, want the default %d", cfg.Bounds.MaxSchemaDepth, d.MaxSchemaDepth)
	}
	if cfg.Bounds.MaxBinaryItems != d.MaxBinaryItems {
		t.Errorf("Bounds.MaxBinaryItems = %d, want the default %d", cfg.Bounds.MaxBinaryItems, d.MaxBinaryItems)
	}
}

func TestConnectHappyPath(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)
	def := okDefinition(tr)

	c, err := Connect(context.Background(), def, Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	got := c.Status()
	want := Status{
		Binding:         "srv",
		State:           StateReady,
		ProtocolVersion: "2025-06-18",
		Server:          ServerIdentity{Name: "srv", Version: "1.2.3", Title: "Test Server"},
		TransportKind:   "fake",
		RedactedOrigin:  "fake://server",
		// A ready binding has adopted its first catalog, so Status reports it.
		CatalogGeneration: 1,
		CatalogDigest:     c.Catalog().Digest,
		// A Definition that names no profile gets the default one.
		CompatProfile: ProfileDefault.String(),
	}
	want.LastChange = got.LastChange
	if want.CatalogDigest == "" {
		t.Error("a ready binding reports no catalog digest")
	}
	if got.Failure != nil {
		t.Errorf("Failure = %+v, want nil on a healthy binding", got.Failure)
	}
	// DeepEqual, not ==: Status carries a slice (StaleFamilies) and so is not
	// comparable. A ready binding's is nil, which this covers.
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Status() = %+v, want %+v", got, want)
	}
	if got.LastChange.IsZero() {
		t.Errorf("Status().LastChange is zero, want the time of the last transition")
	}
	if conn.inits.Load() != 1 {
		t.Errorf("Initialize called %d times, want 1", conn.inits.Load())
	}
	if conn.closeCount() != 0 {
		t.Errorf("conn closed %d times during a successful Connect, want 0", conn.closeCount())
	}
}

func TestConnectTransportError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want FailureClass
	}{
		{
			name: "plain error is classified as transport closed",
			err:  errors.New("dial failed"),
			want: FailureTransportClosed,
		},
		{
			name: "already-typed error is propagated unchanged",
			err:  NewError(FailureAuthRequired, "srv", "connect", "token missing", nil),
			want: FailureAuthRequired,
		},
		{
			name: "typed remote error is propagated unchanged",
			err:  NewError(FailureRemoteHTTP, "srv", "connect", "502", nil),
			want: FailureRemoteHTTP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := okConn()
			tr := newFakeTransport(conn)
			tr.err = tt.err
			def := okDefinition(tr)

			c, err := Connect(context.Background(), def, Handlers{})
			if c != nil {
				t.Errorf("Connect returned a client alongside an error")
			}
			mustClass(t, err, tt.want, def.Name)
			if conn.closeCount() != 0 {
				t.Errorf("conn closed %d times, want 0: no conn was ever handed over", conn.closeCount())
			}
		})
	}
}

// TestConnectTransportReturnsNilConn covers a transport that violates its
// contract by reporting success with no connection. Both nils must become a
// classified error rather than a panic out of Connect.
func TestConnectTransportReturnsNilConn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		untypedNil bool
	}{
		{name: "untyped nil conn", untypedNil: true},
		{name: "typed nil conn", untypedNil: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr := newFakeTransport(nil)
			tr.untypedNil = tt.untypedNil
			def := okDefinition(tr)

			c, err := Connect(context.Background(), def, Handlers{})
			if c != nil {
				t.Errorf("Connect returned a client alongside an error")
			}
			mustClass(t, err, FailureTransportClosed, def.Name)
		})
	}
}

// TestConnectShutdownOvertakesStartup drives the one path where startup is
// interrupted by a legal, concurrent transition rather than by a failure of its
// own: the machine is closed while the handshake is in flight, so the final
// transition to ready is refused.
//
// The established conn must still be closed. Connect returns no Client on this
// path, so a conn left open is owned by nobody and can never be reclaimed.
// Connect cannot be used to reach this — a Client does not escape until it is
// ready — so the sequence is driven directly, exactly as the machine's own
// contract says a concurrent Close would drive it.
func TestConnectShutdownOvertakesStartup(t *testing.T) {
	t.Parallel()

	conn := okConn()
	c := newClient(okDefinition(newFakeTransport(conn)).normalized(), Handlers{})

	// Close the machine while the handshake is in flight, which is what a
	// concurrent Close does.
	conn.beforeInit = func() {
		if err := c.machine.To(lifecycle.StateClosing); err != nil {
			t.Errorf("moving the machine to closing: %v", err)
		}
	}

	err := c.start(context.Background(), protocol.ClientCapabilities{})
	mustClass(t, err, FailureShutdown, "srv")

	if got := conn.closeCount(); got != 1 {
		t.Errorf("conn closed %d times after shutdown overtook startup, want exactly 1: "+
			"Connect returns no client on this path, so an unclosed conn is unreachable forever", got)
	}
	if got := c.Status().State; got != StateClosing {
		t.Errorf("State = %s, want %s: the overtaking transition must stand", got, StateClosing)
	}
	if got := c.Status().Failure; got == nil || got.Class != FailureShutdown {
		t.Errorf("Failure = %+v, want a recorded %s", got, FailureShutdown)
	}
}

func TestConnectInitializeError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		conn    *fakeConn
		want    FailureClass
		wantErr bool
	}{
		{
			name: "plain error is a server protocol failure",
			conn: &fakeConn{initErr: errors.New("bad handshake")},
			want: FailureServerProtocol,
		},
		{
			name: "already-typed error is propagated unchanged",
			conn: &fakeConn{initErr: NewError(FailureUnsupportedProtocol, "srv", "initialize", "version 1999-01-01 unsupported", nil)},
			want: FailureUnsupportedProtocol,
		},
		{
			name: "missing protocol version is a server protocol failure",
			conn: &fakeConn{},
			want: FailureServerProtocol,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tr := newFakeTransport(tt.conn)
			def := okDefinition(tr)
			rec := &eventRecorder{}

			c, err := Connect(context.Background(), def, Handlers{Event: rec.handle})
			if c != nil {
				t.Errorf("Connect returned a client alongside an error")
			}
			mustClass(t, err, tt.want, def.Name)
			if got := tt.conn.closeCount(); got != 1 {
				t.Errorf("conn closed %d times, want exactly 1", got)
			}
			// The binding must be observably failed, not silently abandoned.
			states := rec.states()
			if len(states) == 0 || states[len(states)-1] != StateFailed {
				t.Errorf("state events = %v, want the last to be %s", states, StateFailed)
			}
		})
	}
}

func TestConnectStartupTimeout(t *testing.T) {
	t.Parallel()

	t.Run("transport connect blocks", func(t *testing.T) {
		t.Parallel()
		conn := okConn()
		tr := newFakeTransport(conn)
		tr.block = true
		def := shortStartup(okDefinition(tr), 20*time.Millisecond)

		c, err := Connect(context.Background(), def, Handlers{})
		if c != nil {
			t.Errorf("Connect returned a client alongside an error")
		}
		mustClass(t, err, FailureStartupTimeout, def.Name)
		if conn.closeCount() != 0 {
			t.Errorf("conn closed %d times, want 0: it was never opened", conn.closeCount())
		}
	})

	t.Run("initialize blocks", func(t *testing.T) {
		t.Parallel()
		conn := okConn()
		conn.initBlock = true
		tr := newFakeTransport(conn)
		def := shortStartup(okDefinition(tr), 20*time.Millisecond)

		c, err := Connect(context.Background(), def, Handlers{})
		if c != nil {
			t.Errorf("Connect returned a client alongside an error")
		}
		mustClass(t, err, FailureStartupTimeout, def.Name)
		if got := conn.closeCount(); got != 1 {
			t.Errorf("conn closed %d times, want exactly 1: an opened conn must not be leaked", got)
		}
	})
}

func TestConnectContextCancelled(t *testing.T) {
	t.Parallel()

	t.Run("cancelled before connect", func(t *testing.T) {
		t.Parallel()
		conn := okConn()
		tr := newFakeTransport(conn)
		tr.block = true
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		c, err := Connect(ctx, okDefinition(tr), Handlers{})
		if c != nil {
			t.Errorf("Connect returned a client alongside an error")
		}
		mustClass(t, err, FailureCancelled, "srv")
	})

	t.Run("cancelled during initialize", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		conn := okConn()
		conn.initBlock = true
		conn.beforeInit = cancel
		tr := newFakeTransport(conn)

		c, err := Connect(ctx, okDefinition(tr), Handlers{})
		if c != nil {
			t.Errorf("Connect returned a client alongside an error")
		}
		mustClass(t, err, FailureCancelled, "srv")
		if got := conn.closeCount(); got != 1 {
			t.Errorf("conn closed %d times, want exactly 1", got)
		}
	})
}

func TestCloseIdempotent(t *testing.T) {
	t.Parallel()

	conn := okConn()
	c, err := Connect(context.Background(), okDefinition(newFakeTransport(conn)), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	for i := range 3 {
		if err := c.Close(context.Background()); err != nil {
			t.Errorf("Close() call %d error = %v, want nil", i+1, err)
		}
	}
	if got := conn.closeCount(); got != 1 {
		t.Errorf("conn closed %d times across 3 Close calls, want exactly 1", got)
	}
	if got := c.Status().State; got != StateClosed {
		t.Errorf("State after Close = %s, want %s", got, StateClosed)
	}
}

// TestCloseReportsConnError checks the first Close surfaces a transport close
// failure, and that later calls stay quiet.
func TestCloseReportsConnError(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.closeErr = errors.New("pipe already broken")
	c, err := Connect(context.Background(), okDefinition(newFakeTransport(conn)), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	mustClass(t, c.Close(context.Background()), FailureTransportClosed, "srv")
	if err := c.Close(context.Background()); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}
	if got := c.Status().State; got != StateClosed {
		t.Errorf("State = %s, want %s even though the transport close failed", got, StateClosed)
	}
}

func TestCloseConcurrent(t *testing.T) {
	t.Parallel()

	conn := okConn()
	c, err := Connect(context.Background(), okDefinition(newFakeTransport(conn)), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	const workers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := c.Close(context.Background()); err != nil {
				t.Errorf("Close() error = %v, want nil", err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = c.Status()
		}()
	}
	close(start)
	wg.Wait()

	if got := conn.closeCount(); got != 1 {
		t.Errorf("conn closed %d times under concurrent Close, want exactly 1", got)
	}
}

func TestConnectEmitsStateChanges(t *testing.T) {
	t.Parallel()

	rec := &eventRecorder{}
	conn := okConn()
	c, err := Connect(context.Background(), okDefinition(newFakeTransport(conn)), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	// Discovering is not decoration: a caller watching states must be able to
	// see that a binding is fetching its catalog, and the design requires the
	// catalog to be adopted before ready.
	wantStartup := []State{StateStarting, StateDiscovering, StateReady}
	if got := rec.states(); !equalStates(got, wantStartup) {
		t.Fatalf("states after Connect = %v, want %v", got, wantStartup)
	}
	for _, e := range rec.snapshot() {
		sc, ok := e.(StateChanged)
		if !ok {
			t.Fatalf("event %T, want StateChanged", e)
		}
		if sc.Binding != "srv" {
			t.Errorf("StateChanged.Binding = %q, want %q", sc.Binding, "srv")
		}
		if sc.At.IsZero() {
			t.Errorf("StateChanged.At is zero")
		}
	}
	if from := rec.snapshot()[0].(StateChanged).From; from != StateConfigured {
		t.Errorf("first transition From = %s, want %s", from, StateConfigured)
	}

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	wantAll := []State{StateStarting, StateDiscovering, StateReady, StateClosing, StateClosed}
	if got := rec.states(); !equalStates(got, wantAll) {
		t.Fatalf("states after Close = %v, want %v", got, wantAll)
	}

	// Repeated Closes emit nothing further. This is a weak check on its own —
	// StateClosed is terminal, so no transition could fire regardless — which
	// is why the watcher's removal is proven against the machine below rather
	// than inferred from the absence of events.
	before := len(rec.snapshot())
	for range 3 {
		_ = c.Close(context.Background())
	}
	if after := len(rec.snapshot()); after != before {
		t.Errorf("%d events arrived after Close, want none", after-before)
	}
	if !c.watcherCancelled() {
		t.Errorf("the lifecycle watcher is still registered on the machine after Close; "+
			"it holds the callback and everything it captured, including this Client (watchers: %d)",
			c.machine.WatcherCount())
	}
}

func equalStates(got, want []State) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestNoGoroutineLeak proves a connect/close cycle leaves nothing running.
func TestNoGoroutineLeak(t *testing.T) {
	// Not parallel: it counts process-wide goroutines.
	before := settledGoroutines(t)

	for range 20 {
		c, err := Connect(context.Background(), okDefinition(newFakeTransport(okConn())), Handlers{})
		if err != nil {
			t.Fatalf("Connect() error = %v", err)
		}
		if err := c.Close(context.Background()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	// A failed startup must not leak either.
	for range 20 {
		tr := newFakeTransport(&fakeConn{initErr: errors.New("nope")})
		if _, err := Connect(context.Background(), okDefinition(tr), Handlers{}); err == nil {
			t.Fatal("Connect() error = nil, want an error")
		}
	}

	if after := settledGoroutines(t); after > before {
		t.Errorf("goroutines: %d before, %d after; want no growth", before, after)
	}
}

// settledGoroutines returns the goroutine count once it has stopped shrinking,
// so unrelated runtime/test-framework goroutines do not make the check flaky.
func settledGoroutines(t *testing.T) int {
	t.Helper()
	last := runtime.NumGoroutine()
	for range 50 {
		time.Sleep(10 * time.Millisecond)
		runtime.GC()
		n := runtime.NumGoroutine()
		if n >= last {
			return n
		}
		last = n
	}
	return last
}
