package client

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
)

// fastReconnect gives a definition a reconnect policy with no real delays.
func fastReconnect(d Definition, attempts int) Definition {
	d.Reconnect = ReconnectPolicy{
		RetryPolicy: RetryPolicy{
			Attempts:  attempts,
			BaseDelay: time.Millisecond,
			MaxDelay:  time.Millisecond,
			MaxTotal:  time.Minute,
		},
	}
	return d
}

// lostConn is the error a transport reports when its connection died: a typed
// error of a class that means the connection itself is gone.
func lostConn() error {
	return NewError(FailureTransportClosed, "srv", "call_tool", "the server process exited", nil)
}

// redialTransport is a TransportFactory that hands out a scripted sequence of
// conns, one per Connect. It is what makes a reconnect observable: the client
// gets a genuinely new connection, and the test can tell which one it is talking
// to.
type redialTransport struct {
	mu    sync.Mutex
	conns []*fakeConn
	dials int
	// err, when set, fails every dial after the first.
	err error
}

func newRedialTransport(conns ...*fakeConn) *redialTransport {
	return &redialTransport{conns: conns}
}

func (t *redialTransport) Kind() string { return "fake" }

func (t *redialTransport) RedactedOrigin() string { return "fake://server" }

func (t *redialTransport) Connect(ctx context.Context, cfg protocol.ConnectConfig) (protocol.Conn, error) {
	t.mu.Lock()
	n := t.dials
	t.dials++
	if n < len(t.conns) {
		conn := t.conns[n]
		conn.connectCfg = cfg
		t.mu.Unlock()
		return conn, nil
	}
	err := t.err
	t.mu.Unlock()

	if err == nil {
		err = errors.New("fake: no more connections scripted")
	}
	return nil, err
}

func (t *redialTransport) dialCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dials
}

// TestReconnectAfterTransientLoss is the design's reconnect sequence: a
// transient failure, a new logical connection, a fresh candidate, and an adopted
// generation that never moved.
func TestReconnectAfterTransientLoss(t *testing.T) {
	t.Parallel()

	first, second := okConn(), okConn()
	// The reconnected server offers one more tool, so the candidate it produces
	// is distinguishable from the generation that stays adopted.
	second.setTools(fakeTool("echo"), fakeTool("echo2"))
	first.callErr = lostConn()

	tr := newRedialTransport(first, second)
	rec := &eventRecorder{}
	def := fastReconnect(Definition{Name: "srv", Transport: tr}, 3)

	c, err := Connect(context.Background(), def, Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	adoptedBefore := c.Catalog()

	// A call finds the connection gone.
	_, err = c.CallTool(context.Background(), "echo", nil, CallOpts{})
	if class, ok := ClassOf(err); !ok || class != FailureIndeterminate {
		t.Fatalf("a call on a dying connection: error = %v (class %v), want FailureIndeterminate", err, class)
	}

	waitFor(t, "the reconnect", func() bool { return c.Status().State == StateReady && tr.dialCount() == 2 })

	// The old connection was closed, not leaked: a binding that dialed again
	// without releasing the corpse would hold a subprocess per failure.
	if got := first.closeCount(); got != 1 {
		t.Errorf("the replaced connection was closed %d times, want 1", got)
	}

	// The adopted generation is untouched — the design's "leave existing
	// generations active". The new catalog is a candidate like any other.
	if got := c.Catalog(); got.Generation != adoptedBefore.Generation || got.Digest != adoptedBefore.Digest {
		t.Errorf("adopted catalog = (gen %d, %q) after a reconnect, want the unchanged (gen %d, %q)",
			got.Generation, got.Digest, adoptedBefore.Generation, adoptedBefore.Digest)
	}
	cand, ok := c.Candidate()
	if !ok {
		t.Fatal("a reconnect produced no candidate")
	}
	if _, ok := cand.ToolByRawName("echo2"); !ok {
		t.Error("the candidate does not describe the reconnected server")
	}

	// And the binding works again, over the new connection.
	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err != nil {
		t.Errorf("CallTool() after a reconnect: error = %v", err)
	}
	if got := len(second.callNames()); got != 1 {
		t.Errorf("calls on the new connection = %d, want 1: the client is still using the old one", got)
	}

	lost := eventsOf[ConnectionLost](rec)
	if len(lost) != 1 || !lost[0].Retrying || lost[0].Class != FailureTransportClosed {
		t.Errorf("ConnectionLost events = %+v, want one retrying transport_closed", lost)
	}
	restored := eventsOf[ConnectionRestored](rec)
	if len(restored) != 1 {
		t.Fatalf("ConnectionRestored events = %d, want 1", len(restored))
	}
	if restored[0].Adopted != adoptedBefore.Generation {
		t.Errorf("ConnectionRestored.Adopted = %d, want the untouched %d", restored[0].Adopted, adoptedBefore.Generation)
	}
	if restored[0].Drift != "" {
		t.Errorf("ConnectionRestored.Drift = %q, want empty for the same server", restored[0].Drift)
	}
}

// TestInFlightToolCallAtDisconnectIsIndeterminate is the design's
// correctness-critical rule. A tool call that was in flight when the connection
// died may have run. Reporting it as a plain failure invites a retry, and a
// retried tool call is a second effect.
func TestInFlightToolCallAtDisconnectIsIndeterminate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		class FailureClass
		want  FailureClass
	}{
		{"a closed transport", FailureTransportClosed, FailureIndeterminate},
		{"a framing failure", FailureFraming, FailureIndeterminate},
		// Not every failure is indeterminate. These reached a live server and
		// came back with an answer about the request, so the call's outcome is
		// known: it did not run.
		{"a remote HTTP failure", FailureRemoteHTTP, FailureRemoteHTTP},
		{"a server protocol error", FailureServerProtocol, FailureServerProtocol},
		{"an auth failure", FailureAuthDenied, FailureAuthDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conn := okConn()
			conn.callErr = NewError(tt.class, "srv", "call_tool", "boom", nil)
			tr := newRedialTransport(conn, okConn())
			c, err := Connect(context.Background(), fastReconnect(Definition{Name: "srv", Transport: tr}, 1), Handlers{})
			if err != nil {
				t.Fatalf("Connect() error = %v", err)
			}
			defer func() { _ = c.Close(context.Background()) }()

			_, err = c.CallTool(context.Background(), "echo", nil, CallOpts{})
			if class, ok := ClassOf(err); !ok || class != tt.want {
				t.Errorf("CallTool() on %s: error = %v (class %v), want %v", tt.name, err, class, tt.want)
			}
		})
	}
}

// TestInFlightToolCallIsNotReplayed: the client must not re-send the call it
// could not get an answer for. This is the other half of indeterminacy — the
// class is only honest if nothing behind it quietly retries.
func TestInFlightToolCallIsNotReplayed(t *testing.T) {
	t.Parallel()

	first, second := okConn(), okConn()
	first.callErr = lostConn()
	tr := newRedialTransport(first, second)

	c, err := Connect(context.Background(), fastReconnect(Definition{Name: "srv", Transport: tr}, 3), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err == nil {
		t.Fatal("CallTool() succeeded on a dying connection")
	}
	waitFor(t, "the reconnect", func() bool { return c.Status().State == StateReady })
	// Give a replay every chance to happen.
	time.Sleep(50 * time.Millisecond)

	if got := first.callNames(); len(got) != 1 {
		t.Errorf("calls on the dead connection = %v, want exactly the one that failed", got)
	}
	if got := second.callNames(); len(got) != 0 {
		t.Errorf("the reconnect replayed the in-flight call onto the new connection: %v", got)
	}
}

// TestReconnectIsBounded: a server that never comes back must not produce an
// endless reconnect loop. The budget is spent, the binding is failed, and it
// says so.
func TestReconnectIsBounded(t *testing.T) {
	t.Parallel()

	const attempts = 3

	first := okConn()
	first.callErr = lostConn()
	tr := newRedialTransport(first)
	tr.err = errors.New("connection refused")

	rec := &eventRecorder{}
	c, err := Connect(context.Background(), fastReconnect(Definition{Name: "srv", Transport: tr}, attempts), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err == nil {
		t.Fatal("CallTool() succeeded on a dying connection")
	}

	waitFor(t, "the binding to fail", func() bool { return c.Status().State == StateFailed })
	// Settle, then check the loop actually stopped rather than being caught mid-flight.
	time.Sleep(50 * time.Millisecond)

	// One dial for startup, then exactly the policy's attempts.
	if got := tr.dialCount(); got != attempts+1 {
		t.Errorf("dials = %d, want %d (startup plus the policy's %d attempts)", got, attempts+1, attempts)
	}

	st := c.Status()
	if st.Failure == nil || st.Failure.Message == "" {
		t.Error("a binding that exhausted its reconnect budget reports no failure")
	}
	if st.ReconnectAttempt != attempts {
		t.Errorf("Status().ReconnectAttempt = %d, want the last attempt %d", st.ReconnectAttempt, attempts)
	}
	// The last word to the application is that it has stopped trying.
	lost := eventsOf[ConnectionLost](rec)
	if len(lost) == 0 {
		t.Fatal("no ConnectionLost event")
	}
	if last := lost[len(lost)-1]; last.Retrying {
		t.Error("the final ConnectionLost still claims it is retrying")
	}
	// A failed binding serves nothing, and says why.
	_, err = c.CallTool(context.Background(), "echo", nil, CallOpts{})
	if err == nil {
		t.Error("CallTool() succeeded on a failed binding")
	}
}

// TestReconnectDisabledByPolicy: the design's gate — reconnection happens only
// when policy permits. A binding that must not be re-established silently stays
// degraded and reports it.
func TestReconnectDisabledByPolicy(t *testing.T) {
	t.Parallel()

	first := okConn()
	first.callErr = lostConn()
	tr := newRedialTransport(first, okConn())

	def := Definition{Name: "srv", Transport: tr}
	def.Reconnect.Disabled = true

	rec := &eventRecorder{}
	c, err := Connect(context.Background(), def, Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err == nil {
		t.Fatal("CallTool() succeeded on a dying connection")
	}
	waitFor(t, "the degraded state", func() bool { return c.Status().State == StateDegraded })
	time.Sleep(50 * time.Millisecond)

	if got := tr.dialCount(); got != 1 {
		t.Errorf("dials = %d, want 1: policy forbids reconnection", got)
	}
	lost := eventsOf[ConnectionLost](rec)
	if len(lost) != 1 || lost[0].Retrying {
		t.Errorf("ConnectionLost events = %+v, want exactly one that is not retrying", lost)
	}
}

// TestReconnectNotAttemptedForNonTransientFailure: the design's second gate. An
// auth denial is not a connection problem, and reconnecting through one retries
// a credential that was just refused — which is how a client locks an account
// out on its host's behalf.
func TestReconnectNotAttemptedForNonTransientFailure(t *testing.T) {
	t.Parallel()

	for _, class := range []FailureClass{FailureAuthDenied, FailureAuthExpired, FailureServerProtocol, FailureRemoteHTTP} {
		t.Run(class.String(), func(t *testing.T) {
			t.Parallel()

			conn := okConn()
			conn.callErr = NewError(class, "srv", "call_tool", "refused", nil)
			tr := newRedialTransport(conn, okConn())

			c, err := Connect(context.Background(), fastReconnect(Definition{Name: "srv", Transport: tr}, 3), Handlers{})
			if err != nil {
				t.Fatalf("Connect() error = %v", err)
			}
			defer func() { _ = c.Close(context.Background()) }()

			if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err == nil {
				t.Fatal("CallTool() succeeded")
			}
			time.Sleep(50 * time.Millisecond)

			if got := tr.dialCount(); got != 1 {
				t.Errorf("dials = %d after a %v failure, want 1: it is not a transient connection loss", got, class)
			}
			if got := c.Status().State; got != StateReady {
				t.Errorf("State = %v after a %v failure, want the binding to stay ready", got, class)
			}
		})
	}
}

// TestReconnectDoesNotLeakOnFailedDiscovery: the reconnect path unwinds exactly
// like startup. A connection that is established but cannot be made the
// binding's must be closed — the alternative is a live subprocess owned by
// nobody, which is the leak Task 1.6 fixed and which a second dialing path could
// quietly reintroduce.
func TestReconnectDoesNotLeakOnFailedDiscovery(t *testing.T) {
	t.Parallel()

	first := okConn()
	first.callErr = lostConn()

	// The reconnected conn initializes and then fails discovery.
	broken := okConn()
	broken.setListErr(errors.New("no catalog for you"))
	// And a third that works, so the binding recovers and the test can be sure
	// the broken one was dropped rather than kept.
	third := okConn()

	tr := newRedialTransport(first, broken, third)

	c, err := Connect(context.Background(), fastReconnect(Definition{Name: "srv", Transport: tr}, 3), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err == nil {
		t.Fatal("CallTool() succeeded on a dying connection")
	}
	waitFor(t, "the reconnect", func() bool { return c.Status().State == StateReady && tr.dialCount() == 3 })

	if got := broken.closeCount(); got != 1 {
		t.Errorf("the connection that failed discovery was closed %d times, want 1: it leaked", got)
	}
	// And it never became the binding's: the working third conn is the one in use.
	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err != nil {
		t.Fatalf("CallTool() after recovery: error = %v", err)
	}
	if len(third.callNames()) != 1 {
		t.Error("the client is not using the connection it recovered onto")
	}
	if len(broken.callNames()) != 0 {
		t.Error("the client used a connection that failed discovery")
	}
}

// TestReconnectReportsIdentityDrift: the design says to compare server identity
// after a reconnect. It is reported, not enforced — a restarted server with a
// new version is the ordinary reason to be reconnecting — so the binding
// recovers and the drift travels with the candidate the caller must decide about.
func TestReconnectReportsIdentityDrift(t *testing.T) {
	t.Parallel()

	first := okConn()
	first.callErr = lostConn()
	second := okConn()
	second.initResult.Server = protocol.ServerIdentity{Name: "srv", Version: "2.0.0", Title: "Test Server"}

	tr := newRedialTransport(first, second)
	rec := &eventRecorder{}

	c, err := Connect(context.Background(), fastReconnect(Definition{Name: "srv", Transport: tr}, 3), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err == nil {
		t.Fatal("CallTool() succeeded on a dying connection")
	}
	waitFor(t, "the reconnect", func() bool { return len(eventsOf[ConnectionRestored](rec)) == 1 })

	restored := eventsOf[ConnectionRestored](rec)[0]
	if restored.Drift == "" {
		t.Error("ConnectionRestored.Drift is empty for a server that changed version")
	}
	if restored.Server.Version != "2.0.0" {
		t.Errorf("ConnectionRestored.Server.Version = %q, want the reconnected server's 2.0.0", restored.Server.Version)
	}
	// Reported, not enforced: the binding is serving again.
	if got := c.Status().State; got != StateReady {
		t.Errorf("State = %v after a server identity change, want it to keep serving", got)
	}
	if got := c.Status().Server.Version; got != "2.0.0" {
		t.Errorf("Status().Server.Version = %q, want the reconnected server's", got)
	}
}

// TestCloseDuringReconnectDoesNotLeak: shutdown wins over a reconnect in
// progress, and the connection a losing reconnect opened is still closed.
func TestCloseDuringReconnectDoesNotLeak(t *testing.T) {
	t.Parallel()

	first := okConn()
	first.callErr = lostConn()
	second := okConn()
	// Hold the reconnect inside its discovery, so Close lands squarely in the
	// middle of it.
	second.listEntered = make(chan struct{})
	second.listGate = make(chan struct{})

	tr := newRedialTransport(first, second)
	c, err := Connect(context.Background(), fastReconnect(Definition{Name: "srv", Transport: tr}, 3), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err == nil {
		t.Fatal("CallTool() succeeded on a dying connection")
	}
	<-second.listEntered // the reconnect is mid-discovery

	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Let the held reconnect proceed into a client that is already closed.
	close(second.listGate)
	waitFor(t, "the reconnect's connection to be released", func() bool { return second.closeCount() == 1 })

	if got := c.Status().State; got != StateClosed {
		t.Errorf("State = %v, want %v", got, StateClosed)
	}
}

// TestLateFailureFromARetiredConnectionIsIgnored: a request outlives the
// connection it was issued on. One that started on the old connection and
// reports its death after the binding has already rebuilt — the ordinary
// interleaving when several calls fail together — is describing a connection
// that is already gone. Acting on it would degrade a healthy binding and dial
// away a connection nothing is wrong with.
func TestLateFailureFromARetiredConnectionIsIgnored(t *testing.T) {
	t.Parallel()

	first, second := okConn(), okConn()
	first.callErr = lostConn()
	// Two calls on the dying connection. The first is held inside it — that is
	// the straggler — and the second runs through and reports the death, which
	// is what rebuilds the binding while the straggler is still in there.
	first.callReleased = make(chan struct{})
	first.holdCall = 1

	tr := newRedialTransport(first, second)
	rec := &eventRecorder{}
	def := fastReconnect(Definition{Name: "srv", Transport: tr}, 3)
	def.AllowParallelCalls = true
	def.Limits.MaxConcurrentRequests = 4

	c, err := Connect(context.Background(), def, Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	// The straggler: issued on connection 1, and still inside it.
	straggler := make(chan error, 1)
	go func() {
		_, err := c.CallTool(context.Background(), "echo", nil, CallOpts{})
		straggler <- err
	}()
	waitFor(t, "the straggler to be in flight", func() bool { return first.live.Load() == 1 })

	// A second call on the same connection finds it dead and reports it. The
	// binding degrades, reconnects, and is serving again — all while the
	// straggler is still inside connection 1.
	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err == nil {
		t.Fatal("the second call succeeded on a dying connection")
	}
	waitFor(t, "the reconnect", func() bool { return c.Status().State == StateReady && tr.dialCount() == 2 })

	// Only now is the straggler let go, into a binding that has moved on.
	close(first.callReleased)

	// The straggler now reports connection 1's death into a binding already
	// serving on connection 2.
	select {
	case err := <-straggler:
		if class, ok := ClassOf(err); !ok || class != FailureIndeterminate {
			t.Errorf("the straggler: error = %v (class %v), want FailureIndeterminate", err, class)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the straggler never returned")
	}
	time.Sleep(50 * time.Millisecond)

	// The healthy connection is untouched: no extra dial, no degradation, and
	// the application was not told its live connection had dropped.
	if got := tr.dialCount(); got != 2 {
		t.Errorf("dials = %d, want 2: a stale report dialed away a working connection", got)
	}
	if got := c.Status().State; got != StateReady {
		t.Errorf("State = %v, want %v: a stale report degraded a healthy binding", got, StateReady)
	}
	if got := len(eventsOf[ConnectionLost](rec)); got != 1 {
		t.Errorf("ConnectionLost events = %d, want 1: the straggler re-reported a connection that was already replaced", got)
	}
}

// TestReconnectConcurrentLossReportsOnce: every request in flight observes the
// same disconnection. They must collapse onto one report and one reconnect, not
// tell the application its connection dropped eight times.
func TestReconnectConcurrentLossReportsOnce(t *testing.T) {
	t.Parallel()

	first, second := okConn(), okConn()
	first.callErr = lostConn()
	tr := newRedialTransport(first, second)

	rec := &eventRecorder{}
	def := fastReconnect(Definition{Name: "srv", Transport: tr}, 3)
	def.AllowParallelCalls = true
	def.Limits.MaxConcurrentRequests = 8

	c, err := Connect(context.Background(), def, Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.CallTool(context.Background(), "echo", nil, CallOpts{})
		}()
	}
	wg.Wait()

	waitFor(t, "the reconnect", func() bool { return c.Status().State == StateReady })
	time.Sleep(50 * time.Millisecond)

	if got := len(eventsOf[ConnectionLost](rec)); got != 1 {
		t.Errorf("ConnectionLost events = %d for one disconnection observed by 8 calls, want 1", got)
	}
	if got := tr.dialCount(); got != 2 {
		t.Errorf("dials = %d, want 2 (startup plus one reconnect)", got)
	}
}

// TestLossClaimIsAtomicWithTheSwap drives the interleaving that made this test
// file's concurrent-loss case hang intermittently under load.
//
// The shape is three-way. Two requests fail on one dying connection. The first
// claims the loss and triggers the reconnect, which installs a new connection
// and puts the binding back in service. The second is descheduled in between:
// it observed the death of a connection that, by the time it gets to say so, has
// already been replaced.
//
// The failure it guards against is not "an extra event". It is that the late
// reporter degrades a binding whose connection is fine, which triggers a
// reconnect against a server that never disconnected — and when those retries
// run out, fails a healthy binding outright. It surfaced as a hang: the binding
// sat in StateFailed and every wait for readiness burned its whole deadline.
//
// The lossHook seam is what makes it deterministic. The window is a few
// instructions wide and needs a specific three-goroutine interleaving, so left
// to chance it reproduced in roughly one full-suite run in ten — which is not a
// regression test, it is a rumour.
func TestLossClaimIsAtomicWithTheSwap(t *testing.T) {
	t.Parallel()

	first, second := okConn(), okConn()
	first.callErr = lostConn()
	tr := newRedialTransport(first, second)

	rec := &eventRecorder{}
	def := fastReconnect(Definition{Name: "srv", Transport: tr}, 3)
	def.AllowParallelCalls = true
	def.Limits.MaxConcurrentRequests = 4

	c, err := Connect(context.Background(), def, Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	// A rendezvous, not a race. Both reporters must be inside the window — each
	// having formed its verdict about the dying connection — before the
	// reconnect is allowed to start. Otherwise the second call can simply be
	// issued on the new connection and succeed, and the test proves nothing
	// while looking like it passed.
	//
	// Which goroutine takes which role does not matter: the two calls are
	// identical, and the first to arrive drives while the second straggles.
	var hookCount atomic.Int32
	arrived := make(chan struct{}, 2)
	bothArrived := make(chan struct{})
	reconnected := make(chan struct{})
	c.lossHook = func() {
		n := hookCount.Add(1)
		arrived <- struct{}{}
		if n == 1 {
			// The driver: held until the straggler has also formed its verdict,
			// so the straggler's view of the connection is provably the old one.
			<-bothArrived
			return
		}
		// The straggler: held until the reconnect it knows nothing about has
		// completely finished.
		<-reconnected
	}

	// Two concurrent calls on the dying connection.
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.CallTool(context.Background(), "echo", nil, CallOpts{})
		}()
	}

	// Both reporters are now inside the window, holding a verdict about the
	// connection that is about to be replaced.
	<-arrived
	<-arrived
	close(bothArrived)

	// The driver's claim rebuilds the binding: new connection, back in service.
	waitFor(t, "the reconnect", func() bool {
		return c.Status().State == StateReady && tr.dialCount() == 2
	})
	// Only now does the straggler get to act on what it saw.
	close(reconnected)
	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	// The late report must have changed nothing at all.
	if got := c.Status().State; got != StateReady {
		t.Errorf("State = %v, want %v: a report about a replaced connection degraded a healthy binding", got, StateReady)
	}
	if got := tr.dialCount(); got != 2 {
		t.Errorf("dials = %d, want 2: a report about a replaced connection dialed away a working connection", got)
	}
	if got := len(eventsOf[ConnectionLost](rec)); got != 1 {
		t.Errorf("ConnectionLost events = %d for one disconnection, want 1", got)
	}
	if st := c.Status(); st.ReconnectAttempt != 0 {
		t.Errorf("Status().ReconnectAttempt = %d, want 0: the binding is not reconnecting", st.ReconnectAttempt)
	}
}
