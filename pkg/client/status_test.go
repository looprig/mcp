package client

import (
	"testing"

	"github.com/looprig/mcp/internal/lifecycle"
)

// publicStates is every State this package exports. It is hand-maintained on
// purpose: deriving it from internal/lifecycle is what would make
// TestStateMirrorsLifecycle agree with itself instead of checking anything.
var publicStates = []State{
	StateConfigured,
	StateStarting,
	StateAuthenticating,
	StateDiscovering,
	StateReady,
	StateDegraded,
	StateReconnecting,
	StateFailed,
	StateClosing,
	StateClosed,
}

// TestStateMirrorsLifecycle checks that every state internal/lifecycle declares
// has a public counterpart, so no state the machine can report reaches a
// consumer as "unknown" and internal/lifecycle never has to be exported.
//
// It deliberately does NOT compare the two String methods: this package's State
// delegates to lifecycle's, so such a check compares a function to itself and
// cannot fail. Numeric drift is equally untestable, and equally unnecessary —
// the constants in status.go are *defined* from lifecycle's, so the compiler
// guarantees it. What is left, and all this test is for, is the one failure the
// compiler cannot catch: a state added to internal/lifecycle that nobody
// mirrored here. That shows up as a count mismatch.
func TestStateMirrorsLifecycle(t *testing.T) {
	t.Parallel()

	declared := 0
	for v := 0; v <= 255; v++ {
		if lifecycle.State(v).String() != "unknown" {
			declared++
		}
	}
	if declared == 0 {
		t.Fatal("no declared lifecycle states were found: the mirror test would vacuously pass")
	}
	if len(publicStates) != declared {
		t.Errorf("this package exports %d states but internal/lifecycle declares %d: "+
			"every internal state needs a public mirror in status.go and an entry in publicStates, "+
			"or the machine can report a state a consumer only sees as %q",
			len(publicStates), declared, "unknown")
	}

	// Each exported constant must name a real internal state, and no two may
	// collide onto one.
	seen := make(map[State]bool, len(publicStates))
	for _, s := range publicStates {
		if s.String() == "unknown" {
			t.Errorf("exported State(%d) does not correspond to any declared lifecycle state", s)
		}
		if seen[s] {
			t.Errorf("exported State(%d) (%s) is declared twice", s, s)
		}
		seen[s] = true
	}
	t.Logf("mirrored %d lifecycle state(s)", declared)
}

// TestStateNames pins the public identifiers, which surface in logs and events.
func TestStateNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state State
		want  string
	}{
		{StateConfigured, "configured"},
		{StateStarting, "starting"},
		{StateAuthenticating, "authenticating"},
		{StateDiscovering, "discovering"},
		{StateReady, "ready"},
		{StateDegraded, "degraded"},
		{StateReconnecting, "reconnecting"},
		{StateFailed, "failed"},
		{StateClosing, "closing"},
		{StateClosed, "closed"},
		{State(0), "unknown"},
		{State(200), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != tt.want {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

// TestStatusReportsFailure covers the Failure field, which Connect populates on
// the startup failure path. The failing client is never handed to a caller, so
// this drives the recording directly.
func TestStatusReportsFailure(t *testing.T) {
	t.Parallel()

	c := newClient(okDefinition(newFakeTransport(okConn())).normalized(), Handlers{})
	defer c.unwatch()

	if got := c.Status().Failure; got != nil {
		t.Fatalf("Failure = %+v on a fresh client, want nil", got)
	}

	c.recordFailure(NewError(FailureServerProtocol, "srv", "initialize", "no protocol version", nil))

	got := c.Status().Failure
	if got == nil {
		t.Fatal("Failure = nil after recordFailure, want a value")
	}
	if got.Class != FailureServerProtocol {
		t.Errorf("Failure.Class = %s, want %s", got.Class, FailureServerProtocol)
	}
	if got.Message == "" {
		t.Errorf("Failure.Message is empty, want the bounded error text")
	}
	if len(got.Message) > MaxMessageBytes {
		t.Errorf("Failure.Message = %d bytes, want <= %d", len(got.Message), MaxMessageBytes)
	}

	// Status is a value: mutating a copy must not touch the client's state.
	got.Class = FailureCancelled
	if again := c.Status().Failure; again.Class != FailureServerProtocol {
		t.Errorf("Failure.Class = %s after mutating a returned copy, want %s", again.Class, FailureServerProtocol)
	}
}

// TestStatusFailureIsBounded proves a hostile server cannot smuggle unbounded
// text into Status.
func TestStatusFailureIsBounded(t *testing.T) {
	t.Parallel()

	c := newClient(okDefinition(newFakeTransport(okConn())).normalized(), Handlers{})
	defer c.unwatch()

	long := make([]byte, 8192)
	for i := range long {
		long[i] = 'x'
	}
	c.recordFailure(NewError(FailureServerProtocol, "srv", "initialize", string(long), nil))

	if got := len(c.Status().Failure.Message); got > MaxMessageBytes {
		t.Errorf("Failure.Message = %d bytes, want <= %d", got, MaxMessageBytes)
	}
}
