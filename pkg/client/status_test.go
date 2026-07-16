package client

import (
	"testing"

	"github.com/looprig/mcp/internal/lifecycle"
)

// TestStateMirrorsLifecycle pins the public State enum to the internal one:
// every state the machine can report must have a public counterpart with the
// same identifier, so internal/lifecycle never has to be exported. Sweeping the
// whole uint8 range means a state appended internally fails here rather than
// surfacing as "unknown" to a consumer.
func TestStateMirrorsLifecycle(t *testing.T) {
	t.Parallel()

	declared := 0
	for v := 0; v <= 255; v++ {
		internal := lifecycle.State(v)
		name := internal.String()
		if name == "unknown" {
			// Not a declared internal state; the mirror must not invent one.
			if got := State(v).String(); got != "unknown" {
				t.Errorf("State(%d).String() = %q, want %q: no internal state has this value", v, got, "unknown")
			}
			continue
		}
		declared++
		if got := State(v).String(); got != name {
			t.Errorf("State(%d).String() = %q, want %q to match lifecycle.State(%d)", v, got, name, v)
		}
		if got := fromLifecycle(internal); uint8(got) != uint8(v) {
			t.Errorf("fromLifecycle(%s) = %d, want %d", name, got, v)
		}
	}
	if declared == 0 {
		t.Fatal("no declared lifecycle states were checked: the mirror test would vacuously pass")
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
