// This file defines what a caller may observe about a live binding. Everything
// here is safe metadata: Status is designed to be logged, rendered in a UI, and
// shipped to telemetry as-is, so no field may ever carry a credential, a
// request payload, or an unbounded string. A transport's origin arrives already
// redacted (TransportFactory.RedactedOrigin) and failure text arrives already
// bounded (Error.Msg).

package client

import (
	"time"

	"github.com/looprig/mcp/internal/lifecycle"
)

// State is a binding's lifecycle state. It mirrors internal/lifecycle's State
// exactly — the constants below are derived from it, so the two can never drift
// numerically — and exists so that consumers depend on this package's contract
// rather than on an internal one. The zero value is not a valid state.
type State uint8

// The lifecycle states. See internal/lifecycle for the transition rules.
const (
	// StateConfigured is a binding that has been validated but not started.
	StateConfigured = State(lifecycle.StateConfigured)
	// StateStarting is a binding whose transport is being established.
	StateStarting = State(lifecycle.StateStarting)
	// StateAuthenticating is a binding performing authentication.
	StateAuthenticating = State(lifecycle.StateAuthenticating)
	// StateDiscovering is a binding fetching its catalog from the server.
	StateDiscovering = State(lifecycle.StateDiscovering)
	// StateReady is a binding serving calls normally.
	StateReady = State(lifecycle.StateReady)
	// StateDegraded is a binding still serving calls but with reduced
	// capability or a known fault.
	StateDegraded = State(lifecycle.StateDegraded)
	// StateReconnecting is a binding re-establishing its transport.
	StateReconnecting = State(lifecycle.StateReconnecting)
	// StateFailed is a binding that is not serving calls.
	StateFailed = State(lifecycle.StateFailed)
	// StateClosing is a binding shutting down.
	StateClosing = State(lifecycle.StateClosing)
	// StateClosed is the terminal state.
	StateClosed = State(lifecycle.StateClosed)
)

// String returns the state's stable lowercase identifier, or "unknown" for any
// value outside the declared range. The identifiers match internal/lifecycle's,
// which a test enforces.
func (s State) String() string {
	return lifecycle.State(s).String()
}

// fromLifecycle converts an internal state to its public mirror. The conversion
// is numeric because the constants above are defined from the internal ones; a
// test sweeps the whole range to keep that true.
func fromLifecycle(s lifecycle.State) State {
	return State(s)
}

// ServerIdentity is what a server claims to be. Every field is server-supplied
// and cosmetic: it names a peer, it never authorizes one. Do not use it to make
// a trust decision.
type ServerIdentity struct {
	Name    string
	Version string
	Title   string
}

// Failure is a classified, bounded summary of what went wrong on a binding. Its
// Message comes from an Error, so it is already normalized and capped at
// MaxMessageBytes.
type Failure struct {
	// Class states what kind of failure occurred.
	Class FailureClass
	// Message is bounded, normalized human-readable text.
	Message string
}

// Status is a snapshot of a binding's observable state. It is a value: callers
// may hold, copy and mutate it freely without affecting the client.
type Status struct {
	// Binding names the server binding.
	Binding Name
	// State is the lifecycle state at the moment of the call.
	State State
	// ProtocolVersion is the version negotiated at initialize. Empty before
	// the handshake completes.
	ProtocolVersion string
	// Server is what the server said it is. Zero before the handshake.
	Server ServerIdentity
	// TransportKind names the transport, e.g. "stdio".
	TransportKind string
	// RedactedOrigin is a display origin that never contains credentials.
	RedactedOrigin string
	// Failure summarizes the last failure, or nil when there is none.
	Failure *Failure
	// LastChange is when the state last changed.
	LastChange time.Time
	// Adopted/candidate catalog digests and retry state arrive with the tasks
	// that introduce discovery and reconnection.
}
