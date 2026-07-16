// This file implements Client: one MCP server binding, its lifecycle, and the
// startup sequence that establishes it.
//
// Startup is deliberately linear and fails closed. Every step either advances
// the lifecycle machine or unwinds completely — there is no partially connected
// Client, and no error path that returns one. Because shutdown can legally
// overtake startup at any step (see internal/lifecycle), a refused transition
// is treated as "someone else is closing this" and unwinds, never as a bug.

package client

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/looprig/mcp/internal/lifecycle"
	"github.com/looprig/mcp/internal/protocol"
)

// The identity this module presents to servers. It is cosmetic — a server
// learns who is calling, not what the caller may do.
const (
	// ClientName is the MCP client name this module reports.
	ClientName = "looprig-mcp"
	// ClientVersion is the module version reported alongside ClientName.
	ClientVersion = "0.1.0"
	// ClientTitle is the human-readable client name.
	ClientTitle = "looprig MCP client"
)

// Operation names carried by the errors this file returns.
const (
	opConnect    = "connect"
	opInitialize = "initialize"
	opClose      = "close"
)

// Client is one connection to one MCP server. It is safe for concurrent use.
// A Client is always either usable or closed: Connect never returns one that
// failed to start.
type Client struct {
	// def is the normalized definition. It is written once, before the Client
	// escapes Connect, and never mutated afterwards.
	def Definition

	machine *lifecycle.Machine
	// unwatch deregisters the lifecycle watcher. Close nils it out to release
	// the watcher's reference to this Client; it is only ever touched inside
	// closeOnce.
	unwatch func()

	// connOnce guards the single Close of conn. Both Connect's unwind path and
	// Close go through it, so a conn can never be closed twice.
	connOnce sync.Once
	connErr  error
	// closeOnce guards the whole shutdown sequence, making Close idempotent.
	closeOnce sync.Once

	// mu guards the conn handle and the observable metadata below. The
	// lifecycle state itself lives in the machine, which does its own locking.
	mu sync.Mutex
	// conn is the established connection, assigned once by startup. It is
	// guarded because Close may read it from another goroutine — today only
	// after Connect returned, but reconnection will re-run startup on a Client
	// a caller already holds.
	conn            protocol.Conn
	server          ServerIdentity
	protocolVersion string
	failure         *Failure
	lastChange      time.Time
}

// Connect establishes a binding: it validates def, opens a transport, performs
// the MCP handshake, and returns a ready Client. The whole sequence is bounded
// by def.Timeouts.Startup (or the caller's ctx, whichever fires first).
//
// It fails closed at every step. On any error it returns a nil Client and an
// *Error bound to def.Name — the transport, if one was opened, is always
// closed before returning, so a failed Connect leaks nothing.
//
// ctx bounds startup only; it does not govern the returned Client's lifetime.
// Cancelling it after Connect returns has no effect — use Close.
func Connect(ctx context.Context, def Definition, h Handlers) (*Client, error) {
	// Validate before anything is built or contacted: a malformed definition
	// must not reach a transport.
	if err := def.Validate(); err != nil {
		return nil, err
	}
	caps, err := h.advertised(def.Name, def.Capabilities)
	if err != nil {
		return nil, err
	}

	c := newClient(def.normalized(), h)

	startCtx, cancel := context.WithTimeout(ctx, c.def.Timeouts.Startup)
	defer cancel()

	if err := c.start(startCtx, caps); err != nil {
		// The unwind already closed the transport and recorded the failure.
		c.unwatch()
		return nil, err
	}
	return c, nil
}

// newClient builds an unstarted Client in StateConfigured with its lifecycle
// watcher already registered, so no transition can be missed by a caller's
// event handler.
func newClient(def Definition, h Handlers) *Client {
	c := &Client{def: def, machine: lifecycle.NewMachine()}
	c.unwatch = c.machine.Watch(func(from, to lifecycle.State) {
		now := time.Now()
		c.mu.Lock()
		c.lastChange = now
		c.mu.Unlock()
		if h.Event == nil {
			return
		}
		h.Event(StateChanged{
			Binding: def.Name,
			From:    fromLifecycle(from),
			To:      fromLifecycle(to),
			At:      now,
		})
	})
	return c
}

// start runs the startup sequence: configured -> starting -> ready.
//
// Authentication (StateAuthenticating) is skipped: no transport in this module
// authenticates yet, and the lifecycle permits starting -> ready directly.
// Discovery inserts StateDiscovering between the handshake and StateReady when
// it lands; the transition table already allows it.
func (c *Client) start(ctx context.Context, caps protocol.ClientCapabilities) error {
	if err := c.to(lifecycle.StateStarting, opConnect); err != nil {
		return err
	}

	conn, err := c.def.Transport.Connect(ctx, protocol.ConnectConfig{
		Client:       protocol.ClientIdentity{Name: ClientName, Version: ClientVersion, Title: ClientTitle},
		Capabilities: caps,
		Bounds:       c.def.Limits.bounds(),
	})
	if err != nil {
		return c.fail(ctx, opConnect, err, FailureTransportClosed)
	}
	if isNilConn(conn) {
		// A transport that reports success with no connection is broken; there
		// is nothing to close and nothing to initialize.
		return c.fail(ctx, opConnect, nil, FailureTransportClosed)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	res, err := conn.Initialize(ctx)
	if err != nil {
		return c.fail(ctx, opInitialize, err, FailureServerProtocol)
	}
	if res.ProtocolVersion == "" {
		// Defence in depth: internal/protocol already rejects this, but a Conn
		// is an interface and the client must not proceed on a handshake that
		// never settled a protocol version.
		return c.fail(ctx, opInitialize, nil, FailureServerProtocol)
	}

	c.mu.Lock()
	c.server = ServerIdentity{Name: res.Server.Name, Version: res.Server.Version, Title: res.Server.Title}
	c.protocolVersion = string(res.ProtocolVersion)
	c.mu.Unlock()

	// A refused transition here means shutdown overtook startup after the
	// handshake succeeded. The conn is established at this point, so this
	// unwinds like any other failed step — the alternative is an open
	// connection owned by nobody.
	if err := c.to(lifecycle.StateReady, opInitialize); err != nil {
		return c.unwind(ctx, err)
	}
	return nil
}

// isNilConn reports whether a transport handed back no connection.
//
// A nil check alone is not enough: a transport returning a typed nil pointer
// (var s *session; return s, nil) produces a non-nil interface holding nil,
// which would panic on the first method call — inside Connect, on the caller's
// goroutine. protocol.Conn is a sealed, module-internal boundary, so that is an
// in-module transport bug rather than hostile input; it is still checked here,
// because turning a transport's bug into a typed error the caller can classify
// costs three lines, and a panic out of Connect costs the host its process.
func isNilConn(conn protocol.Conn) bool {
	if conn == nil {
		return true
	}
	v := reflect.ValueOf(conn)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// to moves the machine, converting a refused transition into a typed error. A
// *lifecycle.TransitionError here does not mean the sequence is wrong: it means
// a concurrent Close legally moved the machine first, so the sequence has been
// overtaken and its caller must unwind.
func (c *Client) to(next lifecycle.State, op string) *Error {
	err := c.machine.To(next)
	if err == nil {
		return nil
	}
	var te *lifecycle.TransitionError
	if errors.As(err, &te) {
		return NewError(FailureShutdown, c.def.Name, op, "binding is shutting down", err)
	}
	return NewError(FailureIndeterminate, c.def.Name, op, "lifecycle transition failed", err)
}

// fail classifies a failed startup step and unwinds it.
func (c *Client) fail(ctx context.Context, op string, err error, fallback FailureClass) error {
	return c.unwind(ctx, c.classify(ctx, op, err, fallback))
}

// unwind abandons startup: it records the failure, marks the binding failed and
// closes the transport, returning the *Error Connect gives the caller.
//
// Every failing path routes through here, including a refused transition — the
// one path where the failure is that someone else is already closing. Skipping
// the close there would be the worst version of the bug: the conn is
// established, Connect returns nil, and nothing else holds a reference to it.
// The transport is therefore closed regardless of what the machine says, and
// closing it twice is impossible (connOnce), so racing Close is harmless.
func (c *Client) unwind(ctx context.Context, out *Error) error {
	c.recordFailure(out)
	// A refused transition means shutdown is already running. Either way the
	// caller gets the failure that actually happened, not the transition's.
	_ = c.machine.To(lifecycle.StateFailed)
	// The startup context may already be done — indeed on the timeout and
	// cancellation paths it always is — which would stop a transport from
	// closing cleanly. Give the close its own bounded context.
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.def.Timeouts.Startup)
	defer cancel()
	_ = c.closeConn(closeCtx)
	return out
}

// classify turns a step's failure into a typed *Error.
//
// An *Error from a transport or Conn is authoritative and passes through
// untouched: it knows what went wrong better than its caller does. Otherwise
// context errors are read first — a startup that ran out of time is a startup
// timeout, and a cancelled caller is a cancellation, whatever the step called
// the resulting error — and everything else takes the step's fallback class.
func (c *Client) classify(ctx context.Context, op string, err error, fallback FailureClass) *Error {
	var typed *Error
	if err != nil && errors.As(err, &typed) {
		return typed
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return NewError(FailureCancelled, c.def.Name, op, "startup was cancelled", err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return NewError(FailureStartupTimeout, c.def.Name, op, "startup exceeded "+c.def.Timeouts.Startup.String(), err)
	}
	if err == nil {
		// A step that failed without an error of its own: say what the client
		// observed rather than render an empty message.
		return NewError(fallback, c.def.Name, op, "the "+c.def.Transport.Kind()+" transport did not establish a usable session", nil)
	}
	return NewError(fallback, c.def.Name, op, "", err)
}

// recordFailure stores a bounded summary of err for Status.
func (c *Client) recordFailure(err *Error) {
	f := &Failure{Class: err.Class, Message: err.Msg}
	if f.Message == "" {
		// Error renders the wrapped cause when Msg is empty, bounding it as it
		// goes; Status must carry the same bounded text, never the raw cause.
		f.Message = boundMessage(err.Error())
	}
	c.mu.Lock()
	c.failure = f
	c.mu.Unlock()
}

// closeConn closes the transport at most once, whichever path gets there first.
func (c *Client) closeConn(ctx context.Context) error {
	c.connOnce.Do(func() {
		// Read the conn under the lock — startup may still be assigning it —
		// but never call into it while holding one.
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn != nil {
			c.connErr = conn.Close(ctx)
		}
	})
	if c.connErr != nil {
		return NewError(FailureTransportClosed, c.def.Name, opClose, "closing the transport failed", c.connErr)
	}
	return nil
}

// Status returns a snapshot of the binding's observable state. It carries safe
// metadata only — no credentials, no payloads — and is a value, so the caller
// may keep or mutate it freely.
func (c *Client) Status() Status {
	// The transport's own accessors are called outside c.mu: they are foreign
	// code, and nothing the client guards should be held across a call into it.
	s := Status{
		Binding:        c.def.Name,
		State:          fromLifecycle(c.machine.State()),
		TransportKind:  c.def.Transport.Kind(),
		RedactedOrigin: c.def.Transport.RedactedOrigin(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	s.ProtocolVersion = c.protocolVersion
	s.Server = c.server
	s.LastChange = c.lastChange
	if c.failure != nil {
		// Copy: a caller must not be able to rewrite the client's own record.
		f := *c.failure
		s.Failure = &f
	}
	return s
}

// Close shuts the binding down and releases its transport. It is idempotent and
// safe to call concurrently: the first call performs the shutdown and reports
// any error closing the transport; later calls do nothing and return nil.
//
// Closing a binding that already failed is not an error — shutdown is
// reachable from every non-terminal state, and a caller must never have to know
// which state it is in to release the resources.
func (c *Client) Close(ctx context.Context) error {
	var (
		first bool
		err   error
	)
	c.closeOnce.Do(func() {
		first = true
		// Both transitions may be refused (the binding is already closed, or
		// terminal). Shutdown is best-effort by design: the transport must be
		// released regardless of what the machine says.
		_ = c.machine.To(lifecycle.StateClosing)
		err = c.closeConn(ctx)
		_ = c.machine.To(lifecycle.StateClosed)
		c.unwatch()
		// Drop the watcher's reference to this Client along with the callback
		// it captured, so neither outlives the binding.
		c.unwatch = nil
	})
	if !first {
		return nil
	}
	return err
}
