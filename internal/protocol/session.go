// This file holds the module's only SDK-backed Conn: a thin wrapper around one
// mcp.ClientSession. It lives here, not in a transport, because every transport
// needs exactly this and nothing about it is stdio-specific — the SDK models a
// transport as "something that yields a Connection", so the client session on
// top of it is identical whether the bytes came from a pipe or a socket.
//
// A Session owns the MCP conversation. It does not own whatever produces the
// bytes: a transport that starts a subprocess still terminates and reaps it
// itself, after Session.Close has drained the conversation.

package protocol

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Session is the module's SDK-backed Conn.
var _ Conn = (*Session)(nil)

// errAlreadyInitialized reports a second Initialize on one Session. The MCP
// handshake happens once per connection; a second one is a caller bug, not a
// server defect.
var errAlreadyInitialized = errors.New("protocol: session is already initialized")

// Session is a Conn backed by the MCP Go SDK. It is created unconnected: the
// handshake — which the SDK performs as part of its own Connect — happens in
// Initialize, so that a transport can establish its byte stream (and fail on
// its own terms) before any protocol traffic is attempted.
//
// A Session is safe for concurrent use.
type Session struct {
	transport mcp.Transport
	cfg       ConnectConfig

	// mu guards cs and started. It is never held across a call into the SDK:
	// Close can legally race Initialize, and the SDK does its own locking.
	mu      sync.Mutex
	started bool
	cs      *mcp.ClientSession
}

// NewSession returns an uninitialized Session that will speak MCP over t.
// t must be a transport the SDK has not connected yet: the SDK connects each
// transport exactly once, from Initialize.
func NewSession(t mcp.Transport, cfg ConnectConfig) *Session {
	return &Session{transport: t, cfg: cfg}
}

// Initialize performs the MCP handshake and converts the result.
//
// Errors here are deliberately untyped: this package has no error taxonomy of
// its own and must not import pkg/client. The transport that owns the Session
// classifies the failure, because only it can tell "the server spoke badly"
// from "the process died" — a distinction the SDK reports identically, as a
// closed connection.
func (s *Session) Initialize(ctx context.Context) (InitializeResult, error) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return InitializeResult{}, errAlreadyInitialized
	}
	s.started = true
	s.mu.Unlock()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    s.cfg.Client.Name,
		Version: s.cfg.Client.Version,
		Title:   s.cfg.Client.Title,
	}, &mcp.ClientOptions{
		// Explicit, always: a nil Capabilities makes the SDK advertise roots
		// on the client's behalf. Advertising a capability nobody asked for
		// and nothing here can serve is exactly the fail-open this module
		// does not do.
		Capabilities: sdkClientCapabilities(s.cfg.Capabilities),
	})

	cs, err := client.Connect(ctx, s.transport, nil)
	if err != nil {
		return InitializeResult{}, fmt.Errorf("mcp handshake: %w", err)
	}

	s.mu.Lock()
	s.cs = cs
	s.mu.Unlock()

	res, err := FromSDKInitializeResult(cs.InitializeResult(), s.cfg.Bounds)
	if err != nil {
		// The handshake completed but said something unusable. The session is
		// live and must not be left dangling; the caller gets the conversion's
		// error, not the close's.
		_ = s.Close(ctx)
		return InitializeResult{}, err
	}
	return res, nil
}

// Close ends the MCP conversation. The SDK's session close is graceful — it
// stops accepting new requests and waits for in-flight ones to return before
// tearing the connection down — which is the whole reason a transport must
// route its shutdown through here before it touches the underlying stream. A
// stream yanked from under a pending request loses the reply and makes the peer
// exit on a read error rather than a clean stop.
//
// ctx bounds the wait, so a peer that will not drain cannot block shutdown
// forever; the transport's own teardown (terminate, reap) is what makes that
// case terminal. Closing a Session that was never initialized is a no-op.
func (s *Session) Close(ctx context.Context) error {
	s.mu.Lock()
	cs := s.cs
	s.mu.Unlock()
	if cs == nil {
		return nil
	}

	// The SDK's Close takes no context, so it is run off the caller's
	// goroutine to keep ctx meaningful. The goroutine outlives an abandoned
	// wait, but not the session: it ends when the SDK's close does, which the
	// transport guarantees by killing the process behind it.
	done := make(chan error, 1)
	go func() { done <- cs.Close() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SDKSession returns the underlying SDK session, or nil before Initialize.
//
// It is an escape hatch for the packages inside this module that are allowed to
// speak SDK (see the leak guard's allowlist) and is not, and must not become, a
// way around this package's conversions: everything a caller above the boundary
// consumes still arrives as a neutral, bounded type. The later tasks that add
// tools, prompts and resources add converted methods to Session; until then this
// is what lets a transport's own tests drive real MCP traffic over it.
func (s *Session) SDKSession() *mcp.ClientSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cs
}

// sdkClientCapabilities maps the neutral capability flags onto the SDK's
// nillable capability structs. The client only sets a flag when the application
// both asked for the capability and installed a handler able to serve it, so
// each one is advertised verbatim.
func sdkClientCapabilities(c ClientCapabilities) *mcp.ClientCapabilities {
	caps := &mcp.ClientCapabilities{}
	if c.Roots {
		// RootsV2, not Roots: the SDK derives the deprecated field from it and
		// ignores a value written to the old one.
		caps.RootsV2 = &mcp.RootCapabilities{ListChanged: true}
	}
	if c.Sampling {
		caps.Sampling = &mcp.SamplingCapabilities{}
	}
	if c.Elicitation {
		caps.Elicitation = &mcp.ElicitationCapabilities{}
	}
	return caps
}
