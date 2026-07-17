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

	// mu guards cs, started and progress. It is never held across a call into
	// the SDK, nor across a progress callback: Close can legally race
	// Initialize, the SDK does its own locking, and a callback is foreign code.
	mu      sync.Mutex
	started bool
	cs      *mcp.ClientSession
	// progress maps a call's progress token to its callback, for the calls
	// currently in flight. Entries are added by CallTool and removed by its
	// defer, so the map is bounded by concurrency, not by call count.
	progress map[string]func(ProgressUpdate)
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

	// Advertising is the intersection of "asked for" and "able to serve", and
	// this is where the second half is known: the capability flags say what the
	// application asked for, and the callbacks say what can actually answer.
	// servesElicit is computed once and governs both the advertisement and the
	// handler registration below, so the two cannot drift apart into a client
	// that claims a capability nothing serves, or serves one it never claimed.
	caps := s.cfg.Capabilities
	servesElicit := caps.Elicitation && s.cfg.OnElicit != nil
	caps.Elicitation = servesElicit

	opts := &mcp.ClientOptions{
		// Explicit, always: a nil Capabilities makes the SDK advertise roots
		// on the client's behalf. Advertising a capability nobody asked for
		// and nothing here can serve is exactly the fail-open this module
		// does not do.
		Capabilities: sdkClientCapabilities(caps),
		// The two server-initiated streams that belong to a request rather than
		// to a capability. Both are registered unconditionally: progress routes
		// only to a call that asked for it, and a log with no OnLog installed is
		// dropped — registering them costs nothing and un-registering them
		// would mean a notification arriving with nowhere to go.
		ProgressNotificationHandler: func(_ context.Context, req *mcp.ProgressNotificationClientRequest) {
			s.onProgress(req.Params)
		},
		LoggingMessageHandler: func(_ context.Context, req *mcp.LoggingMessageRequest) {
			s.onLog(req.Params)
		},
		// The list-change notifications. Registered unconditionally for the same
		// reason as the two above: a notification with no OnListChanged installed
		// is dropped here, where declining to register it would leave the SDK
		// logging an unhandled notification instead.
		ToolListChangedHandler: func(_ context.Context, _ *mcp.ToolListChangedRequest) {
			s.onListChanged(ListFamilyTools)
		},
		PromptListChangedHandler: func(_ context.Context, _ *mcp.PromptListChangedRequest) {
			s.onListChanged(ListFamilyPrompts)
		},
		ResourceListChangedHandler: func(_ context.Context, _ *mcp.ResourceListChangedRequest) {
			s.onListChanged(ListFamilyResources)
		},
	}

	// Elicitation, unlike every handler above, is registered conditionally —
	// and the condition is the whole point.
	//
	// The SDK auto-advertises the elicitation capability whenever this field is
	// non-nil, overriding the explicit Capabilities set just above (see its
	// Client.clientCapabilities). So registering it unconditionally, the way a
	// notification handler is registered, would put a capability on the wire for
	// a client that never asked for one — the same fail-open the explicit
	// Capabilities exists to prevent, arriving through a different door.
	//
	// Both halves are required and neither implies the other: the config's
	// Capabilities is what the application *asked* for, and OnElicit is what can
	// actually serve it. A capability is only honorable when it is both — which
	// is why servesElicit, and not either fact alone, is what governs here and
	// what was advertised above.
	if servesElicit {
		opts.ElicitationHandler = func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return s.onElicit(ctx, req.Params)
		}
	}

	client := mcp.NewClient(&mcp.Implementation{
		Name:    s.cfg.Client.Name,
		Version: s.cfg.Client.Version,
		Title:   s.cfg.Client.Title,
	}, opts)

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

// errNotInitialized reports a request made before the handshake settled. It is
// a caller bug: every method other than Initialize and Close needs a live
// session, and the client only issues them from a state the handshake produced.
var errNotInitialized = errors.New("protocol: session is not initialized")

// established returns the live SDK session, or an error if there is none.
//
// Every request method funnels through it, so "the session went away" is
// reported once, as a typed error, rather than as a nil dereference on whatever
// goroutine happened to make the call. Close nils nothing, so a session closed
// concurrently with a call still reaches the SDK, which reports the closure
// itself — that is the SDK's race to lose, and it loses it with an error.
func (s *Session) established() (*mcp.ClientSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cs == nil {
		return nil, errNotInitialized
	}
	return s.cs, nil
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
