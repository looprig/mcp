// These tests drive a real MCP server over the SDK's in-memory transport.
//
// They are not integration tests: nothing here crosses a process boundary, so
// they run in the default suite where they belong. What they buy over the
// conversion tables in elicit_test.go is the half a table cannot reach — what
// this module actually puts on the wire at initialize, and what a server
// actually receives when it asks a question. The capability guard in particular
// is only meaningful as observed by a server: it is a claim about the handshake,
// and the SDK writes the handshake.

package protocol_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/protocol"
)

// sessionTimeout bounds each test's own work. Generous: a slow box must not turn
// an assertion into a flake, and every test here fails on its own terms.
const sessionTimeout = 30 * time.Second

// elicitProbe is a server that captures what the client advertised and, on
// demand, asks it a question.
type elicitProbe struct {
	mu sync.Mutex
	// caps is the client's advertised elicitation capability as the server saw
	// it, captured once the handshake settles.
	caps *mcp.ElicitationCapabilities
	// capsSeen reports whether the handshake was observed at all, so a test can
	// tell "the client advertised nothing" from "nothing was ever checked".
	capsSeen bool
}

// connectProbe wires a server and a Session over an in-memory pair, and returns
// the probe, the live server session, and the client Session.
//
// The server's tool is what makes the elicitation observable in a request/reply
// shape: a server may only speak unprompted after initialize, so "the client
// calls a tool, the server asks a question while answering it" is the
// deterministic way to exercise the seam — no sleeping, no polling.
func connectProbe(t *testing.T, cfg protocol.ConnectConfig) (*elicitProbe, *mcp.ServerSession, *protocol.Session) {
	t.Helper()

	probe := &elicitProbe{}
	server := mcp.NewServer(&mcp.Implementation{Name: "probe", Version: "1"}, nil)

	clientT, serverT := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	t.Cleanup(cancel)

	ss, err := server.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	s := protocol.NewSession(clientT, cfg)
	if _, err := s.Initialize(ctx); err != nil {
		t.Fatalf("Session.Initialize() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), sessionTimeout)
		defer closeCancel()
		_ = s.Close(closeCtx)
	})

	probe.mu.Lock()
	if params := ss.InitializeParams(); params != nil && params.Capabilities != nil {
		probe.caps = params.Capabilities.Elicitation
		probe.capsSeen = true
	}
	probe.mu.Unlock()

	return probe, ss, s
}

// advertisedElicitation reports the client's elicitation capability as the
// server saw it.
func (p *elicitProbe) advertisedElicitation(t *testing.T) *mcp.ElicitationCapabilities {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.capsSeen {
		t.Fatal("the server never saw the client's capabilities: this guard would vacuously pass")
	}
	return p.caps
}

// TestElicitationCapabilityIsNotAdvertisedUnlessAsked is the fail-open guard,
// and it is the reason the SDK handler is registered conditionally.
//
// The hazard is specific and silent: the SDK auto-advertises the elicitation
// capability whenever ClientOptions.ElicitationHandler is non-nil, *overriding*
// the explicit Capabilities this module sets. So a client that installed a
// callback but never asked for the capability would tell every server it may ask
// this host questions — a capability nobody requested, arriving on the wire
// because of an implementation detail two layers down.
//
// Only the server can see this, which is why it is asserted from there.
func TestElicitationCapabilityIsNotAdvertisedUnlessAsked(t *testing.T) {
	t.Parallel()

	// A callback that would serve elicitation if one were ever routed to it. Its
	// presence is the trap: it is exactly what makes the SDK advertise.
	serve := func(context.Context, protocol.ElicitRequest) (protocol.ElicitResult, error) {
		return protocol.ElicitResult{Action: protocol.ElicitDecline}, nil
	}

	tests := []struct {
		name string
		caps protocol.ClientCapabilities
		// onElicit says whether a callback is installed.
		onElicit bool
		// want is whether the server must see the capability.
		want bool
	}{
		{
			name:     "asked for and able to serve: advertised",
			caps:     protocol.ClientCapabilities{Elicitation: true},
			onElicit: true,
			want:     true,
		},
		{
			name: "able to serve but never asked for: NOT advertised. " +
				"This is the SDK's auto-advertisement, and it must not reach the wire",
			caps:     protocol.ClientCapabilities{},
			onElicit: true,
			want:     false,
		},
		{
			name:     "asked for but nothing to serve it: NOT advertised",
			caps:     protocol.ClientCapabilities{Elicitation: true},
			onElicit: false,
			want:     false,
		},
		{
			name:     "neither: not advertised",
			caps:     protocol.ClientCapabilities{},
			onElicit: false,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := protocol.ConnectConfig{
				Client:       protocol.ClientIdentity{Name: "test", Version: "1"},
				Capabilities: tt.caps,
				Bounds:       elicitBounds(),
			}
			if tt.onElicit {
				cfg.OnElicit = serve
			}

			probe, _, _ := connectProbe(t, cfg)
			got := probe.advertisedElicitation(t) != nil
			if got != tt.want {
				t.Errorf("the server saw elicitation advertised = %v, want %v.\n"+
					"Capabilities.Elicitation = %v, OnElicit installed = %v.\n"+
					"A capability is advertised only when the application asked for it AND something can serve it.",
					got, tt.want, tt.caps.Elicitation, tt.onElicit)
			}
		})
	}
}

// TestSessionServesElicitation is the whole seam, end to end against a real
// server: the server asks, the neutral request reaches the config's callback,
// the callback's answer reaches the server.
func TestSessionServesElicitation(t *testing.T) {
	t.Parallel()

	var got protocol.ElicitRequest
	var mu sync.Mutex

	cfg := protocol.ConnectConfig{
		Client:       protocol.ClientIdentity{Name: "test", Version: "1"},
		Capabilities: protocol.ClientCapabilities{Elicitation: true},
		Bounds:       elicitBounds(),
		OnElicit: func(_ context.Context, req protocol.ElicitRequest) (protocol.ElicitResult, error) {
			mu.Lock()
			got = req
			mu.Unlock()
			return protocol.ElicitResult{
				Action:  protocol.ElicitAccept,
				Content: json.RawMessage(`{"name":"ada"}`),
			}, nil
		},
	}
	_, ss, _ := connectProbe(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	res, err := ss.Elicit(ctx, &mcp.ElicitParams{
		Mode:    "form",
		Message: "your name?",
		RequestedSchema: json.RawMessage(
			`{"type":"object","properties":{"name":{"type":"string"}}}`),
	})
	if err != nil {
		t.Fatalf("the server's Elicit failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if got.Mode != protocol.ElicitModeForm {
		t.Errorf("the handler saw mode %v, want form", got.Mode)
	}
	if got.Message != "your name?" {
		t.Errorf("the handler saw message %q, want the server's", got.Message)
	}
	if len(got.Schema) == 0 {
		t.Error("the handler saw no schema, so it could not have validated an answer")
	}
	if res.Action != "accept" {
		t.Errorf("the server was told %q, want accept", res.Action)
	}
	if res.Content["name"] != "ada" {
		t.Errorf("the server received content %v, want the handler's answer", res.Content)
	}
}

// TestSessionUnknownModeNeverReachesAHuman pins the system's behavior: a server
// that sends an unrecognized mode is refused, and no handler is troubled.
//
// Read what this does and does not prove. It does NOT prove this module's
// unknown-mode guard: the SDK's own client validates the mode and refuses it
// before ElicitationHandler is ever called (see its Client.elicit default
// branch), so this test passes even with elicitMode's rejection deleted —
// verified by mutation. Our guard is proved by TestFromSDKElicitParams, which
// drives the conversion directly and does fail when it is removed.
//
// It is kept because it pins the property end to end regardless of which layer
// enforces it, and because it would catch an SDK version that stopped
// enforcing it — at which point our guard becomes the only thing standing
// there, and this test starts testing it.
func TestSessionUnknownModeNeverReachesAHuman(t *testing.T) {
	t.Parallel()

	var called int
	var mu sync.Mutex
	cfg := protocol.ConnectConfig{
		Client:       protocol.ClientIdentity{Name: "test", Version: "1"},
		Capabilities: protocol.ClientCapabilities{Elicitation: true},
		Bounds:       elicitBounds(),
		OnElicit: func(context.Context, protocol.ElicitRequest) (protocol.ElicitResult, error) {
			mu.Lock()
			called++
			mu.Unlock()
			return protocol.ElicitResult{Action: protocol.ElicitAccept}, nil
		},
	}
	_, ss, _ := connectProbe(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	res, err := ss.Elicit(ctx, &mcp.ElicitParams{Mode: "voice", Message: "speak"})
	if err == nil {
		t.Fatalf("the server's Elicit succeeded with %+v, want a refusal: an unknown mode was answered", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if called != 0 {
		t.Errorf("the handler was called %d times for an unknown mode, want 0: "+
			"a human was asked a question this module cannot describe", called)
	}
}

// TestSessionRefusesOverBoundMessageToTheServer: the message bound, observed
// where it matters — the server is refused and no handler is troubled.
func TestSessionRefusesOverBoundMessageToTheServer(t *testing.T) {
	t.Parallel()

	var called int
	var mu sync.Mutex
	cfg := protocol.ConnectConfig{
		Client:       protocol.ClientIdentity{Name: "test", Version: "1"},
		Capabilities: protocol.ClientCapabilities{Elicitation: true},
		Bounds:       elicitBounds(),
		OnElicit: func(context.Context, protocol.ElicitRequest) (protocol.ElicitResult, error) {
			mu.Lock()
			called++
			mu.Unlock()
			return protocol.ElicitResult{Action: protocol.ElicitAccept}, nil
		},
	}
	_, ss, _ := connectProbe(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	// One byte over elicitBounds().MaxElicitMessageBytes.
	huge := strings.Repeat("m", 65)
	if _, err := ss.Elicit(ctx, &mcp.ElicitParams{Mode: "form", Message: huge}); err == nil {
		t.Fatal("the server's over-bound prompt was accepted, want a refusal")
	}
	mu.Lock()
	defer mu.Unlock()
	if called != 0 {
		t.Errorf("the handler was called %d times with an over-bound prompt, want 0", called)
	}
}

// TestSessionCarriesHandlerErrorToTheServer: a handler that fails must leave the
// server with an error rather than a silence it waits out — and rather than an
// answer nobody gave.
func TestSessionCarriesHandlerErrorToTheServer(t *testing.T) {
	t.Parallel()

	errRefused := errors.New("the host refused")
	cfg := protocol.ConnectConfig{
		Client:       protocol.ClientIdentity{Name: "test", Version: "1"},
		Capabilities: protocol.ClientCapabilities{Elicitation: true},
		Bounds:       elicitBounds(),
		OnElicit: func(context.Context, protocol.ElicitRequest) (protocol.ElicitResult, error) {
			return protocol.ElicitResult{}, errRefused
		},
	}
	_, ss, _ := connectProbe(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	if _, err := ss.Elicit(ctx, &mcp.ElicitParams{Mode: "form", Message: "hi"}); err == nil {
		t.Fatal("the server's Elicit succeeded though the handler failed")
	}
}

// TestSessionRefusesElicitationWhenNotAdvertised is the guard's other face: a
// client that did not advertise the capability must be unaskable. The SDK's
// server enforces this, so what this pins is that our non-advertisement is real
// enough for a real server to act on — not merely absent from a struct.
func TestSessionRefusesElicitationWhenNotAdvertised(t *testing.T) {
	t.Parallel()

	var called int
	var mu sync.Mutex
	cfg := protocol.ConnectConfig{
		Client: protocol.ClientIdentity{Name: "test", Version: "1"},
		// Never asked for — but with a callback installed, which is what would
		// make the SDK advertise it if the guard were gone.
		Capabilities: protocol.ClientCapabilities{},
		Bounds:       elicitBounds(),
		OnElicit: func(context.Context, protocol.ElicitRequest) (protocol.ElicitResult, error) {
			mu.Lock()
			called++
			mu.Unlock()
			return protocol.ElicitResult{Action: protocol.ElicitAccept}, nil
		},
	}
	_, ss, _ := connectProbe(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	if _, err := ss.Elicit(ctx, &mcp.ElicitParams{Mode: "form", Message: "hi"}); err == nil {
		t.Fatal("a server elicited a client that never advertised elicitation")
	}
	mu.Lock()
	defer mu.Unlock()
	if called != 0 {
		t.Errorf("the handler ran %d times on a binding that advertised no elicitation, want 0", called)
	}
}
