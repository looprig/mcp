// These tests drive a real MCP server over the SDK's in-memory transport, for
// the reason session_sample_test.go gives: whether a capability is advertised,
// and whether the client actually answers a server request for it, are claims
// about the handshake and the wire — and only a server can observe them.
//
// Roots has its own reason to be tested here rather than by inspecting config.
// The SDK answers roots/list from a set the client supplies, not by dispatching
// to a handler this module registers. So "does an installed provider actually
// answer roots/list" is a question about what this module and the SDK do
// together: a config-level assertion that OnRoots is non-nil would pass even if
// nothing ever installed its roots on the SDK client, which is precisely the bug.

package protocol_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/internal/protocol"
)

// rootsProbe is a server that captures what the client advertised and, on
// demand, asks it for its roots.
//
// The SDK always emits a "roots" object on the wire (its value-typed Roots
// field has a broken omitempty, per #607), so presence alone cannot be observed
// from the server. What distinguishes an advertised roots capability is
// listChanged: this module advertises with RootCapabilities{ListChanged:true}
// and declines by sending a bare {}. So the observable signal is that flag.
type rootsProbe struct {
	mu sync.Mutex
	// listChanged is the client's advertised roots.listChanged as the server saw
	// it — true only when this module advertised the capability.
	listChanged bool
	// capsSeen reports whether the handshake was observed at all.
	capsSeen bool
	// ss is the live server session, which is what asks for roots.
	ss *mcp.ServerSession
}

// connectRootsProbe wires a server and a Session over an in-memory pair.
func connectRootsProbe(t *testing.T, cfg protocol.ConnectConfig) *rootsProbe {
	t.Helper()
	return connectRootsProbeTransport(t, cfg, false)
}

// connectRootsProbeLegacy is connectRootsProbe, but pins the session to
// protocol revisions <= mcptest.LegacyProtocolVersion (see
// mcptest.PinLegacyProtocol), so a test may drive an ad hoc
// ServerSession.ListRoots call: SDK v1.7.0 forbids that once the negotiated
// protocol version reaches 2026-07-28 (SEP-2322), and offers no other way to
// request an older version from an in-memory test peer.
func connectRootsProbeLegacy(t *testing.T, cfg protocol.ConnectConfig) *rootsProbe {
	t.Helper()
	return connectRootsProbeTransport(t, cfg, true)
}

func connectRootsProbeTransport(t *testing.T, cfg protocol.ConnectConfig, legacy bool) *rootsProbe {
	t.Helper()

	probe := &rootsProbe{}
	server := mcp.NewServer(&mcp.Implementation{Name: "roots-probe", Version: "1"}, nil)
	clientT, serverT := mcp.NewInMemoryTransports()
	var serverTransport mcp.Transport = serverT
	if legacy {
		serverTransport = mcptest.PinLegacyProtocol(serverT)
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	t.Cleanup(cancel)

	ss, err := server.Connect(ctx, serverTransport, nil)
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
		// The deprecated Roots field, deliberately: RootsV2 carries json:"-", so
		// it never crosses the wire and is always nil on the server's copy. The
		// value-typed Roots field is the ONLY roots signal a server can observe,
		// which is exactly why this test reads it.
		//lint:ignore SA1019 RootsV2 is not serialized; Roots is the only wire-observable signal
		probe.listChanged = params.Capabilities.Roots.ListChanged
		probe.capsSeen = true
	}
	probe.ss = ss
	probe.mu.Unlock()

	return probe
}

// advertisedRoots reports whether the server saw this client advertise the
// roots capability.
func (p *rootsProbe) advertisedRoots(t *testing.T) bool {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.capsSeen {
		t.Fatal("the server never observed the client's initialize params")
	}
	return p.listChanged
}

// rootsConfig is a config with the given capability and roots provider.
func rootsConfig(advertise bool, fn func(context.Context) ([]protocol.Root, error)) protocol.ConnectConfig {
	return protocol.ConnectConfig{
		Client:       protocol.ClientIdentity{Name: "test", Version: "1"},
		Capabilities: protocol.ClientCapabilities{Roots: advertise},
		Bounds:       protocol.Bounds{MaxTextBytes: 1 << 10},
		OnRoots:      fn,
	}
}

// TestRootsAdvertisement is the capability guard, observed from the server's
// copy of the handshake. A provider with no request must not advertise, and a
// request with no provider must not either.
func TestRootsAdvertisement(t *testing.T) {
	t.Parallel()

	oneRoot := func(context.Context) ([]protocol.Root, error) {
		return []protocol.Root{{URI: "file:///work", Name: "work"}}, nil
	}

	tests := []struct {
		name      string
		advertise bool
		provider  func(context.Context) ([]protocol.Root, error)
		want      bool
	}{
		{name: "requested and provided is advertised", advertise: true, provider: oneRoot, want: true},
		{name: "requested with no provider is not advertised", advertise: true, provider: nil, want: false},
		{name: "provider with no request is not advertised", advertise: false, provider: oneRoot, want: false},
		{name: "neither is not advertised", advertise: false, provider: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			probe := connectRootsProbe(t, rootsConfig(tt.advertise, tt.provider))
			if got := probe.advertisedRoots(t); got != tt.want {
				t.Errorf("server saw roots advertised = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRootsRoundTrip is the whole of Fix #4a: a server that calls roots/list
// against a client with an installed provider receives THAT provider's root,
// not the SDK's never-populated empty set.
func TestRootsRoundTrip(t *testing.T) {
	t.Parallel()

	want := protocol.Root{URI: "file:///approved/workspace", Name: "workspace"}
	probe := connectRootsProbeLegacy(t, rootsConfig(true, func(context.Context) ([]protocol.Root, error) {
		return []protocol.Root{want}, nil
	}))

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
	res, err := probe.ss.ListRoots(ctx, nil)
	if err != nil {
		t.Fatalf("ServerSession.ListRoots() error = %v", err)
	}
	if len(res.Roots) != 1 {
		t.Fatalf("server got %d roots, want exactly the provider's one: %+v", len(res.Roots), res.Roots)
	}
	if res.Roots[0].URI != want.URI || res.Roots[0].Name != want.Name {
		t.Errorf("server got root %+v, want %+v", res.Roots[0], want)
	}
}

// TestRootsProviderErrorFailsHandshake: a provider that cannot determine the
// workspace must not yield a binding that advertises roots it will answer empty.
func TestRootsProviderErrorFailsHandshake(t *testing.T) {
	t.Parallel()

	server := mcp.NewServer(&mcp.Implementation{Name: "roots-probe", Version: "1"}, nil)
	clientT, serverT := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	ss, err := server.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	defer func() { _ = ss.Close() }()

	s := protocol.NewSession(clientT, rootsConfig(true, func(context.Context) ([]protocol.Root, error) {
		return nil, errors.New("cannot determine workspace")
	}))
	if _, err := s.Initialize(ctx); err == nil {
		t.Fatal("Session.Initialize() error = nil, want the provider's failure to fail the handshake")
	}
}

// TestRootsBoundAndCanonical: a root with no URI has no identity and is dropped,
// and no more than MaxRoots reach the server, however many the provider returns.
func TestRootsBoundAndCanonical(t *testing.T) {
	t.Parallel()

	probe := connectRootsProbeLegacy(t, rootsConfig(true, func(context.Context) ([]protocol.Root, error) {
		roots := []protocol.Root{{URI: "", Name: "no-uri"}}
		for i := 0; i < protocol.MaxRoots+50; i++ {
			roots = append(roots, protocol.Root{URI: fmt.Sprintf("file:///r%d", i)})
		}
		return roots, nil
	}))

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
	res, err := probe.ss.ListRoots(ctx, nil)
	if err != nil {
		t.Fatalf("ServerSession.ListRoots() error = %v", err)
	}
	if len(res.Roots) != protocol.MaxRoots {
		t.Fatalf("server got %d roots, want the cap %d", len(res.Roots), protocol.MaxRoots)
	}
	for _, r := range res.Roots {
		if r.URI == "" {
			t.Error("a root with no URI reached the server; it has no identity and must be dropped")
		}
	}
}
