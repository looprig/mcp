// These tests drive a real MCP server over the SDK's in-memory transport, for
// the reason session_elicit_test.go gives: the capability guard is a claim about
// the handshake, and only a server can observe a handshake.
//
// Sampling has a second reason. The SDK advertises the sampling capability by
// itself the moment a CreateMessageHandler is registered, whatever this module
// asked for — so "does registering a handler advertise the capability" is not a
// question about this module's code in isolation. It is a question about what
// this module and the SDK do together, and a table cannot answer it.

package protocol_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/internal/protocol"
)

// sampleProbe is a server that captures what the client advertised and, on
// demand, asks it for a completion.
type sampleProbe struct {
	mu sync.Mutex
	// caps is the client's advertised sampling capability as the server saw it.
	//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
	caps *mcp.SamplingCapabilities
	// capsSeen reports whether the handshake was observed at all, so a test can
	// tell "the client advertised nothing" from "nothing was ever checked".
	capsSeen bool
	// ss is the live server session, which is what asks for sampling.
	ss *mcp.ServerSession
}

// connectSampleProbe wires a server and a Session over an in-memory pair.
func connectSampleProbe(t *testing.T, cfg protocol.ConnectConfig) *sampleProbe {
	t.Helper()
	return connectSampleProbeTransport(t, cfg, false)
}

// connectSampleProbeLegacy is connectSampleProbe, but pins the session to
// protocol revisions <= mcptest.LegacyProtocolVersion (see
// mcptest.PinLegacyProtocol), so a test may drive an ad hoc
// ServerSession.CreateMessage call: SDK v1.7.0 forbids that once the
// negotiated protocol version reaches 2026-07-28 (SEP-2322), and offers no
// other way to request an older version from an in-memory test peer.
func connectSampleProbeLegacy(t *testing.T, cfg protocol.ConnectConfig) *sampleProbe {
	t.Helper()
	return connectSampleProbeTransport(t, cfg, true)
}

func connectSampleProbeTransport(t *testing.T, cfg protocol.ConnectConfig, legacy bool) *sampleProbe {
	t.Helper()

	probe := &sampleProbe{}
	server := mcp.NewServer(&mcp.Implementation{Name: "sample-probe", Version: "1"}, nil)
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
		//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
		probe.caps = params.Capabilities.Sampling
		probe.capsSeen = true
	}
	probe.ss = ss
	probe.mu.Unlock()

	return probe
}

// advertisedSampling reports the client's sampling capability as the server saw
// it.
//
//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
func (p *sampleProbe) advertisedSampling(t *testing.T) *mcp.SamplingCapabilities {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.capsSeen {
		t.Fatal("the server never observed the client's initialize params")
	}
	return p.caps
}

// okSample is a callback that always completes.
func okSample(_ context.Context, _ protocol.SampleRequest) (protocol.SampleResult, error) {
	return protocol.SampleResult{Model: "test-model", Text: "hello"}, nil
}

// sampleConfig is a config with generous bounds and the given capability and
// callback.
func sampleConfig(advertise bool, fn func(context.Context, protocol.SampleRequest) (protocol.SampleResult, error)) protocol.ConnectConfig {
	return protocol.ConnectConfig{
		Client:       protocol.ClientIdentity{Name: "test", Version: "1"},
		Capabilities: protocol.ClientCapabilities{Sampling: advertise},
		Bounds:       protocol.Bounds{MaxTextBytes: 1 << 10},
		OnSample:     fn,
	}
}

// TestSamplingAdvertisement is the capability guard, observed from the only
// place it means anything: the server's copy of the handshake.
//
// The "handler but no capability" case is the one that matters most. It is the
// SDK's documented fail-open — a registered CreateMessageHandler makes it
// advertise sampling on the client's behalf — and this module's answer is to
// register nothing when the application did not ask. A client that never asked
// to spend money on a server's behalf must not be made to offer to.
func TestSamplingAdvertisement(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		advertise bool
		handler   func(context.Context, protocol.SampleRequest) (protocol.SampleResult, error)
		want      bool
	}{
		{
			name:      "requested and handled is advertised",
			advertise: true,
			handler:   okSample,
			want:      true,
		},
		{
			name:      "requested with no handler is not advertised",
			advertise: true,
			handler:   nil,
			want:      false,
		},
		{
			name:      "handler with no request is not advertised",
			advertise: false,
			handler:   okSample,
			want:      false,
		},
		{
			name:      "neither is not advertised",
			advertise: false,
			handler:   nil,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			probe := connectSampleProbe(t, sampleConfig(tt.advertise, tt.handler))
			if got := probe.advertisedSampling(t) != nil; got != tt.want {
				t.Errorf("server saw sampling advertised = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSamplingAdvertisesNoSubCapabilities pins the shape of the advertisement,
// not just its presence.
//
// Both sub-capabilities are things a server checks for before asking, so a nil
// one is what stops it asking. Tools nil is the structural half of "sampling
// never receives an unrestricted tool registry": a server that cannot see the
// Tools capability does not send tools, and the SDK will not route a
// tool-bearing request to the basic handler this module registers. Context nil
// stops a server asking the host to harvest other servers' data into a prompt.
func TestSamplingAdvertisesNoSubCapabilities(t *testing.T) {
	t.Parallel()

	probe := connectSampleProbe(t, sampleConfig(true, okSample))
	caps := probe.advertisedSampling(t)
	if caps == nil {
		t.Fatal("sampling was not advertised")
	}
	if caps.Tools != nil {
		t.Errorf("Tools = %+v, want nil: advertising it invites tool-bearing sampling requests", caps.Tools)
	}
	if caps.Context != nil {
		t.Errorf("Context = %+v, want nil: advertising it invites context-harvesting requests", caps.Context)
	}
}

// TestSamplingRoundTrip drives a real sampling request from a real server and
// checks what the server gets back.
func TestSamplingRoundTrip(t *testing.T) {
	t.Parallel()

	var got protocol.SampleRequest
	var mu sync.Mutex
	probe := connectSampleProbeLegacy(t, sampleConfig(true, func(_ context.Context, req protocol.SampleRequest) (protocol.SampleResult, error) {
		mu.Lock()
		got = req
		mu.Unlock()
		return protocol.SampleResult{Model: "test-model", Text: "hi back", StopReason: "endTurn"}, nil
	}))

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
	res, err := probe.ss.CreateMessage(ctx, &mcp.CreateMessageParams{
		MaxTokens:    100,
		SystemPrompt: "be brief",
		//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
		Messages: []*mcp.SamplingMessage{textMsg("user", "hello")},
		// The server's preference, which the host is free to ignore — and does:
		// nothing carries it to the handler.
		//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
		ModelPreferences: &mcp.ModelPreferences{Hints: []*mcp.ModelHint{{Name: "server-choice"}}},
	})
	if err != nil {
		t.Fatalf("ServerSession.CreateMessage() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if got.SystemPrompt != "be brief" {
		t.Errorf("handler got SystemPrompt = %q, want %q", got.SystemPrompt, "be brief")
	}
	if len(got.Messages) != 1 || got.Messages[0].Text != "hello" || got.Messages[0].Role != protocol.SampleRoleUser {
		t.Errorf("handler got Messages = %+v, want one user message %q", got.Messages, "hello")
	}
	if got.MaxTokens != 100 {
		t.Errorf("handler got MaxTokens = %d, want 100", got.MaxTokens)
	}

	if res.Model != "test-model" {
		t.Errorf("server got Model = %q, want %q", res.Model, "test-model")
	}
	if res.Role != "assistant" {
		t.Errorf("server got Role = %q, want %q", res.Role, "assistant")
	}
	text, ok := res.Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("server got Content = %T, want *mcp.TextContent", res.Content)
	}
	if text.Text != "hi back" {
		t.Errorf("server got Text = %q, want %q", text.Text, "hi back")
	}
	if res.StopReason != "endTurn" {
		t.Errorf("server got StopReason = %q, want %q", res.StopReason, "endTurn")
	}
}

// TestSamplingRefusalReachesServer checks that a host's "no" is an answer the
// server receives, rather than a silence it waits out.
func TestSamplingRefusalReachesServer(t *testing.T) {
	t.Parallel()

	probe := connectSampleProbe(t, sampleConfig(true, func(_ context.Context, _ protocol.SampleRequest) (protocol.SampleResult, error) {
		return protocol.SampleResult{}, errors.New("the host declined")
	}))

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
	_, err := probe.ss.CreateMessage(ctx, &mcp.CreateMessageParams{
		MaxTokens: 100,
		//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
		Messages: []*mcp.SamplingMessage{textMsg("user", "hello")},
	})
	if err == nil {
		t.Fatal("ServerSession.CreateMessage() error = nil, want the host's refusal")
	}
}

// TestSamplingOverBoundRequestIsRefused checks the bound is enforced against a
// real server, and that the handler never sees the request.
func TestSamplingOverBoundRequestIsRefused(t *testing.T) {
	t.Parallel()

	var called bool
	var mu sync.Mutex
	probe := connectSampleProbe(t, protocol.ConnectConfig{
		Client:       protocol.ClientIdentity{Name: "test", Version: "1"},
		Capabilities: protocol.ClientCapabilities{Sampling: true},
		Bounds:       protocol.Bounds{MaxTextBytes: 16},
		OnSample: func(_ context.Context, _ protocol.SampleRequest) (protocol.SampleResult, error) {
			mu.Lock()
			called = true
			mu.Unlock()
			return protocol.SampleResult{Model: "m"}, nil
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()

	//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
	_, err := probe.ss.CreateMessage(ctx, &mcp.CreateMessageParams{
		MaxTokens: 100,
		//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
		Messages: []*mcp.SamplingMessage{textMsg("user", strings.Repeat("x", 17))},
	})
	if err == nil {
		t.Fatal("ServerSession.CreateMessage() error = nil, want the bound's refusal")
	}
	mu.Lock()
	defer mu.Unlock()
	if called {
		t.Error("the handler was called with an over-bound conversation: the bound must be enforced before foreign code runs")
	}
}
