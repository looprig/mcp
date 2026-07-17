// These tests drive a real MCP server over the SDK's in-memory transport, like
// session_sample_test.go: resource-update delivery is a claim about what this
// module and the SDK do together — the SDK routes a server's notification to the
// handler this module registers — and only a real server emitting a real
// notification can observe it. A config-level check that OnResourceUpdated is
// non-nil would pass even if nothing wired the SDK handler that feeds it, which
// is exactly the dead-end this fix closes.

package protocol_test

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/protocol"
)

// subURI is the resource the resource tests subscribe to.
const subURI = "fixture://static/hello"

// connectResourceProbe wires a server that supports resource subscription and a
// Session whose OnResourceUpdated feeds updates onto updates. It returns the
// server (to emit notifications) and the Session (to subscribe/unsubscribe).
func connectResourceProbe(t *testing.T, updates chan<- protocol.ResourceUpdate) (*mcp.Server, *protocol.Session) {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "resource-probe", Version: "1"}, &mcp.ServerOptions{
		// The SDK advertises resources.subscribe only when both handlers are set,
		// and it tracks the subscription set itself; these no-ops are enough to
		// make the capability real and the notification routable.
		SubscribeHandler:   func(context.Context, *mcp.SubscribeRequest) error { return nil },
		UnsubscribeHandler: func(context.Context, *mcp.UnsubscribeRequest) error { return nil },
	})
	server.AddResource(&mcp.Resource{URI: subURI, Name: "hello"},
		func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: subURI, Text: "hi"}}}, nil
		})

	clientT, serverT := mcp.NewInMemoryTransports()

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	t.Cleanup(cancel)

	ss, err := server.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	cfg := protocol.ConnectConfig{
		Client: protocol.ClientIdentity{Name: "test", Version: "1"},
		Bounds: protocol.Bounds{MaxTextBytes: 1 << 10},
		OnResourceUpdated: func(u protocol.ResourceUpdate) {
			select {
			case updates <- u:
			default:
			}
		},
	}
	s := protocol.NewSession(clientT, cfg)
	if _, err := s.Initialize(ctx); err != nil {
		t.Fatalf("Session.Initialize() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), sessionTimeout)
		defer closeCancel()
		_ = s.Close(closeCtx)
	})
	return server, s
}

// TestResourceUpdateReachesTheCallback is the heart of Fix #4b: a server that
// emits resources/updated for a subscribed resource must have that update
// delivered to OnResourceUpdated carrying the resource URI, rather than dropped
// on the floor with no handler wired.
func TestResourceUpdateReachesTheCallback(t *testing.T) {
	t.Parallel()

	updates := make(chan protocol.ResourceUpdate, 4)
	server, s := connectResourceProbe(t, updates)

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()
	if err := s.Subscribe(ctx, subURI); err != nil {
		t.Fatalf("Session.Subscribe() error = %v", err)
	}

	if err := server.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: subURI}); err != nil {
		t.Fatalf("Server.ResourceUpdated() error = %v", err)
	}

	select {
	case u := <-updates:
		if u.URI != subURI {
			t.Errorf("update URI = %q, want %q", u.URI, subURI)
		}
	case <-time.After(sessionTimeout):
		t.Fatal("no resource update reached the callback: the notification handler is unwired")
	}
}

// TestUnsubscribeStopsUpdates: after Unsubscribe the server routes no further
// updates to this session, so the callback sees nothing. The Unsubscribe
// round-trip completes before the next emit, so the server has dropped the
// subscription by the time it tries to notify.
func TestUnsubscribeStopsUpdates(t *testing.T) {
	t.Parallel()

	updates := make(chan protocol.ResourceUpdate, 4)
	server, s := connectResourceProbe(t, updates)

	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout)
	defer cancel()
	if err := s.Subscribe(ctx, subURI); err != nil {
		t.Fatalf("Session.Subscribe() error = %v", err)
	}

	// While subscribed the pipe is demonstrably live.
	if err := server.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: subURI}); err != nil {
		t.Fatalf("Server.ResourceUpdated() error = %v", err)
	}
	select {
	case <-updates:
	case <-time.After(sessionTimeout):
		t.Fatal("the first update never arrived; the test cannot prove unsubscribe stops a live stream")
	}

	if err := s.Unsubscribe(ctx, subURI); err != nil {
		t.Fatalf("Session.Unsubscribe() error = %v", err)
	}

	// Now the server has no subscriber for this URI, so the emit reaches no one.
	if err := server.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: subURI}); err != nil {
		t.Fatalf("Server.ResourceUpdated() error = %v", err)
	}
	select {
	case u := <-updates:
		t.Errorf("an update arrived after Unsubscribe: %q", u.URI)
	case <-time.After(200 * time.Millisecond):
		// Correct: an unsubscribed session receives no further updates.
	}
}
