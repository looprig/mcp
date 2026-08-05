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

	// Since the SDK bump to v1.7.0, Subscribe's "subscriptions/listen" call
	// (SEP-2575) is fire-and-forget on the client side (see
	// defaultSendingMethodHandler's special case for methodSubscriptionsListen
	// in vendor/.../mcp/shared.go): it returns once the request is dispatched,
	// not once the server has registered the subscription. So the first emit
	// can legitimately race ahead of that registration; retry until it lands or
	// the deadline expires.
	deadline := time.Now().Add(sessionTimeout)
	for {
		if err := server.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: subURI}); err != nil {
			t.Fatalf("Server.ResourceUpdated() error = %v", err)
		}
		select {
		case u := <-updates:
			if u.URI != subURI {
				t.Errorf("update URI = %q, want %q", u.URI, subURI)
			}
			return
		case <-time.After(200 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("no resource update reached the callback: the notification handler is unwired")
			}
		}
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

	// While subscribed the pipe is demonstrably live. Retry the emit: since the
	// SDK bump to v1.7.0, Subscribe's "subscriptions/listen" call (SEP-2575) is
	// fire-and-forget on the client side (see TestResourceUpdateReachesTheCallback),
	// so the first emit can race ahead of the server registering the subscription.
	deadline := time.Now().Add(sessionTimeout)
	for {
		if err := server.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: subURI}); err != nil {
			t.Fatalf("Server.ResourceUpdated() error = %v", err)
		}
		gotFirst := false
		select {
		case <-updates:
			gotFirst = true
		case <-time.After(200 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("the first update never arrived; the test cannot prove unsubscribe stops a live stream")
			}
		}
		if gotFirst {
			break
		}
	}

	// Drain any stragglers: each retry above broadcast its own update, and a
	// slow one can still be in flight, or already buffered, after the first hit
	// unblocked the loop. Waiting out a quiet window with nothing arriving is
	// what makes the "no update after Unsubscribe" assertion below trustworthy.
drain:
	for {
		select {
		case <-updates:
		case <-time.After(300 * time.Millisecond):
			break drain
		}
	}

	if err := s.Unsubscribe(ctx, subURI); err != nil {
		t.Fatalf("Session.Unsubscribe() error = %v", err)
	}

	// Eventually the server has no subscriber for this URI, so an emit reaches
	// no one — but not necessarily the very next one. Since the SDK bump to
	// v1.7.0, Unsubscribe cancels the background "subscriptions/listen" stream
	// (SEP-2575) and returns without waiting for the server to process that
	// cancellation (see ClientSession.Unsubscribe in vendor/.../mcp/client.go):
	// the cancellation notice travels to the server asynchronously, so an emit
	// issued immediately after Unsubscribe returns can still land once while it
	// is in flight. The claim under test is that delivery stops, not that it
	// stops within one RPC: retry until a whole window passes with nothing
	// delivered, and fail only if delivery never stops within sessionTimeout.
	settleDeadline := time.Now().Add(sessionTimeout)
	for {
		if err := server.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{URI: subURI}); err != nil {
			t.Fatalf("Server.ResourceUpdated() error = %v", err)
		}
		select {
		case u := <-updates:
			if time.Now().After(settleDeadline) {
				t.Fatalf("an update (%q) kept arriving after Unsubscribe throughout sessionTimeout", u.URI)
			}
			// Still settling: the server had not yet processed the
			// cancellation. Try again.
		case <-time.After(300 * time.Millisecond):
			return // A whole window passed silent: delivery has stopped.
		}
	}
}
