//go:build integration

// Integration tests for candidate generations, against the real fixture MCP
// server over a real stdio subprocess.
//
// The unit tests drive the OnListChanged callback directly, which proves what
// the client does with a notification. These prove the part no fake can: that a
// real SDK server changing its tool list really does emit
// notifications/tools/list_changed, that it really reaches this client through
// the transport and the SDK's notification dispatch, and that the refetch it
// triggers really sees the server's new catalog.

package client_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/pkg/client"
)

// awaitCandidate polls until the binding has a candidate, failing if none
// arrives. The server's notification is debounced by the SDK and the refetch is
// asynchronous, so there is nothing to synchronize on but the outcome.
func awaitCandidate(t *testing.T, c *client.Client) client.Catalog {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if cand, ok := c.Candidate(); ok {
			return cand
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for a candidate generation")
	return client.Catalog{}
}

// mutate drives the fixture's "mutate" tool, which adds or removes a tool at
// runtime and so makes the server emit a real tools/list_changed.
func mutate(t *testing.T, c *client.Client, add bool) {
	t.Helper()
	args, err := json.Marshal(mcptest.MutateInput{Add: add})
	if err != nil {
		t.Fatalf("marshaling mutate args: %v", err)
	}
	res, err := c.CallTool(testCtx(t), mcptest.ToolMutate, args, client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool(%q) error = %v", mcptest.ToolMutate, err)
	}
	if res.IsError {
		t.Fatalf("CallTool(%q) reported a tool error: %+v", mcptest.ToolMutate, res.Content)
	}
}

// TestIntegrationListChangedProducesCandidate is the design's change-notification
// sequence end to end against a real server: it changes its tools, says so, and
// the binding ends up with a validated candidate that the caller — not the
// client — adopts.
func TestIntegrationListChangedProducesCandidate(t *testing.T) {
	t.Parallel()

	events := make(chan client.Event, 64)
	c := fixtureClient(t, client.Handlers{
		Event: func(e client.Event) {
			// Non-blocking: this runs on the connection's notification
			// goroutine, and a test that wedged it would deadlock the client
			// rather than fail.
			select {
			case events <- e:
			default:
			}
		},
	}, nil, "-mutate")

	first := c.Catalog()
	if first.Generation != 1 {
		t.Fatalf("adopted generation = %d, want 1 after startup", first.Generation)
	}
	if _, ok := first.ToolByRawName(mcptest.ToolMutated); ok {
		t.Fatalf("the fixture already offers %q before any mutation", mcptest.ToolMutated)
	}

	// The server grows a tool. This is a real AddTool on a real server, which
	// really emits the notification.
	mutate(t, c, true)

	cand := awaitCandidate(t, c)
	if _, ok := cand.ToolByRawName(mcptest.ToolMutated); !ok {
		t.Errorf("the candidate does not carry %q, which the server added", mcptest.ToolMutated)
	}
	if cand.Generation <= first.Generation {
		t.Errorf("candidate generation = %d, want one past the adopted %d", cand.Generation, first.Generation)
	}
	if cand.Digest == first.Digest {
		t.Error("the candidate's digest equals the adopted one's, but its tools differ")
	}

	// Still not adopted: only the caller decides that.
	if got := c.Catalog(); got.Generation != first.Generation {
		t.Errorf("adopted generation = %d, want an unchanged %d", got.Generation, first.Generation)
	}
	if _, ok := c.Catalog().ToolByRawName(mcptest.ToolMutated); ok {
		t.Error("the adopted catalog gained the new tool without Adopt")
	}

	// The tool is callable once adopted — proof the candidate describes the
	// server that is actually running, not just a digest that changed.
	if err := c.Adopt(cand.Generation); err != nil {
		t.Fatalf("Adopt(%d) error = %v", cand.Generation, err)
	}
	args, err := json.Marshal(mcptest.EchoInput{Text: "hello"})
	if err != nil {
		t.Fatalf("marshaling echo args: %v", err)
	}
	res, err := c.CallTool(testCtx(t), mcptest.ToolMutated, args, client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool(%q) after adopting: error = %v", mcptest.ToolMutated, err)
	}
	if res.IsError {
		t.Errorf("CallTool(%q) reported a tool error: %+v", mcptest.ToolMutated, res.Content)
	}

	// The whole sequence was reported, in order, to the application.
	waitForEvent[client.CatalogStale](t, events)
	waitForEvent[client.CatalogCandidate](t, events)
	waitForEvent[client.CatalogAdopted](t, events)
}

// TestIntegrationListChangedRemovalProducesCandidate covers the other direction.
// A removed tool must reach the caller as a candidate too: a catalog that only
// ever grows would leave a binding calling tools its server has dropped.
func TestIntegrationListChangedRemovalProducesCandidate(t *testing.T) {
	t.Parallel()

	c := fixtureClient(t, client.Handlers{}, nil, "-mutate")

	mutate(t, c, true)
	added := awaitCandidate(t, c)
	if err := c.Adopt(added.Generation); err != nil {
		t.Fatalf("Adopt(%d) error = %v", added.Generation, err)
	}
	if _, ok := c.Catalog().ToolByRawName(mcptest.ToolMutated); !ok {
		t.Fatalf("the adopted catalog does not carry %q", mcptest.ToolMutated)
	}

	// And now the server takes it away again.
	mutate(t, c, false)
	removed := awaitCandidate(t, c)
	if _, ok := removed.ToolByRawName(mcptest.ToolMutated); ok {
		t.Errorf("the candidate still carries %q, which the server removed", mcptest.ToolMutated)
	}
	if removed.Generation <= added.Generation {
		t.Errorf("candidate generation = %d, want one past %d", removed.Generation, added.Generation)
	}

	if err := c.Adopt(removed.Generation); err != nil {
		t.Fatalf("Adopt(%d) error = %v", removed.Generation, err)
	}
	// A tool that is gone from the adopted catalog is refused by the client
	// rather than sent to the server and failed as an unknown tool.
	_, err := c.CallTool(testCtx(t), mcptest.ToolMutated, json.RawMessage(`{"text":"x"}`), client.CallOpts{})
	if class, ok := client.ClassOf(err); !ok || class != client.FailureToolUnavailable {
		t.Errorf("CallTool on a removed tool: error = %v (class %v), want FailureToolUnavailable", err, class)
	}
}

// waitForEvent drains ch until an event of type E arrives, or the test times
// out.
func waitForEvent[E client.Event](t *testing.T, ch <-chan client.Event) E {
	t.Helper()
	timeout := time.After(testTimeout)
	for {
		select {
		case e := <-ch:
			if typed, ok := e.(E); ok {
				return typed
			}
		case <-timeout:
			var zero E
			t.Fatalf("timed out waiting for a %T event", zero)
			return zero
		}
	}
}
