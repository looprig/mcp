//go:build integration

// Integration tests for bounded reconnection, against the real fixture MCP
// server over real stdio subprocesses.
//
// The unit tests script a transport that hands out conns. These prove the thing
// no script can: that a real server process dying really does surface as a
// classified transport failure, that the reconnect really launches a second
// process and speaks a whole new MCP handshake to it, and that the binding
// really serves calls again afterwards — over the new process, with the old one
// reaped.

package client_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/pkg/client"
	"github.com/looprig/mcp/pkg/transport/stdio"
)

// awaitState polls until the binding reaches want.
func awaitState(t *testing.T, c *client.Client, want client.State) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if got := c.Status().State; got == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for state %v; the binding is %v", want, c.Status().State)
}

// TestIntegrationReconnectAfterServerCrash is the design's reconnect sequence
// against a server that really dies: the fixture's crash tool exits the process
// with a reply outstanding, which is what a server crash looks like from the
// client's end.
func TestIntegrationReconnectAfterServerCrash(t *testing.T) {
	t.Parallel()

	tr, err := stdio.New(stdio.Config{
		Command: mcptest.BuildFixture(t),
		Args:    []string{"-crash", "-mutate"},
	})
	if err != nil {
		t.Fatalf("stdio.New() error = %v", err)
	}

	def := client.Definition{Name: "fixture", Transport: tr}
	// Bounded and quick: a real relaunch costs a process spawn, not a network
	// round trip, so the defaults would only make the test slow.
	def.Reconnect.Attempts = 3
	def.Reconnect.BaseDelay = 10 * time.Millisecond
	def.Reconnect.MaxDelay = 50 * time.Millisecond

	events := make(chan client.Event, 64)
	c, err := client.Connect(testCtx(t), def, client.Handlers{
		Event: func(e client.Event) {
			select {
			case events <- e:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(testCtx(t)) })

	adoptedBefore := c.Catalog()

	// Kill it. The process exits without replying, so the call in flight has no
	// answer and never will.
	_, err = c.CallTool(testCtx(t), mcptest.ToolCrash, json.RawMessage(`{}`), client.CallOpts{})
	if err == nil {
		t.Fatal("CallTool(crash) succeeded; the fixture was supposed to exit")
	}
	// The design's correctness-critical rule, against a real dead process: the
	// call's outcome is unknowable, so it is indeterminate rather than failed.
	if class, ok := client.ClassOf(err); !ok || class != client.FailureIndeterminate {
		t.Errorf("CallTool(crash): error = %v (class %v), want FailureIndeterminate", err, class)
	}

	// A whole new process, a whole new handshake, a whole new catalog.
	awaitState(t, c, client.StateReady)

	// The adopted generation survived the crash untouched.
	if got := c.Catalog(); got.Generation != adoptedBefore.Generation || got.Digest != adoptedBefore.Digest {
		t.Errorf("adopted catalog = (gen %d, %q) after a reconnect, want the unchanged (gen %d, %q)",
			got.Generation, got.Digest, adoptedBefore.Generation, adoptedBefore.Digest)
	}

	// And the binding really works: this call runs on the replacement process.
	args, err := json.Marshal(mcptest.EchoInput{Text: "alive"})
	if err != nil {
		t.Fatalf("marshaling echo args: %v", err)
	}
	res, err := c.CallTool(testCtx(t), mcptest.ToolEcho, args, client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool(echo) after a reconnect: error = %v", err)
	}
	if res.IsError {
		t.Errorf("CallTool(echo) after a reconnect reported a tool error: %+v", res.Content)
	}

	// The new connection is a live MCP peer in its own right: its notifications
	// route to this binding, and produce a candidate exactly as before.
	mutate(t, c, true)
	cand := awaitCandidate(t, c)
	if _, ok := cand.ToolByRawName(mcptest.ToolMutated); !ok {
		t.Error("the reconnected connection's notifications do not reach the binding")
	}

	// The application was told both halves of the story.
	lost := waitForEvent[client.ConnectionLost](t, events)
	if !lost.Retrying || lost.Adopted != adoptedBefore.Generation {
		t.Errorf("ConnectionLost = %+v, want a retrying loss over the still-adopted generation %d", lost, adoptedBefore.Generation)
	}
	restored := waitForEvent[client.ConnectionRestored](t, events)
	if restored.Server.Name != mcptest.ServerName {
		t.Errorf("ConnectionRestored.Server.Name = %q, want the fixture's %q", restored.Server.Name, mcptest.ServerName)
	}
	if restored.Drift != "" {
		t.Errorf("ConnectionRestored.Drift = %q, want empty: the relaunched fixture is the same server", restored.Drift)
	}
}

// TestIntegrationReconnectBoundedAgainstADeadCommand: a server that cannot be
// relaunched must not be retried forever. The binding spends its budget and
// reports failure — with every process it started along the way reaped, which
// the stdio transport's own cleanup guards and this must not defeat.
func TestIntegrationReconnectBoundedAgainstADeadCommand(t *testing.T) {
	t.Parallel()

	// A fixture that crashes on demand, plus a transport whose command will stop
	// existing: the binary is built into a temp dir the test removes, so every
	// redial fails at exec.
	fixture := mcptest.BuildFixture(t)
	tr, err := stdio.New(stdio.Config{Command: fixture, Args: []string{"-crash"}})
	if err != nil {
		t.Fatalf("stdio.New() error = %v", err)
	}

	def := client.Definition{Name: "fixture", Transport: tr}
	def.Reconnect.Attempts = 2
	def.Reconnect.BaseDelay = 5 * time.Millisecond
	def.Reconnect.MaxDelay = 10 * time.Millisecond
	def.Reconnect.MaxTotal = 5 * time.Second

	c, err := client.Connect(testCtx(t), def, client.Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(testCtx(t)) })

	// The binary lives in this test's own TempDir, so removing it affects
	// nothing else. Every redial now fails at exec, which is a server that
	// cannot be relaunched — the case a bound exists for.
	if err := os.Remove(fixture); err != nil {
		t.Fatalf("removing the fixture binary: %v", err)
	}

	if _, err := c.CallTool(testCtx(t), mcptest.ToolCrash, json.RawMessage(`{}`), client.CallOpts{}); err == nil {
		t.Fatal("CallTool(crash) succeeded; the fixture was supposed to exit")
	}

	// It cannot come back, and it stops trying.
	awaitState(t, c, client.StateFailed)
	if st := c.Status(); st.Failure == nil {
		t.Error("a binding that exhausted its reconnect budget reports no failure")
	}
}
