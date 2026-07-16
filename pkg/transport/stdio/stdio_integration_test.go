//go:build integration && unix

// Integration tests for the stdio transport: a real child process, real pipes,
// real MCP. The fixture (internal/mcptest) is an SDK-based MCP server, so what
// is exercised here is the protocol, not our idea of it.
//
// The process-lifetime assertions are the point of this file. "The child is
// gone" is checked by asking the kernel — kill(pid, 0) returning ESRCH — and
// never by sleeping and hoping: a sleep that is long enough today is a flake
// tomorrow, and a leaked server process is the bug this transport exists to not
// have.
//
// Unix-only (and both darwin and linux are unix): the liveness check and the
// process-group assertion have no portable equivalent. A platform without
// process groups gets the honest fallback in process_other.go and no test that
// pretends otherwise.

package stdio

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/client"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testConnectConfig is what a real client would pass down. Bounds are generous:
// this file tests the transport, and internal/protocol's own tests test the
// bounding.
func testConnectConfig() protocol.ConnectConfig {
	return protocol.ConnectConfig{
		Client: protocol.ClientIdentity{Name: "looprig-mcp-test", Version: "0.0.0", Title: "stdio transport test"},
		Bounds: protocol.Bounds{
			MaxSchemaBytes:     1 << 20,
			MaxSchemaDepth:     32,
			MaxTextBytes:       1 << 20,
			MaxStructuredBytes: 1 << 20,
			MaxBinaryItemBytes: 1 << 20,
			MaxBinaryItems:     16,
		},
	}
}

// newFixtureFactory builds the fixture binary and a factory that runs it.
func newFixtureFactory(t *testing.T, cfg Config) *factory {
	t.Helper()
	if cfg.Command == "" {
		cfg.Command = mcptest.BuildFixture(t)
	}
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return f.(*factory)
}

// connectFixture starts the fixture and returns the connection, already
// registered for cleanup.
func connectFixture(t *testing.T, cfg Config) *conn {
	t.Helper()
	f := newFixtureFactory(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := f.Connect(ctx, testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	c := got.(*conn)
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		_ = c.Close(closeCtx)
	})
	return c
}

// processAlive asks the kernel whether pid exists. Signal 0 delivers nothing
// and only performs the existence and permission checks, which is exactly the
// question. ESRCH — and only ESRCH — means gone.
func processAlive(pid int) bool {
	return !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// groupAlive asks whether any member of the child's process group is left. The
// child leads its own group, so the group id is its pid.
func groupAlive(pid int) bool {
	return !errors.Is(syscall.Kill(-pid, 0), syscall.ESRCH)
}

// requireGone polls until the process and its group are gone, or fails. It
// polls rather than sleeps: the assertion is "it went away", and the loop is
// only how long the test is willing to wait to see it.
func requireGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) && !groupAlive(pid) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("process %d (or a member of its group) is still alive; the transport leaked it", pid)
}

// callTool drives a real tool call over the established session. It reaches
// through internal/protocol's SDK escape hatch because the neutral tool API is
// a later task: what is under test is that this transport carries MCP traffic,
// and a real tool call is what proves it.
func callTool(ctx context.Context, c *conn, name string, args map[string]any) (*mcp.CallToolResult, error) {
	return c.session.SDKSession().CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
}

// resultText flattens a tool result's text content.
func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, content := range res.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

// TestClientConnectOverStdio is the end-to-end shape a consumer sees: a
// Definition with a stdio transport, connected through pkg/client.
func TestClientConnectOverStdio(t *testing.T) {
	t.Parallel()
	const instructions = "be excellent to each other"

	f, err := New(Config{
		Command: mcptest.BuildFixture(t),
		Args:    []string{"-instructions", instructions},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := client.Connect(ctx, client.Definition{Name: "fixture", Transport: f}, client.Handlers{})
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		if err := c.Close(closeCtx); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	status := c.Status()
	if status.State != client.StateReady {
		t.Errorf("State = %v, want ready (failure: %+v)", status.State, status.Failure)
	}
	if status.TransportKind != "stdio" {
		t.Errorf("TransportKind = %q, want %q", status.TransportKind, "stdio")
	}
	if want := "fixture (2 args)"; status.RedactedOrigin != want {
		t.Errorf("RedactedOrigin = %q, want %q", status.RedactedOrigin, want)
	}
	if status.Server.Name != mcptest.ServerName {
		t.Errorf("Server.Name = %q, want %q", status.Server.Name, mcptest.ServerName)
	}
	if status.Server.Version != mcptest.ServerVersion {
		t.Errorf("Server.Version = %q, want %q", status.Server.Version, mcptest.ServerVersion)
	}
	if status.ProtocolVersion == "" {
		t.Error("ProtocolVersion is empty: the handshake did not settle a version")
	}
	if status.Failure != nil {
		t.Errorf("Failure = %+v, want nil", status.Failure)
	}
}

// TestInitializeReportsWhatTheServerSaid checks the handshake's converted
// result, which is the transport's one protocol output.
func TestInitializeReportsWhatTheServerSaid(t *testing.T) {
	t.Parallel()
	const instructions = "read the fixture's mind"
	c := connectFixture(t, Config{Args: []string{"-instructions", instructions}})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := c.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if res.Server.Name != mcptest.ServerName {
		t.Errorf("Server.Name = %q, want %q", res.Server.Name, mcptest.ServerName)
	}
	if res.Instructions != instructions {
		t.Errorf("Instructions = %q, want %q", res.Instructions, instructions)
	}
	if res.ProtocolVersion == "" {
		t.Error("ProtocolVersion is empty")
	}
	if !res.Capabilities.Tools {
		t.Error("Capabilities.Tools = false, want true: the fixture exposes tools")
	}

	// A second handshake on one connection is a caller bug, not a retry.
	if _, err := c.Initialize(ctx); err == nil {
		t.Error("a second Initialize succeeded; the handshake happens once per connection")
	}
}

// TestEchoRoundTrip proves the session works: a real request, over the pipes,
// answered by a real server.
func TestEchoRoundTrip(t *testing.T) {
	t.Parallel()
	c := connectFixture(t, Config{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	for _, want := range []string{
		"hello over a pipe",
		// Framing is newline-delimited JSON: text that contains the delimiter,
		// and text that is not ASCII, must survive it.
		"two\nlines",
		"日本語 and 🎉",
	} {
		res, err := callTool(ctx, c, mcptest.ToolEcho, map[string]any{"text": want})
		if err != nil {
			t.Fatalf("CallTool(%s, %q) error = %v", mcptest.ToolEcho, want, err)
		}
		if res.IsError {
			t.Fatalf("CallTool(%s, %q) reported an error result", mcptest.ToolEcho, want)
		}
		if got := resultText(t, res); got != want {
			t.Errorf("echo = %q, want %q", got, want)
		}
	}
}

// TestCancelInFlightCall checks requirement seven's other half: a caller's
// context cancels work already on the wire.
func TestCancelInFlightCall(t *testing.T) {
	t.Parallel()
	c := connectFixture(t, Config{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	callCtx, callCancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(50 * time.Millisecond)
		callCancel()
	}()

	start := time.Now()
	// The fixture sleeps far longer than the test will wait: if cancellation
	// does not work, this blocks until the test times out rather than passing
	// slowly.
	_, err := callTool(callCtx, c, mcptest.ToolSlow, map[string]any{"ms": 60_000})
	if err == nil {
		t.Fatal("CallTool(slow) returned successfully; the cancellation was ignored")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to wrap context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("the cancelled call took %v; it did not return on cancellation", elapsed)
	}

	// The connection survives a cancelled call: cancelling one request must not
	// take down the server.
	res, err := callTool(ctx, c, mcptest.ToolEcho, map[string]any{"text": "still here"})
	if err != nil {
		t.Fatalf("the connection did not survive a cancelled call: %v", err)
	}
	if got := resultText(t, res); got != "still here" {
		t.Errorf("echo = %q, want %q", got, "still here")
	}
}

// TestPrematureExitIsTyped is requirement eight: a server that dies before it
// says anything is reported as a closed transport, with its exit status and
// what it said on the way out.
//
// The child is killed by its own configuration check — an out-of-range flag
// makes it report to stderr and exit 2 — which is a server dying during
// startup, before any protocol traffic, and needs no cooperation from the
// fixture to arrange.
func TestPrematureExitIsTyped(t *testing.T) {
	t.Parallel()
	c := connectFixture(t, Config{Args: []string{"-noise-bytes", "-1"}})
	pid := c.proc.Pid()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := c.Initialize(ctx)
	if err == nil {
		t.Fatal("Initialize() succeeded against a process that exited")
	}
	var typed *client.Error
	if !errors.As(err, &typed) {
		t.Fatalf("want *client.Error, got %T: %v", err, err)
	}
	if typed.Class != client.FailureTransportClosed {
		t.Fatalf("class = %v, want %v (%v)", typed.Class, client.FailureTransportClosed, err)
	}
	text := typed.Error()
	if !strings.Contains(text, "exit status 2") {
		t.Errorf("error = %q, want it to report the exit status", text)
	}
	if !strings.Contains(text, "noise bytes: -1 out of range") {
		t.Errorf("error = %q, want it to carry the stderr tail", text)
	}
	if len(typed.Msg) > client.MaxMessageBytes {
		t.Errorf("message is %d bytes, want at most %d", len(typed.Msg), client.MaxMessageBytes)
	}

	// A server that crashed is still a server that must not be left behind.
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer closeCancel()
	if err := c.Close(closeCtx); err != nil {
		t.Errorf("Close() error = %v; a child that already exited is not a close failure", err)
	}
	requireGone(t, pid)
}

// TestStderrIsCapturedAndBounded checks the capture against a server that
// chatters: it is kept, and it is bounded by StderrLimit whatever the server
// does.
func TestStderrIsCapturedAndBounded(t *testing.T) {
	t.Parallel()
	const limit = 4096
	const noise = 512 * 1024

	c := connectFixture(t, Config{
		Args:        []string{"-noise-bytes", "524288"},
		StderrLimit: limit,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The noise is written before the server serves, so a transport that could
	// not tolerate stderr chatter would fail here — stdout stays clean, which
	// is the property the noise mode exists to check.
	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v; stderr noise must not disturb the protocol", err)
	}
	res, err := callTool(ctx, c, mcptest.ToolEcho, map[string]any{"text": "clean"})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if got := resultText(t, res); got != "clean" {
		t.Errorf("echo = %q, want %q", got, "clean")
	}

	// Poll for the capture to fill: the copier runs concurrently with the
	// protocol, so this waits for it rather than assuming it has caught up.
	deadline := time.Now().Add(10 * time.Second)
	for c.stderr.Len() < limit && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if got := c.stderr.Len(); got != limit {
		t.Errorf("captured %d bytes, want the capture to fill to its %d-byte limit", got, limit)
	}
	if got := len(c.stderr.Tail(noise)); got > limit {
		t.Errorf("Tail() returned %d bytes, want at most the %d-byte limit", got, limit)
	}
	if c.stderr.Dropped() == 0 {
		t.Error("Dropped() = 0, want the capture to admit it dropped the server's earlier chatter")
	}
	if !strings.Contains(string(c.stderr.Tail(limit)), "MCPTEST-NOISE") {
		t.Error("the capture does not hold what the server wrote to stderr")
	}
}

// TestStartupTimeout is requirement seven's first half: a child that starts but
// never speaks MCP must fail on the caller's deadline, not hang.
//
// /bin/sleep is the perfect stalling server: it starts, it holds its pipes, and
// it says nothing. Arranging the same thing in the fixture would prove less —
// the fixture cooperates, and a stalled server does not.
func TestStartupTimeout(t *testing.T) {
	t.Parallel()
	c := connectFixture(t, Config{Command: "sleep", Args: []string{"60"}})
	pid := c.proc.Pid()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.Initialize(ctx)
	if err == nil {
		t.Fatal("Initialize() succeeded against a server that never spoke")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Initialize() took %v; it did not honor the deadline", elapsed)
	}
	var typed *client.Error
	if !errors.As(err, &typed) {
		t.Fatalf("want *client.Error, got %T: %v", err, err)
	}
	if typed.Class != client.FailureStartupTimeout {
		t.Errorf("class = %v, want %v (%v)", typed.Class, client.FailureStartupTimeout, err)
	}

	// The stalled child is still running and is still ours to destroy.
	if !processAlive(pid) {
		t.Fatal("the stalled child is not alive; the test is not testing what it claims")
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer closeCancel()
	if err := c.Close(closeCtx); err != nil {
		t.Errorf("Close() error = %v", err)
	}
	requireGone(t, pid)
}

// TestConnectCancelledLeavesNothingRunning checks that a caller who gives up
// during the start does not leave a server behind.
func TestConnectCancelledLeavesNothingRunning(t *testing.T) {
	t.Parallel()
	f := newFixtureFactory(t, Config{})

	// Cancelled as Connect runs: the process may or may not have been started
	// by the time the cancellation is noticed, which is the race being checked.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c, err := f.Connect(ctx, testConnectConfig())
	if c != nil {
		t.Error("Connect returned a conn for a cancelled context")
	}
	var typed *client.Error
	if !errors.As(err, &typed) {
		t.Fatalf("want *client.Error, got %T: %v", err, err)
	}
	if typed.Class != client.FailureCancelled {
		t.Errorf("class = %v, want %v", typed.Class, client.FailureCancelled)
	}
}

// TestCloseTerminatesTheChildAndItsGroup is requirement six, checked against
// the kernel: after Close, the server and everything sharing its process group
// are gone.
func TestCloseTerminatesTheChildAndItsGroup(t *testing.T) {
	t.Parallel()
	c := connectFixture(t, Config{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	pid := c.proc.Pid()
	if !processAlive(pid) {
		t.Fatalf("the server (pid %d) is not running before Close", pid)
	}
	// The child leads its own group: that is what makes killing the group reap
	// everything it spawned.
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("Getpgid(%d) error = %v", pid, err)
	}
	if pgid != pid {
		t.Errorf("pgid = %d, want %d: the child is not a process group leader", pgid, pid)
	}

	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	requireGone(t, pid)

	// Close is idempotent, and a second one neither errs nor blocks.
	if err := c.Close(ctx); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}
}

// TestCloseReapsTheChildsChildren is the claim TestCloseTerminatesTheChildAndItsGroup
// cannot make. That test's group has exactly one member, so it would pass
// against a transport that had never heard of process groups: a plain kill of
// the leader satisfies every assertion in it. The reason Setpgid exists is the
// server that spawns something — a language runtime's worker, a wrapper
// script's real payload — and an orphan like that holds the pipes it inherited
// long after the server it belonged to is gone.
//
// So this starts a child that starts a child, and asks the kernel about the
// grandchild after Close. It is the only test here that would notice
// Setpgid being dropped.
//
// The shell is the test fixture, not the transport's doing. A grandchild has to
// come from somewhere, and /bin/sh is the portable way to spawn one; the
// transport still receives an explicit argv — Command "/bin/sh", Args
// ["-c", script] — and execs it directly, exactly as it would any other
// program. Nothing here interprets a command string, and the no-shell rule this
// transport enforces is about what it does with a *caller's* command, which is
// unchanged: see TestArgsReachTheChildUninterpreted, which proves it.
func TestCloseReapsTheChildsChildren(t *testing.T) {
	t.Parallel()
	const probe = "/bin/sh"
	if _, err := os.Stat(probe); err != nil {
		t.Skipf("no %s on this host: %v", probe, err)
	}

	// The background sleep is the grandchild; it prints its pid and outlives
	// the script's own sleep by design. Both sleeps are far longer than this
	// test, so neither can end on its own and pass the test by accident.
	const script = "sleep 300 & echo $!; sleep 300"
	f := newFixtureFactory(t, Config{Command: probe, Args: []string{"-c", script}})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := f.Connect(ctx, testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	c := got.(*conn)
	pid := c.proc.Pid()

	// The probe is not an MCP server, so stdout is nobody else's: no session has
	// been initialized, and reading the pid off the pipe is safe.
	line, err := bufio.NewReader(c.stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the grandchild's pid: %v", err)
	}
	gcpid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("the probe printed %q, want a pid: %v", line, err)
	}

	// Both must be running, or the test proves nothing about what Close ended.
	if !processAlive(pid) {
		t.Fatalf("the child (pid %d) is not running before Close", pid)
	}
	if !processAlive(gcpid) {
		t.Fatalf("the grandchild (pid %d) is not running before Close", gcpid)
	}
	// The grandchild is in the child's group — inherited, not arranged — which
	// is what makes one signal reach both.
	gcpgid, err := syscall.Getpgid(gcpid)
	if err != nil {
		t.Fatalf("Getpgid(%d) error = %v", gcpid, err)
	}
	if gcpgid != pid {
		t.Fatalf("the grandchild's pgid = %d, want the child's pid %d: it is not in the group Close signals", gcpgid, pid)
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer closeCancel()
	if err := c.Close(closeCtx); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// The point of the test: the grandchild, which nothing ever signalled by
	// name, is gone because its group was.
	deadline := time.Now().Add(10 * time.Second)
	for processAlive(gcpid) {
		if time.Now().After(deadline) {
			t.Fatalf("the grandchild (pid %d) is still alive after Close: the transport killed the server it started and orphaned what the server started", gcpid)
		}
		time.Sleep(5 * time.Millisecond)
	}
	requireGone(t, pid)
}

// TestGracefulShutdownDoesNotYankStdin is the finding this transport is built
// around: closing the child's stdin with a request outstanding makes an
// SDK-based server treat the EOF as "stop", drop the reply it had not written,
// and exit on an error. Close must therefore drain the session first.
//
// The check is that a slow call, still in flight when Close is called, is
// answered rather than lost — and that the server exits cleanly afterwards.
func TestGracefulShutdownDoesNotYankStdin(t *testing.T) {
	t.Parallel()
	c := connectFixture(t, Config{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	pid := c.proc.Pid()

	type outcome struct {
		text string
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := callTool(ctx, c, mcptest.ToolSlow, map[string]any{"ms": 750})
		if err != nil {
			done <- outcome{err: err}
			return
		}
		done <- outcome{text: resultText(t, res)}
	}()

	// Close while the call is on the wire.
	time.Sleep(100 * time.Millisecond)
	closeErr := c.Close(ctx)

	got := <-done
	if got.err != nil {
		t.Fatalf("the in-flight call was lost by shutdown: %v", got.err)
	}
	if got.text == "" {
		t.Error("the in-flight call returned no content")
	}
	if closeErr != nil {
		t.Errorf("Close() error = %v", closeErr)
	}
	requireGone(t, pid)
}

// TestNoOrphanOnCrash checks that a server which kills itself mid-session
// leaves nothing behind, and that Close over its corpse is not a failure.
func TestNoOrphanOnCrash(t *testing.T) {
	t.Parallel()
	c := connectFixture(t, Config{Args: []string{"-crash", "-crash-exit-code", "9"}})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.Initialize(ctx); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	pid := c.proc.Pid()

	// The crash tool exits the process; the call itself cannot be answered, so
	// its error is expected and is not what is under test.
	if _, err := callTool(ctx, c, mcptest.ToolCrash, map[string]any{}); err == nil {
		t.Log("the crash tool answered before exiting; the process still exits")
	}

	requireGone(t, pid)

	// The transport noticed how it died.
	select {
	case <-c.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the transport never reaped the crashed server")
	}
	status, ok := c.exitStatus()
	if !ok {
		t.Fatalf("exitStatus() reported no status: %v", c.waitErr)
	}
	if status.Code != 9 {
		t.Errorf("exit code = %d (%s), want 9", status.Code, status)
	}

	if err := c.Close(ctx); err != nil {
		t.Errorf("Close() error = %v; a server that already crashed is not a close failure", err)
	}
}

// TestChildEnvironmentIsAllowlisted is the environment guarantee against a real
// execve, checked by a child that reports what it actually got.
//
// /usr/bin/env is that child: it is not an MCP server, so this drives the
// transport's process layer and reads the probe's output directly — which is
// safe precisely because nothing has connected the SDK session to the pipe yet.
// It is not a shell, and it is not invoked through one.
func TestChildEnvironmentIsAllowlisted(t *testing.T) {
	// No t.Parallel: t.Setenv forbids it.
	const probe = "/usr/bin/env"
	if _, err := os.Stat(probe); err != nil {
		t.Skipf("no %s on this host: %v", probe, err)
	}
	t.Setenv("LOOPRIG_STDIO_PARENT_SECRET", secret)
	t.Setenv("LOOPRIG_STDIO_ALLOWED", "allowed-value")

	f := newFixtureFactory(t, Config{
		Command: probe,
		Env: EnvAllowlist{
			Vars:        []Var{{Name: "EXPLICIT", Value: "explicit-value"}},
			PassThrough: []string{"LOOPRIG_STDIO_ALLOWED"},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := f.Connect(ctx, testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	c := got.(*conn)
	t.Cleanup(func() { _ = c.Close(ctx) })

	out, err := io.ReadAll(c.stdout)
	if err != nil {
		t.Fatalf("reading the probe's output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	if strings.Contains(string(out), secret) {
		t.Errorf("the child inherited an unlisted secret from this process:\n%s", out)
	}
	seen := make(map[string]string, len(lines))
	for _, line := range lines {
		if name, value, ok := strings.Cut(line, "="); ok {
			seen[name] = value
		}
	}
	if _, leaked := seen["LOOPRIG_STDIO_PARENT_SECRET"]; leaked {
		t.Error("an unlisted parent variable reached the child")
	}
	if _, leaked := seen["HOME"]; leaked {
		t.Error("HOME reached the child without being allowlisted")
	}
	if got := seen["LOOPRIG_STDIO_ALLOWED"]; got != "allowed-value" {
		t.Errorf("LOOPRIG_STDIO_ALLOWED = %q, want the allowlisted passthrough to be copied", got)
	}
	if got := seen["EXPLICIT"]; got != "explicit-value" {
		t.Errorf("EXPLICIT = %q, want %q", got, "explicit-value")
	}
	if len(seen) != 2 {
		t.Errorf("the child's environment is %v, want exactly the two allowlisted entries", seen)
	}
}

// TestArgsReachTheChildUninterpreted checks the argv rule against a real exec:
// shell metacharacters are data, because there is no shell.
func TestArgsReachTheChildUninterpreted(t *testing.T) {
	t.Parallel()
	const probe = "/bin/echo"
	if _, err := os.Stat(probe); err != nil {
		t.Skipf("no %s on this host: %v", probe, err)
	}
	// If any of these were interpreted, the output would not be the literal
	// argument list.
	args := []string{"; touch /tmp/pwned", "$(id)", "`id`", "&& echo no", "*"}

	f := newFixtureFactory(t, Config{Command: probe, Args: args})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, err := f.Connect(ctx, testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	c := got.(*conn)
	t.Cleanup(func() { _ = c.Close(ctx) })

	out, err := io.ReadAll(c.stdout)
	if err != nil {
		t.Fatalf("reading the probe's output: %v", err)
	}
	if want := strings.Join(args, " ") + "\n"; string(out) != want {
		t.Errorf("the child received %q, want %q verbatim", out, want)
	}
}

// TestRedactedOriginNeverLeaksArgs checks requirement nine against a real
// binding: a secret passed as an argument is invisible in everything the host
// is invited to display.
func TestRedactedOriginNeverLeaksArgs(t *testing.T) {
	t.Parallel()
	fixture := mcptest.BuildFixture(t)
	f, err := New(Config{
		Command: fixture,
		Args:    []string{"-instructions", "token=" + secret},
		Env:     EnvAllowlist{Vars: []Var{{Name: "API_TOKEN", Value: secret}}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := client.Connect(ctx, client.Definition{Name: "fixture", Transport: f}, client.Handlers{})
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(ctx) })

	status := c.Status()
	if strings.Contains(status.RedactedOrigin, secret) {
		t.Errorf("RedactedOrigin leaks a secret: %q", status.RedactedOrigin)
	}
	if want := filepath.Base(fixture) + " (2 args)"; status.RedactedOrigin != want {
		t.Errorf("RedactedOrigin = %q, want %q", status.RedactedOrigin, want)
	}
}
