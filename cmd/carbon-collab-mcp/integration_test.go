package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/serverwire"
	"github.com/looprig/mcp/pkg/collab"
)

const integrationAgentID = "55555555-5555-4555-8555-555555555555"

type integrationBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

type integrationReadCloser struct {
	io.Reader
	io.Closer
}

func (b *integrationBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *integrationBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type integrationBroker struct {
	listener    net.Listener
	endpoint    string
	capability  []byte
	secretToken string

	mu          sync.Mutex
	connections int
	requests    chan collab.MessageAgentRequest
	errors      chan error
	done        chan struct{}
	closeOnce   sync.Once
}

func newIntegrationBroker(t *testing.T, endpoint string, capability []byte, secretToken string) *integrationBroker {
	t.Helper()
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		t.Skipf("Unix socket unavailable in this environment: %v", err)
	}
	broker := &integrationBroker{
		listener:    listener,
		endpoint:    endpoint,
		capability:  append([]byte(nil), capability...),
		secretToken: secretToken,
		requests:    make(chan collab.MessageAgentRequest, 1),
		errors:      make(chan error, 4),
		done:        make(chan struct{}),
	}
	go broker.serve()
	t.Cleanup(func() {
		broker.close()
		select {
		case <-broker.done:
		case <-time.After(2 * time.Second):
			t.Errorf("fake broker did not stop")
		}
	})
	return broker
}

func (b *integrationBroker) serve() {
	defer close(b.done)
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				b.report(err)
			}
			return
		}
		b.mu.Lock()
		b.connections++
		connection := b.connections
		b.mu.Unlock()
		if connection == 1 {
			b.serveSuccess(conn)
		} else {
			b.serveFailure(conn)
		}
	}
}

func (b *integrationBroker) serveSuccess(conn net.Conn) {
	defer conn.Close()
	capability, err := collab.ReadHandshake(conn)
	if err != nil {
		b.report(err)
		return
	}
	if !bytes.Equal(capability, b.capability) {
		b.report(fmt.Errorf("broker received wrong capability"))
		return
	}
	frame, err := collab.ReadFrame(conn)
	if err != nil {
		b.report(err)
		return
	}
	if bytes.Contains(frame, []byte(b.secretToken)) || bytes.Contains(frame, []byte(b.endpoint)) {
		b.report(fmt.Errorf("environment secret appeared in broker request"))
		return
	}
	request, err := collab.DecodeMessageAgent(frame)
	if err != nil {
		b.report(err)
		return
	}
	select {
	case b.requests <- request:
	default:
		b.report(fmt.Errorf("broker request channel full"))
		return
	}
	if err := collab.WriteFrame(conn, []byte(`{"agent_id":"`+integrationAgentID+`","name":"child","state":"idle","delivery_status":"queued","response_status":"completed","response":"broker response"}`)); err != nil {
		b.report(err)
	}
}

func (b *integrationBroker) serveFailure(conn net.Conn) {
	defer conn.Close()
	if _, err := collab.ReadHandshake(conn); err != nil {
		b.report(err)
		return
	}
	if _, err := collab.ReadFrame(conn); err != nil {
		b.report(err)
		return
	}
	// Closing after a fully admitted request exercises the MCP server's
	// categorical internal-error boundary without returning broker details.
}

func (b *integrationBroker) report(err error) {
	select {
	case b.errors <- err:
	default:
	}
}

func (b *integrationBroker) connectionCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.connections
}

func (b *integrationBroker) close() {
	b.closeOnce.Do(func() {
		_ = b.listener.Close()
		_ = os.Remove(b.endpoint)
	})
}

func buildCollabMCPBinary(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	binaryPath := filepath.Join(t.TempDir(), "carbon-collab-mcp")
	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/carbon-collab-mcp") // #nosec G204 -- fixed local module and output path
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building collaboration MCP executable: %v\n%s", err, output)
	}
	return binaryPath
}

func integrationEnvironment(endpoint, token string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, collab.EndpointEnv+"=") || strings.HasPrefix(entry, collab.TokenEnv+"=") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, collab.EndpointEnv+"="+endpoint, collab.TokenEnv+"="+token)
}

func waitForIntegrationProcess(t *testing.T, waitCh <-chan error) {
	t.Helper()
	select {
	case err := <-waitCh:
		if err != nil {
			t.Fatalf("collaboration MCP process exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collaboration MCP process did not exit after stdio shutdown")
	}
}

func TestCollabMCPIntegrationProcessBoundary(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("the collaboration process boundary requires Unix sockets")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	capability := bytes.Repeat([]byte{0xde}, collab.CapabilityBytes)
	secretToken, err := collab.EncodeCapabilityToken(capability)
	if err != nil {
		t.Fatalf("EncodeCapabilityToken: %v", err)
	}
	socketDir, err := os.MkdirTemp("/tmp", "mcp-collab-")
	if err != nil {
		t.Skipf("temporary Unix socket directory unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	secretEndpoint := "endpoint-secret-collab"
	endpoint := filepath.Join(socketDir, secretEndpoint+".sock")
	broker := newIntegrationBroker(t, endpoint, capability, secretToken)
	binaryPath := buildCollabMCPBinary(t)

	command := exec.Command(binaryPath) // #nosec G204 -- binary is built by this test into t.TempDir
	command.Env = integrationEnvironment(endpoint, secretToken)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	stderr := &integrationBuffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatalf("starting collaboration MCP process: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- command.Wait() }()

	wire := &integrationBuffer{}
	clientDefinition := serverwire.NewClient(&serverwire.Implementation{Name: "integration-client", Version: "1"}, nil)
	client, err := clientDefinition.Connect(ctx, &serverwire.IOTransport{Reader: &integrationReadCloser{Reader: io.TeeReader(stdout, wire), Closer: stdout}, Writer: stdin}, nil)
	if err != nil {
		_ = stdin.Close()
		<-waitCh
		t.Fatalf("connecting to collaboration MCP process: %v\nstderr: %s", err, stderr.String())
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = client.Close()
			_ = stdin.Close()
			waitForIntegrationProcess(t, waitCh)
			closed = true
		}
	})

	tools, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != collab.ToolName {
		t.Fatalf("discovered tools = %#v, want only %q", tools.Tools, collab.ToolName)
	}
	if tools.Tools[0].InputSchema == nil {
		t.Fatal("MessageAgent discovery omitted input schema")
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	schemaBytes, err := json.Marshal(tools.Tools[0].InputSchema)
	if err != nil {
		t.Fatalf("marshal MessageAgent schema: %v", err)
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("MessageAgent schema: %v", err)
	}
	if len(schema.Properties) != 4 {
		t.Fatalf("MessageAgent schema properties = %d, want four", len(schema.Properties))
	}

	wantResponse := []byte(`{"agent_id":"` + integrationAgentID + `","name":"child","state":"idle","delivery_status":"queued","response_status":"completed","response":"broker response"}`)
	result, err := client.CallTool(ctx, &serverwire.CallToolParams{
		Name:      collab.ToolName,
		Arguments: json.RawMessage(`{"agent_id":"` + integrationAgentID + `","message":"hello"}`),
	})
	if err != nil {
		t.Fatalf("MessageAgent call: %v", err)
	}
	if result.IsError {
		t.Fatalf("MessageAgent result marked error: %#v", result)
	}
	if len(result.Content) != 1 {
		t.Fatalf("MessageAgent content = %#v, want broker JSON", result.Content)
	}
	content, ok := result.Content[0].(*serverwire.TextContent)
	if !ok || content.Text != string(wantResponse) {
		t.Fatalf("MessageAgent content = %#v, want broker JSON", result.Content)
	}
	structured, err := json.Marshal(result.StructuredContent)
	var gotObject, wantObject map[string]any
	if err == nil {
		err = json.Unmarshal(structured, &gotObject)
	}
	if err == nil {
		err = json.Unmarshal(wantResponse, &wantObject)
	}
	if err != nil || !reflect.DeepEqual(gotObject, wantObject) {
		t.Fatalf("MessageAgent structured content = %s, want JSON equivalent to %s (error %v)", structured, wantResponse, err)
	}
	select {
	case request := <-broker.requests:
		if !request.WaitForResponse || request.TimeoutSeconds != nil || request.Message != "hello" || request.AgentID != integrationAgentID {
			t.Fatalf("broker request = %#v, want defaults and exact payload", request)
		}
	case <-ctx.Done():
		t.Fatal("broker did not receive MessageAgent request")
	}

	_, err = client.CallTool(ctx, &serverwire.CallToolParams{
		Name:      collab.ToolName,
		Arguments: json.RawMessage(`{"agent_id":"` + integrationAgentID + `","message":"hello","timeout_seconds":86401}`),
	})
	if err == nil {
		t.Fatal("out-of-range timeout unexpectedly succeeded")
	}
	if got := broker.connectionCount(); got != 1 {
		t.Fatalf("invalid timeout opened %d broker connections, want one valid call only", got)
	}

	_, err = client.CallTool(ctx, &serverwire.CallToolParams{
		Name:      collab.ToolName,
		Arguments: json.RawMessage(`{"agent_id":"` + integrationAgentID + `","message":"transport failure"}`),
	})
	if err == nil {
		t.Fatal("broker failure unexpectedly returned nil error")
	}
	for label, text := range map[string]string{"error": err.Error(), "stdout": wire.String(), "stderr": stderr.String()} {
		if strings.Contains(text, secretToken) || strings.Contains(text, endpoint) || strings.Contains(text, secretEndpoint) {
			t.Fatalf("%s exposed environment secret: %q", label, text)
		}
	}
	if got := broker.connectionCount(); got != 2 {
		t.Fatalf("broker connections after failure = %d, want two", got)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	_ = stdin.Close()
	waitForIntegrationProcess(t, waitCh)
	closed = true
	for label, text := range map[string]string{"stdout after shutdown": wire.String(), "stderr after shutdown": stderr.String()} {
		if strings.Contains(text, secretToken) || strings.Contains(text, endpoint) || strings.Contains(text, secretEndpoint) {
			t.Fatalf("%s exposed environment secret: %q", label, text)
		}
	}
	broker.close()
	select {
	case <-broker.done:
	case <-time.After(2 * time.Second):
		t.Fatal("fake broker did not stop")
	}
	if _, err := os.Stat(endpoint); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("broker socket stat after shutdown = %v, want not exist", err)
	}
}
