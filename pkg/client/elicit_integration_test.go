//go:build integration

// Integration tests for elicitation, against the real fixture MCP server over a
// real stdio subprocess.
//
// The unit tests in this package drive the callback the client installed, which
// proves the client's own half: the validation, the timeout, the events, the
// answer. These prove the half a fake conn cannot — that a real MCP server's
// elicitation/create actually arrives at Handlers.Elicitation, and that the
// human's answer actually arrives back at the server that asked.

package client_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/pkg/client"
)

// scriptedElicitor answers every elicitation the same way, and records what it
// was asked.
type scriptedElicitor struct {
	res client.ElicitResult
	err error

	mu   sync.Mutex
	seen []client.ElicitRequest
}

func (e *scriptedElicitor) Elicit(_ context.Context, req client.ElicitRequest) (client.ElicitResult, error) {
	e.mu.Lock()
	e.seen = append(e.seen, req)
	e.mu.Unlock()
	return e.res, e.err
}

func (e *scriptedElicitor) requests() []client.ElicitRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]client.ElicitRequest(nil), e.seen...)
}

// TestRealServerElicitsAHuman is the seam end to end over a real subprocess: the
// server asks while answering a tool call, the request reaches the application's
// handler with the server's own prompt and schema, and the answer reaches the
// server, which reports it back in the tool's result.
func TestRealServerElicitsAHuman(t *testing.T) {
	t.Parallel()

	h := &scriptedElicitor{res: client.ElicitResult{
		Action:  client.ElicitAccept,
		Content: json.RawMessage(`{"name":"ada"}`),
	}}
	c := fixtureClient(t, client.Handlers{Elicitation: h}, func(d *client.Definition) {
		d.Capabilities.Elicitation = true
	}, "-elicit")

	res, err := c.CallTool(testCtx(t), mcptest.ToolElicit,
		json.RawMessage(`{"mode":"form","schema":true}`), client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool(%q) error = %v", mcptest.ToolElicit, err)
	}
	if res.IsError {
		t.Fatalf("the server could not elicit: %s", resultText(t, res))
	}

	// The server was told what the human said. This is the assertion the whole
	// feature exists for: a real answer completed a real round trip.
	if got, want := resultText(t, res), mcptest.ElicitAnswerPrefix+"accept"; got != want {
		t.Errorf("the tool reported %q, want %q", got, want)
	}

	reqs := h.requests()
	if len(reqs) != 1 {
		t.Fatalf("the handler was called %d times, want 1", len(reqs))
	}
	if reqs[0].Binding != "fixture" {
		t.Errorf("ElicitRequest.Binding = %q, want the binding's name", reqs[0].Binding)
	}
	if reqs[0].Mode != client.ElicitModeForm {
		t.Errorf("ElicitRequest.Mode = %v, want form", reqs[0].Mode)
	}
	if reqs[0].Message != mcptest.ElicitMessage {
		t.Errorf("ElicitRequest.Message = %q, want the server's %q", reqs[0].Message, mcptest.ElicitMessage)
	}
	if !strings.Contains(string(reqs[0].Schema), `"name"`) {
		t.Errorf("ElicitRequest.Schema = %s, want the server's requested form", reqs[0].Schema)
	}
	if reqs[0].URL != "" || reqs[0].ElicitationID != "" {
		t.Errorf("a form elicitation carried url fields: %+v", reqs[0])
	}
}

// TestRealServerElicitationDecline: a decline is a person's answer and reaches
// the server as one, rather than as a failure.
func TestRealServerElicitationDecline(t *testing.T) {
	t.Parallel()

	h := &scriptedElicitor{res: client.ElicitResult{Action: client.ElicitDecline}}
	c := fixtureClient(t, client.Handlers{Elicitation: h}, func(d *client.Definition) {
		d.Capabilities.Elicitation = true
	}, "-elicit")

	res, err := c.CallTool(testCtx(t), mcptest.ToolElicit, json.RawMessage(`{"mode":"form"}`), client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if got, want := resultText(t, res), mcptest.ElicitAnswerPrefix+"decline"; got != want {
		t.Errorf("the tool reported %q, want %q", got, want)
	}
}

// TestRealServerCannotElicitWithoutTheCapability is the fail-open guard as a
// real server experiences it.
//
// The handler is installed — which is exactly what makes the SDK advertise the
// capability if nothing stops it — but the binding never asked for elicitation.
// A real MCP server must therefore be unable to ask, and the handler must never
// run.
func TestRealServerCannotElicitWithoutTheCapability(t *testing.T) {
	t.Parallel()

	h := &scriptedElicitor{res: client.ElicitResult{Action: client.ElicitAccept}}
	// No Capabilities.Elicitation: the handler is installed and simply unused.
	c := fixtureClient(t, client.Handlers{Elicitation: h}, nil, "-elicit")

	res, err := c.CallTool(testCtx(t), mcptest.ToolElicit, json.RawMessage(`{"mode":"form"}`), client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if !res.IsError {
		t.Fatalf("a server elicited a binding that advertised no elicitation: %s", resultText(t, res))
	}
	if got := len(h.requests()); got != 0 {
		t.Errorf("the handler ran %d times on a binding with no elicitation capability, want 0", got)
	}
}

// TestRealServerUnknownElicitModeNeverReachesAHuman: an unrecognized mode from a
// real server is refused and never shown to a human.
//
// As with the session-level test of the same property, this does not prove this
// module's own guard — the SDK's client refuses an unknown mode before our
// handler runs, so it passes with our rejection deleted (verified by mutation).
// internal/protocol's TestFromSDKElicitParams is where that guard is proved.
// This pins the end-to-end property against a real server.
func TestRealServerUnknownElicitModeNeverReachesAHuman(t *testing.T) {
	t.Parallel()

	h := &scriptedElicitor{res: client.ElicitResult{Action: client.ElicitAccept}}
	c := fixtureClient(t, client.Handlers{Elicitation: h}, func(d *client.Definition) {
		d.Capabilities.Elicitation = true
	}, "-elicit")

	res, err := c.CallTool(testCtx(t), mcptest.ToolElicit, json.RawMessage(`{"mode":"voice"}`), client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if !res.IsError {
		t.Fatalf("an unknown elicitation mode was answered: %s", resultText(t, res))
	}
	if got := len(h.requests()); got != 0 {
		t.Errorf("the handler was asked %d questions this module cannot describe, want 0", got)
	}
}

// TestRealServerOverBoundPromptIsRefused: the prompt bound, against a real
// server sending a real oversized prompt.
func TestRealServerOverBoundPromptIsRefused(t *testing.T) {
	t.Parallel()

	h := &scriptedElicitor{res: client.ElicitResult{Action: client.ElicitAccept}}
	c := fixtureClient(t, client.Handlers{Elicitation: h}, func(d *client.Definition) {
		d.Capabilities.Elicitation = true
		d.Limits.MaxElicitMessageBytes = 64
	}, "-elicit")

	args, err := json.Marshal(mcptest.ElicitInput{Mode: "form", Message: strings.Repeat("m", 65)})
	if err != nil {
		t.Fatalf("marshaling args: %v", err)
	}
	res, err := c.CallTool(testCtx(t), mcptest.ToolElicit, args, client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if !res.IsError {
		t.Fatalf("an over-bound prompt was accepted: %s", resultText(t, res))
	}
	if got := len(h.requests()); got != 0 {
		t.Errorf("the handler was shown %d over-bound prompts, want 0", got)
	}
}

// TestRealServerElicitOnInitialize keeps the fixture's older elicitation path
// working, and shows the client serves an elicitation that arrives at the
// earliest moment a server may send one — before any tool call, on the heels of
// the handshake.
func TestRealServerElicitOnInitialize(t *testing.T) {
	t.Parallel()

	events := make(chan client.Event, 64)
	h := &scriptedElicitor{res: client.ElicitResult{Action: client.ElicitDecline}}
	fixtureClient(t, client.Handlers{
		Elicitation: h,
		Event:       func(e client.Event) { events <- e },
	}, func(d *client.Definition) {
		d.Capabilities.Elicitation = true
	}, "-elicit-on-initialize")

	// The elicitation is unprompted, so the event stream is what says it
	// happened — waiting on it is what makes this deterministic rather than a
	// sleep.
	resolved := waitForEvent[client.ElicitationResolved](t, events)
	if resolved.Action != client.ElicitDecline {
		t.Errorf("ElicitationResolved.Action = %v, want decline", resolved.Action)
	}
	if resolved.Mode != client.ElicitModeForm {
		t.Errorf("ElicitationResolved.Mode = %v, want form", resolved.Mode)
	}

	reqs := h.requests()
	if len(reqs) != 1 {
		t.Fatalf("the handler was called %d times, want 1", len(reqs))
	}
	if reqs[0].Message != mcptest.ElicitMessage {
		t.Errorf("ElicitRequest.Message = %q, want %q", reqs[0].Message, mcptest.ElicitMessage)
	}
}
