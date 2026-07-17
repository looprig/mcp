package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/internal/secrettest"
)

// recordingElicitor is an elicitation handler a test can script and interrogate.
type recordingElicitor struct {
	// res and err are what Elicit returns.
	res ElicitResult
	err error
	// block, when true, makes Elicit wait for ctx — a person who never answers,
	// which is what the elicitation timeout exists for.
	block bool

	mu   sync.Mutex
	seen []ElicitRequest
}

func (e *recordingElicitor) Elicit(ctx context.Context, req ElicitRequest) (ElicitResult, error) {
	e.mu.Lock()
	e.seen = append(e.seen, req)
	e.mu.Unlock()

	if e.block {
		<-ctx.Done()
		return ElicitResult{}, ctx.Err()
	}
	return e.res, e.err
}

func (e *recordingElicitor) requests() []ElicitRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]ElicitRequest(nil), e.seen...)
}

func (e *recordingElicitor) calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.seen)
}

// elicitingClient connects a Client that serves elicitation, and returns it
// alongside the transport (for the installed callback) and the event recorder.
func elicitingClient(t *testing.T, h *recordingElicitor, shape func(*Definition)) (*fakeTransport, *eventRecorder) {
	t.Helper()

	tr := newFakeTransport(okConn())
	rec := &eventRecorder{}
	def := okDefinition(tr)
	def.Capabilities.Elicitation = true
	if shape != nil {
		shape(&def)
	}

	c, err := Connect(context.Background(), def, Handlers{Elicitation: h, Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return tr, rec
}

// formRequest is a well-formed neutral elicitation, as the protocol boundary
// would hand one over.
func formRequest() protocol.ElicitRequest {
	return protocol.ElicitRequest{
		Mode:    protocol.ElicitModeForm,
		Message: "your name?",
		Schema:  json.RawMessage(`{"type":"object"}`),
	}
}

// TestElicitationReachesTheHandler is the producer itself: a server's request,
// arriving on the connection the client installed a callback on, reaches
// Handlers.Elicitation and its answer comes back.
//
// It drives the callback the client actually installed rather than a constructed
// one, so a client that installed nothing fails here rather than passing on a
// technicality.
func TestElicitationReachesTheHandler(t *testing.T) {
	t.Parallel()

	h := &recordingElicitor{res: ElicitResult{
		Action:  ElicitAccept,
		Content: json.RawMessage(`{"name":"ada"}`),
	}}
	tr, _ := elicitingClient(t, h, nil)

	onElicit := tr.lastConfig().OnElicit
	if onElicit == nil {
		t.Fatal("the client installed no OnElicit callback, so no server request can reach a handler")
	}

	got, err := onElicit(context.Background(), formRequest())
	if err != nil {
		t.Fatalf("OnElicit() error = %v", err)
	}

	reqs := h.requests()
	if len(reqs) != 1 {
		t.Fatalf("the handler was called %d times, want 1", len(reqs))
	}
	if reqs[0].Binding != "srv" {
		t.Errorf("ElicitRequest.Binding = %q, want the binding's name", reqs[0].Binding)
	}
	if reqs[0].Mode != ElicitModeForm {
		t.Errorf("ElicitRequest.Mode = %v, want form", reqs[0].Mode)
	}
	if reqs[0].Message != "your name?" {
		t.Errorf("ElicitRequest.Message = %q, want the server's", reqs[0].Message)
	}
	if string(reqs[0].Schema) != `{"type":"object"}` {
		t.Errorf("ElicitRequest.Schema = %s, want the server's", reqs[0].Schema)
	}
	if got.Action != protocol.ElicitAccept || string(got.Content) != `{"name":"ada"}` {
		t.Errorf("the answer returned to the connection = %+v, want the handler's", got)
	}
}

// TestElicitationCapabilityFollowsTheHandler: a nil Handlers.Elicitation means
// the capability is not advertised, and that must be true end to end rather than
// only in Handlers.advertised.
//
// Both halves are asserted on the config the client actually handed the
// transport: the capability flag, and the callback whose presence is what makes
// internal/protocol register (and the SDK auto-advertise).
func TestElicitationCapabilityFollowsTheHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// requested is Definition.Capabilities.Elicitation.
		requested bool
		// handler says whether Handlers.Elicitation is installed.
		handler bool
		// wantConnect is whether Connect must succeed.
		wantConnect bool
		// wantCap and wantCallback are what must reach the transport.
		wantCap      bool
		wantCallback bool
	}{
		{
			name:      "requested with no handler is refused outright",
			requested: true, handler: false, wantConnect: false,
		},
		{
			name:      "requested and handled: advertised, with a callback to serve it",
			requested: true, handler: true, wantConnect: true,
			wantCap: true, wantCallback: true,
		},
		{
			name: "handled but never requested: NOT advertised. The handler is installed " +
				"and simply never called; nothing about having one may put a capability on the wire",
			requested: false, handler: true, wantConnect: true,
			wantCap: false, wantCallback: true,
		},
		{
			name:      "neither: no capability, no callback",
			requested: false, handler: false, wantConnect: true,
			wantCap: false, wantCallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr := newFakeTransport(okConn())
			def := okDefinition(tr)
			def.Capabilities.Elicitation = tt.requested

			h := Handlers{}
			if tt.handler {
				h.Elicitation = &recordingElicitor{res: ElicitResult{Action: ElicitDecline}}
			}

			c, err := Connect(context.Background(), def, h)
			if (err == nil) != tt.wantConnect {
				t.Fatalf("Connect() error = %v, wantConnect %v", err, tt.wantConnect)
			}
			if !tt.wantConnect {
				if class, ok := ClassOf(err); !ok || class != FailureInvalidConfig {
					t.Errorf("Connect() error class = %v, want FailureInvalidConfig", class)
				}
				return
			}
			defer func() { _ = c.Close(context.Background()) }()

			cfg := tr.lastConfig()
			if cfg.Capabilities.Elicitation != tt.wantCap {
				t.Errorf("the advertised elicitation capability = %v, want %v",
					cfg.Capabilities.Elicitation, tt.wantCap)
			}
			if (cfg.OnElicit != nil) != tt.wantCallback {
				t.Errorf("an OnElicit callback was installed = %v, want %v",
					cfg.OnElicit != nil, tt.wantCallback)
			}
		})
	}
}

// TestElicitationEmitsLifecycleEvents: the two events, with the metadata they
// are allowed to carry and the answer that was actually given.
func TestElicitationEmitsLifecycleEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		res        ElicitResult
		err        error
		wantAction ElicitAction
	}{
		{
			name:       "an accept",
			res:        ElicitResult{Action: ElicitAccept, Content: json.RawMessage(`{}`)},
			wantAction: ElicitAccept,
		},
		{
			name:       "a decline is a person's answer, and is reported as one",
			res:        ElicitResult{Action: ElicitDecline},
			wantAction: ElicitDecline,
		},
		{
			name:       "a cancel",
			res:        ElicitResult{Action: ElicitCancel},
			wantAction: ElicitCancel,
		},
		{
			name: "a handler that fails resolves with no action: the host could not ask, " +
				"which is not the same as a person declining",
			err:        errors.New("no ui available"),
			wantAction: 0,
		},
		{
			name:       "a handler that answers with no action is refused, and resolves with none",
			res:        ElicitResult{},
			wantAction: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := &recordingElicitor{res: tt.res, err: tt.err}
			tr, rec := elicitingClient(t, h, nil)

			_, _ = tr.lastConfig().OnElicit(context.Background(), formRequest())

			requested := eventsOf[ElicitationRequested](rec)
			if len(requested) != 1 {
				t.Fatalf("ElicitationRequested events = %d, want 1", len(requested))
			}
			if requested[0].Binding != "srv" || requested[0].Mode != ElicitModeForm {
				t.Errorf("ElicitationRequested = %+v, want the binding and the form mode", requested[0])
			}
			if requested[0].At.IsZero() {
				t.Error("ElicitationRequested.At is zero")
			}

			resolved := eventsOf[ElicitationResolved](rec)
			if len(resolved) != 1 {
				t.Fatalf("ElicitationResolved events = %d, want exactly one per request", len(resolved))
			}
			if resolved[0].Action != tt.wantAction {
				t.Errorf("ElicitationResolved.Action = %v, want %v", resolved[0].Action, tt.wantAction)
			}
			if resolved[0].Mode != ElicitModeForm {
				t.Errorf("ElicitationResolved.Mode = %v, want form", resolved[0].Mode)
			}
			if resolved[0].Duration < 0 {
				t.Errorf("ElicitationResolved.Duration = %v, want a non-negative elapsed time", resolved[0].Duration)
			}
		})
	}
}

// TestElicitationEventsCarryNothingTheServerSent is design §Elicitation's rule,
// asserted against the real producer rather than against the event's field list.
//
// The field sweep in events_test.go proves no event *can* hold a URL. This
// proves the producer does not smuggle one into the fields that exist: a
// server's URL, query parameters, prompt and schema all go to the handler and
// none of them to an observer.
func TestElicitationEventsCarryNothingTheServerSent(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-token-value"

	h := &recordingElicitor{res: ElicitResult{Action: ElicitAccept}}
	tr, rec := elicitingClient(t, h, nil)

	_, _ = tr.lastConfig().OnElicit(context.Background(), protocol.ElicitRequest{
		Mode:          protocol.ElicitModeURL,
		Message:       "authorize " + secret,
		URL:           "https://example.com/authorize?token=" + secret,
		ElicitationID: secret,
	})

	// The handler must have been given everything: it is the thing that has to
	// act on it, and a test where it was not is a test of nothing.
	reqs := h.requests()
	if len(reqs) != 1 || !strings.Contains(reqs[0].URL, secret) {
		t.Fatalf("the handler did not receive the server's URL: %+v", reqs)
	}

	for _, e := range rec.snapshot() {
		switch e.(type) {
		case ElicitationRequested, ElicitationResolved:
			if dump := secrettest.Dump(e); strings.Contains(dump, secret) {
				t.Errorf("an elicitation event carries what the server sent:\n%s", dump)
			}
		}
	}
}

// TestElicitationIsBoundedByTheBindingsTimeout: a person who never answers must
// not pin the connection's dispatch goroutine forever. The handler's ctx carries
// the binding's elicitation timeout, and the server is told it timed out.
func TestElicitationIsBoundedByTheBindingsTimeout(t *testing.T) {
	t.Parallel()

	h := &recordingElicitor{block: true}
	tr, rec := elicitingClient(t, h, func(d *Definition) {
		d.Timeouts.Elicitation = 20 * time.Millisecond
	})

	// context.Background(), deliberately: the deadline under test is the
	// binding's own, so the caller's context must not be what ends this.
	_, err := tr.lastConfig().OnElicit(context.Background(), formRequest())
	if err == nil {
		t.Fatal("an unanswered elicitation returned no error: the server would wait forever")
	}
	if class, ok := ClassOf(err); !ok || class != FailureElicitationTimeout {
		t.Errorf("error class = %v, want FailureElicitationTimeout", class)
	}

	resolved := eventsOf[ElicitationResolved](rec)
	if len(resolved) != 1 || resolved[0].Action != 0 {
		t.Errorf("ElicitationResolved = %+v, want one with no action: nobody answered", resolved)
	}
}

// TestElicitationErrorsDoNotLeakTheHandlersOwnText is a redaction rule with an
// unusual direction: these errors go *to the server*.
//
// A handler's error is the host's business — it may name a user, a file, a
// window, a credential store. The server asked a question and is entitled to
// learn that it failed, and to nothing else.
func TestElicitationErrorsDoNotLeakTheHandlersOwnText(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-token-value"

	h := &recordingElicitor{err: errors.New("keychain unlock failed for " + secret)}
	tr, _ := elicitingClient(t, h, nil)

	_, err := tr.lastConfig().OnElicit(context.Background(), formRequest())
	if err == nil {
		t.Fatal("a failing handler produced no error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the error answering the server quotes the handler's own text: %v", err)
	}
	// The cause is not destroyed — an operator holding the error can still
	// unwrap it. It just does not travel to the peer.
	if !strings.Contains(errors.Unwrap(err).Error(), secret) {
		t.Error("the test's own premise is broken: the wrapped cause does not carry the handler's text")
	}
}

// TestClientRevalidatesWhatReachesTheHandler is defence in depth: internal/
// protocol bounds and validates every elicitation, but Conn is an interface and
// the client is what promises Handlers.Elicitation a declared mode and a bounded
// prompt. A defective transport must not be able to break that promise.
func TestClientRevalidatesWhatReachesTheHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  protocol.ElicitRequest
	}{
		{
			name: "an undeclared mode never reaches a handler",
			req:  protocol.ElicitRequest{Mode: protocol.ElicitMode(99), Message: "hi"},
		},
		{
			name: "the zero mode never reaches a handler",
			req:  protocol.ElicitRequest{Message: "hi"},
		},
		{
			name: "an over-bound prompt never reaches a handler",
			req: protocol.ElicitRequest{
				Mode:    protocol.ElicitModeForm,
				Message: strings.Repeat("m", 65),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := &recordingElicitor{res: ElicitResult{Action: ElicitAccept}}
			tr, rec := elicitingClient(t, h, func(d *Definition) {
				d.Limits.MaxElicitMessageBytes = 64
			})

			_, err := tr.lastConfig().OnElicit(context.Background(), tt.req)
			if err == nil {
				t.Fatal("a defective elicitation was accepted, want a refusal")
			}
			if got := h.calls(); got != 0 {
				t.Errorf("the handler was called %d times, want 0", got)
			}
			// Nothing happened, so nothing is reported: an observer must not see
			// a request that no handler ever received.
			if got := len(eventsOf[ElicitationRequested](rec)); got != 0 {
				t.Errorf("ElicitationRequested events = %d for a refused request, want 0", got)
			}
		})
	}
}

// TestElicitationSurvivesAReconnect: what a host can serve is a property of the
// host, not of which socket a server is on. The reconnected connection
// re-advertises the same capabilities (c.caps verbatim), so it must carry the
// callback that makes them honorable — or the binding would claim elicitation
// with nothing behind it.
func TestElicitationSurvivesAReconnect(t *testing.T) {
	t.Parallel()

	first, second := okConn(), okConn()
	first.callErr = lostConn()
	tr := newRedialTransport(first, second)

	h := &recordingElicitor{res: ElicitResult{Action: ElicitDecline}}
	def := fastReconnect(Definition{Name: "srv", Transport: tr}, 3)
	def.Capabilities.Elicitation = true

	c, err := Connect(context.Background(), def, Handlers{Elicitation: h})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	// A call finds the connection gone, which drives the reconnect.
	_, _ = c.CallTool(context.Background(), "echo", nil, CallOpts{})
	waitFor(t, "the reconnect", func() bool { return c.Status().State == StateReady && tr.dialCount() == 2 })

	cfg := second.connectCfg
	if !cfg.Capabilities.Elicitation {
		t.Fatal("the reconnected binding advertised no elicitation: the test's premise is broken")
	}
	if cfg.OnElicit == nil {
		t.Fatal("the reconnected binding advertises elicitation with no callback to serve it")
	}
	if _, err := cfg.OnElicit(context.Background(), formRequest()); err != nil {
		t.Errorf("the reconnected binding's OnElicit failed: %v", err)
	}
	if got := h.calls(); got != 1 {
		t.Errorf("the handler was called %d times over the new connection, want 1", got)
	}
}

// TestElicitModeString pins the identifiers, which reach events and telemetry.
func TestElicitModeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode ElicitMode
		want string
	}{
		{ElicitModeForm, "form"},
		{ElicitModeURL, "url"},
		{0, "unknown"},
		{ElicitMode(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("ElicitMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}
