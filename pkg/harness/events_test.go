package mcpharness

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/looprig/harness/pkg/event"
	"github.com/looprig/mcp/pkg/client"
)

// capturingEvents records every event a Manager publishes, and can refuse one.
type capturingEvents struct {
	mu     sync.Mutex
	events []event.Event
	err    error
}

func (c *capturingEvents) PublishEvent(_ context.Context, ev event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.events = append(c.events, ev)
	return nil
}

func (c *capturingEvents) statuses() []event.IntegrationStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]event.IntegrationStatus, 0, len(c.events))
	for _, ev := range c.events {
		if s, ok := ev.(event.IntegrationStatus); ok {
			out = append(out, s)
		}
	}
	return out
}

// managerForEvents returns a Manager wired to a capturing publisher and
// reporter, plus one binding's state to raise events against.
func managerForEvents(t *testing.T) (*Manager, *bindingState, *capturingEvents, *recordingReporter) {
	t.Helper()
	events := &capturingEvents{}
	reporter := &recordingReporter{}
	deps := testDeps()
	deps.Events = events
	deps.Reporter = reporter
	m, err := NewManager([]Binding{scriptedBinding("github", ScopeSession, okTransport("github"))}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	bs, ok := m.states["github"]
	if !ok {
		t.Fatal("binding state for github is missing")
	}
	return m, bs, events, reporter
}

// TestStateChangedBecomesIntegrationStatus is the happy path of the bridge: the
// client's lifecycle reaches the Harness event stream, projected onto the coarse
// state a consumer outside this module can act on.
func TestStateChangedBecomesIntegrationStatus(t *testing.T) {
	t.Parallel()
	m, bs, events, _ := managerForEvents(t)

	m.onClientEvent(bs, client.StateChanged{Binding: "github", From: client.StateDiscovering, To: client.StateReady})

	got := events.statuses()
	if len(got) != 1 {
		t.Fatalf("published %d statuses, want 1", len(got))
	}
	if got[0].Source != IntegrationSource {
		t.Errorf("Source = %q, want %q", got[0].Source, IntegrationSource)
	}
	if got[0].Name != "github" {
		t.Errorf("Name = %q, want github", got[0].Name)
	}
	if got[0].State != event.IntegrationReady {
		t.Errorf("State = %v, want ready", got[0].State)
	}
	if got[0].SessionID != sessionID {
		t.Errorf("SessionID = %v, want the Manager's Session", got[0].SessionID)
	}
	if got[0].EventID.IsZero() {
		t.Error("EventID is zero; the hub does not mint one for a public event")
	}
}

// TestIntegrationStateProjection pins the whole mapping. Every client state must
// project, because a state that did not would silently publish nothing and leave
// a consumer rendering a binding that has moved on.
func TestIntegrationStateProjection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		from client.State
		want event.IntegrationState
	}{
		{client.StateConfigured, event.IntegrationStarting},
		{client.StateStarting, event.IntegrationStarting},
		{client.StateAuthenticating, event.IntegrationStarting},
		{client.StateDiscovering, event.IntegrationStarting},
		{client.StateReady, event.IntegrationReady},
		{client.StateDegraded, event.IntegrationDegraded},
		{client.StateReconnecting, event.IntegrationDegraded},
		{client.StateFailed, event.IntegrationFailed},
		{client.StateClosing, event.IntegrationClosed},
		{client.StateClosed, event.IntegrationClosed},
	}
	for _, tt := range tests {
		t.Run(tt.from.String(), func(t *testing.T) {
			t.Parallel()
			got, ok := integrationState(tt.from)
			if !ok {
				t.Fatalf("integrationState(%v) not ok; every client state must project", tt.from)
			}
			if got != tt.want {
				t.Errorf("integrationState(%v) = %v, want %v", tt.from, got, tt.want)
			}
		})
	}
}

// TestIntegrationStateRejectsUnknown proves the projection fails closed. A state
// outside the client's declared range must publish nothing rather than invent a
// status.
func TestIntegrationStateRejectsUnknown(t *testing.T) {
	t.Parallel()
	if _, ok := integrationState(client.State(0)); ok {
		t.Error("integrationState(0) is ok; the zero state is not a state")
	}
	if _, ok := integrationState(client.State(99)); ok {
		t.Error("integrationState(99) is ok; an undeclared state must not project")
	}
}

// TestFailureEventsBecomeStatuses covers the events that carry a reason. Each
// asserts the state AND that the Detail names the class, since a Degraded with
// no reason is a status an operator cannot act on.
func TestFailureEventsBecomeStatuses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		ev         client.Event
		want       event.IntegrationState
		wantDetail string
	}{
		{
			// Retrying is the difference between "wait" and "act".
			name:       "connection lost while retrying is degraded",
			ev:         client.ConnectionLost{Binding: "github", Class: client.FailureTransportClosed, Retrying: true},
			want:       event.IntegrationDegraded,
			wantDetail: client.FailureTransportClosed.String(),
		},
		{
			name:       "connection lost for good is failed",
			ev:         client.ConnectionLost{Binding: "github", Class: client.FailureTransportClosed, Retrying: false},
			want:       event.IntegrationFailed,
			wantDetail: client.FailureTransportClosed.String(),
		},
		{
			// A rejected refresh leaves the adopted generation serving, so the
			// binding is degraded and never failed.
			name:       "catalog rejected is degraded",
			ev:         client.CatalogRejected{Binding: "github", Class: client.FailureServerProtocol, Adopted: 3},
			want:       event.IntegrationDegraded,
			wantDetail: client.FailureServerProtocol.String(),
		},
		{
			name:       "connection restored is ready",
			ev:         client.ConnectionRestored{Binding: "github", Adopted: 3, Generation: 4},
			want:       event.IntegrationReady,
			wantDetail: "re-established",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, bs, events, _ := managerForEvents(t)
			m.onClientEvent(bs, tt.ev)
			got := events.statuses()
			if len(got) != 1 {
				t.Fatalf("published %d statuses, want 1", len(got))
			}
			if got[0].State != tt.want {
				t.Errorf("State = %v, want %v", got[0].State, tt.want)
			}
			if !strings.Contains(got[0].Detail, tt.wantDetail) {
				t.Errorf("Detail = %q, want it to mention %q", got[0].Detail, tt.wantDetail)
			}
		})
	}
}

// TestNonStatusEventsPublishNothing pins the other half of the mapping. These
// events are real and useful, but none of them is a statement about whether the
// binding is up, and publishing a status for one would churn the stream with
// non-transitions.
func TestNonStatusEventsPublishNothing(t *testing.T) {
	t.Parallel()
	evs := []client.Event{
		client.CatalogStale{Binding: "github", Family: "tools"},
		client.CatalogCandidate{Binding: "github", Generation: 2},
		client.CatalogRefreshed{Binding: "github", Generation: 1},
		client.CatalogAdopted{Binding: "github", Generation: 2},
		client.ServerLog{Binding: "github", Level: client.LogError, Text: "something"},
		client.RequestProgress{Binding: "github", Progress: 1},
	}
	for _, ev := range evs {
		t.Run(fmt.Sprintf("%T", ev), func(t *testing.T) {
			t.Parallel()
			m, bs, events, _ := managerForEvents(t)
			m.onClientEvent(bs, ev)
			if got := events.statuses(); len(got) != 0 {
				t.Errorf("published %d statuses, want 0: %+v", len(got), got)
			}
		})
	}
}

// TestUnknownClientEventIsIgnored proves the type switch's default arm is real.
// client.Event is sealed to pkg/client, which may add a member; an unknown one
// must be ignored rather than panic the client's event goroutine.
func TestUnknownClientEventIsIgnored(t *testing.T) {
	t.Parallel()
	m, bs, events, _ := managerForEvents(t)
	// A nil Event is the closest this package can get to "a member added later"
	// without pkg/client's cooperation: statusFor's switch must fall to default.
	got, ok := m.statusFor("github", nil)
	if ok {
		t.Errorf("statusFor(nil) = %+v, ok; an unrecognized event must not become a status", got)
	}
	m.onClientEvent(bs, nil)
	if s := events.statuses(); len(s) != 0 {
		t.Errorf("published %d statuses for an unrecognized event, want 0", len(s))
	}
}

// canary is a marker no event may ever carry. It stands for the class of thing a
// server controls: a bearer token in an error message, a secret in a log line, a
// version string in a drift report.
const canary = "CANARY-c2VjcmV0-SHOULD-NEVER-APPEAR"

// TestEventsRedactServerText is the redaction guard, and it is the reason
// statusFor builds Detail from a FailureClass instead of a Message.
//
// Every field here is server-influenced: an *Error's Msg is bounded and
// normalized but still describes what a server said, ServerLog.Text is verbatim
// server output, and ConnectionRestored.Drift is a server's own claim about its
// identity. None of it may reach an event that a host will log, render, or ship
// to telemetry.
func TestEventsRedactServerText(t *testing.T) {
	t.Parallel()
	evs := []client.Event{
		client.ConnectionLost{Binding: "github", Class: client.FailureTransportClosed, Message: canary, Retrying: true},
		client.ConnectionLost{Binding: "github", Class: client.FailureTransportClosed, Message: canary, Retrying: false},
		client.CatalogRejected{Binding: "github", Class: client.FailureServerProtocol, Message: canary, Adopted: 1},
		client.ConnectionRestored{Binding: "github", Drift: canary, Server: client.ServerIdentity{Name: canary, Version: canary}},
		client.ServerLog{Binding: "github", Level: client.LogError, Text: canary, Logger: canary},
		client.RequestProgress{Binding: "github", Message: canary},
		client.CatalogStale{Binding: "github", Family: canary},
		client.CatalogCandidate{Binding: "github", Digest: canary},
		client.CatalogRefreshed{Binding: "github", Digest: canary},
		client.CatalogAdopted{Binding: "github", Digest: canary},
	}
	m, bs, events, reporter := managerForEvents(t)
	for _, ev := range evs {
		m.onClientEvent(bs, ev)
	}

	for _, published := range events.statuses() {
		// Sweep the whole struct rather than the fields this test remembers: a
		// field added later must be swept without anyone remembering to add it
		// here.
		if found := findCanary(reflect.ValueOf(published)); found != "" {
			t.Errorf("a published IntegrationStatus carries server text at %s: %+v", found, published)
		}
	}
	for _, n := range reporter.snapshot() {
		if strings.Contains(n.Message, canary) {
			t.Errorf("a Notice carries server text: %q", n.Message)
		}
	}
}

// findCanary walks v and reports the path of the first string containing the
// canary, or "" when there is none.
func findCanary(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		if strings.Contains(v.String(), canary) {
			return "<string>"
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if path := findCanary(v.Field(i)); path != "" {
				return v.Type().Field(i).Name + "." + path
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if path := findCanary(v.Index(i)); path != "" {
				return fmt.Sprintf("[%d].%s", i, path)
			}
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return findCanary(v.Elem())
		}
	}
	return ""
}

// TestInvalidStatusIsNotPublished proves the producer validates.
//
// hub.PublishEvent does not validate a public event's body, and an Ephemeral
// event never reaches the journal's append-time validation — so if this adapter
// did not validate, an unbounded Detail would go straight onto the stream. The
// over-long Detail here is built from a FailureClass, which is this module's own
// constant, so the only way to drive it is directly.
func TestInvalidStatusIsNotPublished(t *testing.T) {
	t.Parallel()
	m, _, events, reporter := managerForEvents(t)

	m.publish(m.status("github", event.IntegrationDegraded, strings.Repeat("d", event.MaxIntegrationDetailBytes+1)))

	if got := events.statuses(); len(got) != 0 {
		t.Fatalf("published %d invalid statuses, want 0", len(got))
	}
	if !reporter.sawKind(NoticeEventRejected) {
		t.Error("an invalid status was dropped without a Notice; the fact that the sink is broken has nowhere else to go")
	}
}

// TestHostRefusalIsReported proves a publisher that says no is not silently
// ignored. There is nobody to return the error to — this runs on a client's
// event goroutine — so the Reporter is the only honest sink.
func TestHostRefusalIsReported(t *testing.T) {
	t.Parallel()
	m, bs, events, reporter := managerForEvents(t)
	events.mu.Lock()
	events.err = errors.New("the hub is closed")
	events.mu.Unlock()

	m.onClientEvent(bs, client.StateChanged{Binding: "github", To: client.StateReady})

	if !reporter.sawKind(NoticeEventRejected) {
		t.Error("a refused publish produced no Notice")
	}
}

// TestPublishSurvivesNilReporter pins that the optional Reporter really is
// optional on the failure path — the one place a nil would be reached.
func TestPublishSurvivesNilReporter(t *testing.T) {
	t.Parallel()
	events := &capturingEvents{err: errors.New("refused")}
	deps := testDeps()
	deps.Events = events
	deps.Reporter = nil
	m, err := NewManager([]Binding{scriptedBinding("github", ScopeSession, okTransport("github"))}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	// Must not panic.
	m.onClientEvent(m.states["github"], client.StateChanged{Binding: "github", To: client.StateReady})
}

// TestHandlersAreInstalled proves the connection actually gets the callbacks. A
// bridge nothing is wired to is a bridge that never carries anything — and this
// is exactly what was missing before this task: Handlers.Elicitation was
// declared and nothing ever set it.
func TestHandlersAreInstalled(t *testing.T) {
	t.Parallel()
	m, bs, _, _ := managerForEvents(t)
	h := m.handlersFor(bs)
	if h.Event == nil {
		t.Error("Handlers.Event is nil; client events would be dropped")
	}
	if h.Elicitation == nil {
		t.Error("Handlers.Elicitation is nil; a server's request for input would have nowhere to go")
	}
}
