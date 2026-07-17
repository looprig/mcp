package mcpharness

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/core/uuid"
	"github.com/looprig/mcp/pkg/client"
)

// scriptedPolicy is a SamplingPolicy a test can script and interrogate.
type scriptedPolicy struct {
	res SampleResult
	err error

	mu   sync.Mutex
	seen []SampleRequest
}

func (p *scriptedPolicy) Sample(_ context.Context, req SampleRequest) (SampleResult, error) {
	p.mu.Lock()
	p.seen = append(p.seen, req)
	p.mu.Unlock()
	return p.res, p.err
}

func (p *scriptedPolicy) requests() []SampleRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]SampleRequest(nil), p.seen...)
}

func (p *scriptedPolicy) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

// okPolicy is a policy that always completes.
func okPolicy() *scriptedPolicy {
	return &scriptedPolicy{res: SampleResult{Model: "test-model", Text: "hi", StopReason: "end_turn"}}
}

// samplerFor builds a sampler over one binding, with a scripted policy.
func samplerFor(t *testing.T, scope Scope, policy SamplingPolicy) (*sampler, *recordingReporter) {
	t.Helper()
	reporter := &recordingReporter{}
	deps := testDeps()
	deps.Sampling = policy
	deps.Reporter = reporter

	b := scriptedBinding("github", scope, okTransport("github"))
	if scope == ScopeLoop {
		b.Loop = samplingLoopID
		b.Visibility = LoopSelector{}
	}
	m, err := NewManager([]Binding{b}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	return &sampler{m: m, bs: m.states["github"]}, reporter
}

// samplingLoopID is the Loop a loop-scoped sampling binding belongs to.
var samplingLoopID = uuid.MustParse("77777777-7777-4777-8777-777777777777")

// clientRequest is a well-formed sampling request as pkg/client would deliver
// one.
func clientRequest() client.SampleRequest {
	return client.SampleRequest{
		Binding:      "github",
		SystemPrompt: "be brief",
		Messages: []client.SampleMessage{
			{Role: client.SampleRoleUser, Text: "hello"},
			{Role: client.SampleRoleAssistant, Text: "hi"},
		},
		MaxTokens: 512,
	}
}

// TestSamplingSeamCarriesNoAuthority is the structural half of design §Optional
// sampling's "sampling never receives a Harness Session controller or
// unrestricted tool registry", enforced at THIS layer.
//
// pkg/client proves the same thing about its own SampleRequest, but that proof
// does not reach here: this package defines its own seam types, and a Manager,
// a bindingState, a *client.Client and a tool registry are all in scope in
// sampling.go. Nothing stops a future field from carrying one except this.
//
// It sweeps by field KIND rather than by name, so a field named innocently is
// caught anyway: an interface, a pointer, a func, a chan or a map is a thing a
// policy could act THROUGH, and every one of them fails. A field added here must
// argue with this test.
func TestSamplingSeamCarriesNoAuthority(t *testing.T) {
	t.Parallel()
	for _, typ := range []reflect.Type{
		reflect.TypeOf(SampleRequest{}),
		reflect.TypeOf(SampleResult{}),
		reflect.TypeOf(SampleMessage{}),
	} {
		t.Run(typ.Name(), func(t *testing.T) {
			t.Parallel()
			for i := range typ.NumField() {
				f := typ.Field(i)
				if !inertField(f.Type) {
					t.Errorf("%s.%s is %s: a sampling policy must receive only inert data, and this field could carry authority",
						typ.Name(), f.Name, f.Type)
				}
			}
		})
	}
}

// inertField reports whether t can only ever hold data — never a reference to
// something a policy could act through. It mirrors pkg/client's own sweep, with
// Array added for uuid.UUID (a [16]byte, and the only reason LoopID is
// expressible here at all).
func inertField(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.String, reflect.Int, reflect.Int64, reflect.Uint8, reflect.Bool:
		return true
	case reflect.Slice, reflect.Array:
		return inertField(t.Elem())
	case reflect.Struct:
		for i := range t.NumField() {
			if !inertField(t.Field(i).Type) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// TestSamplingSweepRejectsAuthority proves the sweep above is a test and not a
// tautology: a struct carrying each shape of authority must fail it.
func TestSamplingSweepRejectsAuthority(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		typ  reflect.Type
	}{
		{"a session controller", reflect.TypeOf(struct{ M *Manager }{})},
		{"a tool registry", reflect.TypeOf(struct{ Tools map[string]string }{})},
		{"an interface", reflect.TypeOf(struct{ Any SamplingPolicy }{})},
		{"a callback", reflect.TypeOf(struct{ Call func() }{})},
		{"a channel", reflect.TypeOf(struct{ C chan int }{})},
		{"a nested reference", reflect.TypeOf(struct{ Inner struct{ M *Manager } }{})},
		{"a slice of references", reflect.TypeOf(struct{ Ms []*Manager }{})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if inertField(tt.typ.Field(0).Type) {
				t.Errorf("inertField(%s) is true; the sweep would not catch %s", tt.typ.Field(0).Type, tt.name)
			}
		})
	}
}

// TestSamplingHandlerRequiresPolicy is the fail-closed rule's mechanism: no
// policy, no handler. Installing a sampler that could only refuse would advertise
// a capability this host cannot honor, and Connect would never learn the
// application forgot to configure one.
func TestSamplingHandlerRequiresPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		policy     SamplingPolicy
		wantNil    bool
		wantReason string
	}{
		{
			name:       "no policy installs no handler",
			policy:     nil,
			wantNil:    true,
			wantReason: "a nil handler is what lets Connect reject a binding that requested the capability",
		},
		{
			name:       "a policy installs a handler",
			policy:     okPolicy(),
			wantNil:    false,
			wantReason: "a server's sampling request would have nowhere to go",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			deps := testDeps()
			deps.Sampling = tt.policy
			m, err := NewManager([]Binding{scriptedBinding("github", ScopeSession, okTransport("github"))}, deps)
			if err != nil {
				t.Fatalf("NewManager() error = %v", err)
			}
			t.Cleanup(func() { _ = m.Close(context.Background()) })

			h := m.handlersFor(m.states["github"])
			if (h.Sampling == nil) != tt.wantNil {
				t.Errorf("Handlers.Sampling nil = %v, want %v: %s", h.Sampling == nil, tt.wantNil, tt.wantReason)
			}
			// The other two are unconditional, and must stay so.
			if h.Event == nil {
				t.Error("Handlers.Event is nil; client events would be dropped")
			}
			if h.Elicitation == nil {
				t.Error("Handlers.Elicitation is nil; Gates is a required dep, so an elicitor always has somewhere to ask")
			}
		})
	}
}

// TestSamplingCapabilityWithoutPolicyFailsToStart is the fail-closed rule's
// OBSERVABLE behavior, and the point of the test is that this package does not
// implement it.
//
// A Binding that requests sampling with no policy installed must be a
// configuration error, not a binding that quietly comes up serving its tools with
// the capability it advertised missing. The decision is client.Handlers.advertised'
// — one rule, applied to elicitation, sampling and roots alike — and this asserts
// the adapter routes into it rather than holding a second opinion: the failure
// carries pkg/client's own class, and the transport is never dialed, because
// Connect refuses before it builds anything.
func TestSamplingCapabilityWithoutPolicyFailsToStart(t *testing.T) {
	t.Parallel()
	transport := okTransport("github")
	b := scriptedBinding("github", ScopeSession, transport)
	b.Server.Capabilities.Sampling = true
	b.Required = true

	deps := testDeps()
	deps.Sampling = nil
	m, err := NewManager([]Binding{b}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v; the omission is a startup failure, not a construction one", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	err = m.Start(context.Background())
	var startErr *StartupError
	if !errors.As(err, &startErr) {
		t.Fatalf("Start() error = %v, want a *StartupError: a required binding that cannot advertise what it asked for must not come up", err)
	}
	if len(startErr.Failures) != 1 {
		t.Fatalf("Start() reported %d failures, want 1: %+v", len(startErr.Failures), startErr.Failures)
	}
	if got := startErr.Failures[0].Class; got != client.FailureInvalidConfig {
		t.Errorf("failure class = %v, want %v (pkg/client's own classification, not this package's)", got, client.FailureInvalidConfig)
	}
	if !strings.Contains(startErr.Failures[0].Message, "Sampling") {
		t.Errorf("failure message = %q, want it to name the capability", startErr.Failures[0].Message)
	}
	if n := transport.dials.Load(); n != 0 {
		t.Errorf("the transport was dialed %d times; Connect must refuse before it contacts a server", n)
	}
}

// TestSamplingCapabilityWithPolicyStarts is the other half: the same binding,
// with a policy, comes up. Without this, the test above would pass on a Manager
// that could never start a sampling binding at all.
func TestSamplingCapabilityWithPolicyStarts(t *testing.T) {
	t.Parallel()
	b := scriptedBinding("github", ScopeSession, okTransport("github"))
	b.Server.Capabilities.Sampling = true
	b.Required = true

	deps := testDeps()
	deps.Sampling = okPolicy()
	m, err := NewManager([]Binding{b}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v; a binding with a policy must come up", err)
	}
}

// TestSamplingNotRequestedNeedsNoPolicy pins that a policy is not a cost every
// binding pays. Sampling authority is per-binding, and a binding that never asked
// for the capability must not be held to the configuration of one that did.
func TestSamplingNotRequestedNeedsNoPolicy(t *testing.T) {
	t.Parallel()
	b := scriptedBinding("github", ScopeSession, okTransport("github"))
	b.Required = true
	if b.Server.Capabilities.Sampling {
		t.Fatal("the fixture requests sampling; this test is about a binding that does not")
	}

	deps := testDeps()
	deps.Sampling = nil
	m, err := NewManager([]Binding{b}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v; a binding that never asked for sampling needs no policy", err)
	}
}

// TestSamplerRoutesToPolicy is the happy path: a server's request reaches the
// application's policy with everything the policy needs to decide, and the
// policy's answer reaches the server.
func TestSamplerRoutesToPolicy(t *testing.T) {
	t.Parallel()
	policy := okPolicy()
	s, _ := samplerFor(t, ScopeSession, policy)

	got, err := s.Sample(context.Background(), clientRequest())
	if err != nil {
		t.Fatalf("Sample() error = %v", err)
	}
	want := client.SampleResult{Model: "test-model", Text: "hi", StopReason: "end_turn"}
	if got != want {
		t.Errorf("Sample() = %+v, want %+v", got, want)
	}

	reqs := policy.requests()
	if len(reqs) != 1 {
		t.Fatalf("the policy saw %d requests, want 1", len(reqs))
	}
	req := reqs[0]
	if req.Binding != "github" {
		t.Errorf("Binding = %q, want github: a policy that trusts one server and not another switches on this", req.Binding)
	}
	if req.SystemPrompt != "be brief" {
		t.Errorf("SystemPrompt = %q, want %q", req.SystemPrompt, "be brief")
	}
	if req.MaxTokens != 512 {
		t.Errorf("MaxTokens = %d, want 512 (the ceiling pkg/client already capped)", req.MaxTokens)
	}
	wantMsgs := []SampleMessage{
		{Role: SampleRoleUser, Text: "hello"},
		{Role: SampleRoleAssistant, Text: "hi"},
	}
	if !reflect.DeepEqual(req.Messages, wantMsgs) {
		t.Errorf("Messages = %+v, want %+v", req.Messages, wantMsgs)
	}
}

// TestSamplerAttributesTheBindingItServes proves the attribution is taken from
// the state the handler was built for and not from the request.
//
// The two agree in practice — Binding.Validate refuses a binding whose
// Server.Name differs from its own — and this is what makes that agreement
// irrelevant rather than load-bearing. SampleRequest.Binding is the whole of
// "which authority is this" to a policy, so it must be a fact this side knows,
// not a claim carried alongside the request.
func TestSamplerAttributesTheBindingItServes(t *testing.T) {
	t.Parallel()
	policy := okPolicy()
	s, _ := samplerFor(t, ScopeSession, policy)

	req := clientRequest()
	req.Binding = "impostor"

	if _, err := s.Sample(context.Background(), req); err != nil {
		t.Fatalf("Sample() error = %v", err)
	}
	if got := policy.requests()[0].Binding; got != "github" {
		t.Errorf("Binding = %q, want github: attribution must come from the binding this handler serves, never from the request", got)
	}
}

// TestSamplerAttributesLoop covers the one thing this adapter adds that
// pkg/client cannot: which Loop's budget is being spent.
func TestSamplerAttributesLoop(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		scope Scope
		want  uuid.UUID
		why   string
	}{
		{
			name:  "a loop-scoped binding names its owner",
			scope: ScopeLoop,
			want:  samplingLoopID,
			why:   "a policy budgeting per Loop must know whose budget this is",
		},
		{
			name:  "a session-scoped binding names no Loop",
			scope: ScopeSession,
			want:  uuid.UUID{},
			why:   "a shared server's request belongs to the Session, not to whichever Loop was first",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			policy := okPolicy()
			s, _ := samplerFor(t, tt.scope, policy)

			if _, err := s.Sample(context.Background(), clientRequest()); err != nil {
				t.Fatalf("Sample() error = %v", err)
			}
			if got := policy.requests()[0].LoopID; got != tt.want {
				t.Errorf("LoopID = %v, want %v: %s", got, tt.want, tt.why)
			}
		})
	}
}

// TestSamplerClassifiesPolicyRefusals is the denied/failed distinction, which is
// the whole reason ErrSamplingDenied is a sentinel.
//
// A denial is a budget being enforced and a failure is a defect. A host that
// could not tell them apart could not tell its own policy working from its own
// policy broken.
func TestSamplerClassifiesPolicyRefusals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		err         error
		wantClass   client.FailureClass
		wantMessage string
	}{
		{
			name:        "the sentinel is a denial",
			err:         ErrSamplingDenied,
			wantClass:   client.FailureSamplingDenied,
			wantMessage: "declined",
		},
		{
			name:        "a wrapped sentinel is a denial",
			err:         fmt.Errorf("this loop is over its budget: %w", ErrSamplingDenied),
			wantClass:   client.FailureSamplingDenied,
			wantMessage: "declined",
		},
		{
			// Not FailureSamplingDenied, and that is the load-bearing part:
			// pkg/client reads this class to tell a budget being enforced from a
			// host that broke.
			name:        "anything else is a failure",
			err:         errors.New("the model endpoint is unreachable"),
			wantClass:   client.FailureIndeterminate,
			wantMessage: "failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, reporter := samplerFor(t, ScopeSession, &scriptedPolicy{err: tt.err})

			_, err := s.Sample(context.Background(), clientRequest())
			if err == nil {
				t.Fatal("Sample() error = nil; a policy that refused must not produce a completion")
			}
			class, ok := client.ClassOf(err)
			if !ok {
				t.Fatalf("the error %v carries no class; pkg/client cannot tell a denial from a defect", err)
			}
			if class != tt.wantClass {
				t.Errorf("class = %v, want %v", class, tt.wantClass)
			}
			if !errors.Is(err, tt.err) {
				t.Errorf("the policy's error is not in the chain; a host cannot diagnose its own policy")
			}

			notices := reporter.snapshot()
			if len(notices) != 1 {
				t.Fatalf("the reporter saw %d notices, want 1: %+v", len(notices), notices)
			}
			if notices[0].Kind != NoticeSamplingDenied {
				t.Errorf("Kind = %v, want %v", notices[0].Kind, NoticeSamplingDenied)
			}
			if !strings.Contains(notices[0].Message, tt.wantMessage) {
				t.Errorf("Message = %q, want it to say %q", notices[0].Message, tt.wantMessage)
			}
		})
	}
}

// TestSamplerRefusalTellsServerNothing is the probe-resistance rule, and it is
// the reason both refusal paths build their own message instead of rendering the
// policy's.
//
// A server that can read why it was refused can search for a request that gets
// past the rule. The host's own reason goes to the Reporter; the server gets
// "denied".
//
// The rendering is asserted at THIS layer on purpose. pkg/client would also
// decline to render a cause under a message of its own — but a refusal that is
// redacted only because a downstream package renders it a certain way is one that
// leaks the day that rendering changes, so the error this file hands over is
// already safe on its face.
func TestSamplerRefusalTellsServerNothing(t *testing.T) {
	t.Parallel()
	const secret = "SECRET-POLICY-RULE: budget for tenant 42 is exhausted"
	tests := []struct {
		name string
		err  error
	}{
		{"a denial", fmt.Errorf("%s: %w", secret, ErrSamplingDenied)},
		{"a failure", errors.New(secret)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, reporter := samplerFor(t, ScopeSession, &scriptedPolicy{err: tt.err})

			_, err := s.Sample(context.Background(), clientRequest())
			if err == nil {
				t.Fatal("Sample() error = nil")
			}
			// Error() is what pkg/client renders toward the server.
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the error a server sees carries the host's own policy reason: %q", err.Error())
			}
			// ...and the host still gets it.
			var found bool
			for _, n := range reporter.snapshot() {
				if strings.Contains(n.Message, "SECRET-POLICY-RULE") {
					found = true
				}
			}
			if !found {
				t.Error("the host's Reporter never learned why; a refusal nobody can explain is one nobody can fix")
			}
		})
	}
}

// TestSamplerRefusesUnknownRole is the boundary re-check. pkg/client already
// refuses a role it cannot attribute, so this is unreachable in practice — and it
// fails closed anyway, because a policy weighing "the user asked for this" must
// never be shown a message attributed to the wrong author.
func TestSamplerRefusesUnknownRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		role client.SampleRole
	}{
		{"the zero role", client.SampleRole(0)},
		{"an undeclared role", client.SampleRole(99)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			policy := okPolicy()
			s, reporter := samplerFor(t, ScopeSession, policy)

			req := clientRequest()
			req.Messages = []client.SampleMessage{{Role: tt.role, Text: "hello"}}

			_, err := s.Sample(context.Background(), req)
			if err == nil {
				t.Fatal("Sample() error = nil; an unattributable message must not reach a policy")
			}
			if class, _ := client.ClassOf(err); class != client.FailureSamplingDenied {
				t.Errorf("class = %v, want %v", class, client.FailureSamplingDenied)
			}
			if n := policy.calls(); n != 0 {
				t.Errorf("the policy was called %d times; nothing may be spent on a request this adapter could not route", n)
			}
			if !reporter.sawKind(NoticeSamplingDenied) {
				t.Error("a routing refusal produced no Notice")
			}
		})
	}
}

// TestSampleAuditReportsRequestsAndOutcomes is design §Optional sampling's
// "sampling requests and outcomes are audited".
//
// It matters that these arrive at all: the Manager owns Handlers.Event for every
// binding, so without this route an application composing MCP with Harness would
// have NO way to see that a server is spending its model budget — the client's
// events would be received and dropped.
func TestSampleAuditReportsRequestsAndOutcomes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ev       client.Event
		wantKind NoticeKind
		wantText []string
	}{
		{
			name:     "a request reports its shape",
			ev:       client.SamplingRequested{Binding: "github", Messages: 3, MaxTokens: 1024, Depth: 2},
			wantKind: NoticeSamplingRequested,
			wantText: []string{"3 message(s)", "1024 token budget", "depth 2"},
		},
		{
			name:     "a completion reports its model",
			ev:       client.SamplingResolved{Binding: "github", Outcome: client.SampleCompleted, Model: "test-model", Duration: 2 * time.Second},
			wantKind: NoticeSamplingResolved,
			wantText: []string{"completed", "2s", "test-model"},
		},
		{
			name:     "a denial reports no model",
			ev:       client.SamplingResolved{Binding: "github", Outcome: client.SampleDenied, Duration: time.Second},
			wantKind: NoticeSamplingResolved,
			wantText: []string{"denied"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, bs, events, reporter := managerForEvents(t)

			m.onClientEvent(bs, tt.ev)

			notices := reporter.snapshot()
			if len(notices) != 1 {
				t.Fatalf("the reporter saw %d notices, want 1: %+v", len(notices), notices)
			}
			if notices[0].Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", notices[0].Kind, tt.wantKind)
			}
			if notices[0].Binding != "github" {
				t.Errorf("Binding = %q, want github", notices[0].Binding)
			}
			for _, want := range tt.wantText {
				if !strings.Contains(notices[0].Message, want) {
					t.Errorf("Message = %q, want it to contain %q", notices[0].Message, want)
				}
			}
			// A sampling event is not a statement about whether the binding is up.
			if got := events.statuses(); len(got) != 0 {
				t.Errorf("published %d statuses for a sampling event, want 0: %+v", len(got), got)
			}
		})
	}
}

// TestSampleAuditReportsNoModelForARefusal pins the suffix. A denied request has
// no model, and rendering an empty one as though it were a name would make every
// refusal read like a completion.
func TestSampleAuditReportsNoModelForARefusal(t *testing.T) {
	t.Parallel()
	m, bs, _, reporter := managerForEvents(t)

	m.onClientEvent(bs, client.SamplingResolved{Binding: "github", Outcome: client.SampleDenied, Duration: time.Second})

	msg := reporter.snapshot()[0].Message
	if strings.Contains(msg, "model") {
		t.Errorf("Message = %q; a request that ran no model must not name one", msg)
	}
}

// TestSampleAuditBoundsHostText holds Notice's own contract — Message is bounded
// — for the one input to it this module does not author. A policy is host code,
// not a server, so this is not redaction; it is a bound this module promised and
// must keep whatever a host hands it.
func TestSampleAuditBoundsHostText(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("m", 4096)

	t.Run("a model name from the audit path", func(t *testing.T) {
		t.Parallel()
		m, bs, _, reporter := managerForEvents(t)
		m.onClientEvent(bs, client.SamplingResolved{Binding: "github", Outcome: client.SampleCompleted, Model: long})
		if got := len(reporter.snapshot()[0].Message); got > maxSampleNoticeTextBytes {
			t.Errorf("Message is %d bytes, over the %d byte bound", got, maxSampleNoticeTextBytes)
		}
	})

	t.Run("a decline reason from the policy", func(t *testing.T) {
		t.Parallel()
		s, reporter := samplerFor(t, ScopeSession, &scriptedPolicy{err: fmt.Errorf("%s: %w", long, ErrSamplingDenied)})
		if _, err := s.Sample(context.Background(), clientRequest()); err == nil {
			t.Fatal("Sample() error = nil")
		}
		if got := len(reporter.snapshot()[0].Message); got > maxSampleNoticeTextBytes {
			t.Errorf("Message is %d bytes, over the %d byte bound", got, maxSampleNoticeTextBytes)
		}
	})
}

// TestSamplingSurvivesNilReporter pins that the optional Reporter really is
// optional on the sampling paths, which are the newest places a nil would be
// reached.
func TestSamplingSurvivesNilReporter(t *testing.T) {
	t.Parallel()
	deps := testDeps()
	deps.Sampling = &scriptedPolicy{err: ErrSamplingDenied}
	deps.Reporter = nil
	m, err := NewManager([]Binding{scriptedBinding("github", ScopeSession, okTransport("github"))}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	bs := m.states["github"]

	// Must not panic.
	if _, err := (&sampler{m: m, bs: bs}).Sample(context.Background(), clientRequest()); err == nil {
		t.Fatal("Sample() error = nil")
	}
	m.onClientEvent(bs, client.SamplingRequested{Binding: "github", Messages: 1, MaxTokens: 10, Depth: 1})
	m.onClientEvent(bs, client.SamplingResolved{Binding: "github", Outcome: client.SampleDenied})
}

// TestNoticeKindStrings pins the audit vocabulary. A Notice a host cannot name is
// one it cannot filter, route, or alert on.
func TestNoticeKindStrings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind NoticeKind
		want string
	}{
		{NoticeSamplingRequested, "sampling_requested"},
		{NoticeSamplingResolved, "sampling_resolved"},
		{NoticeSamplingDenied, "sampling_denied"},
		{NoticeKind(0), "unknown"},
		{NoticeKind(250), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("NoticeKind(%d).String() = %q, want %q", uint8(tt.kind), got, tt.want)
			}
		})
	}
}

// TestSampleRoleStrings pins the seam's role vocabulary, including the zero,
// which is not a role.
func TestSampleRoleStrings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		role SampleRole
		want string
	}{
		{SampleRoleUser, "user"},
		{SampleRoleAssistant, "assistant"},
		{SampleRole(0), "unknown"},
		{SampleRole(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.role.String(); got != tt.want {
				t.Errorf("SampleRole(%d).String() = %q, want %q", uint8(tt.role), got, tt.want)
			}
		})
	}
}
