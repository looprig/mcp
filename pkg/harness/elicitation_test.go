package mcpharness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/mcp/pkg/client"
)

// scriptedGates answers OpenGate from a script and records what it was asked.
type scriptedGates struct {
	mu       sync.Mutex
	requests []GateRequest
	// answer is consulted per request. A nil answer declines.
	answer func(GateRequest) (GateResponse, error)
	// block, when non-nil, is waited on before answering — the seam a
	// cancellation or deadline test needs.
	block chan struct{}
}

func (g *scriptedGates) OpenGate(ctx context.Context, req GateRequest) (GateResponse, error) {
	g.mu.Lock()
	g.requests = append(g.requests, req)
	answer, block := g.answer, g.block
	g.mu.Unlock()

	if block != nil {
		// Honor ctx, as a real opener must.
		select {
		case <-block:
		case <-ctx.Done():
			return GateResponse{}, ctx.Err()
		}
	}
	if answer == nil {
		return GateResponse{Action: gate.FormActionDecline}, nil
	}
	return answer(req)
}

func (g *scriptedGates) opened() []GateRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]GateRequest(nil), g.requests...)
}

// elicitorFor builds an elicitor over one binding, with a scripted gate opener.
func elicitorFor(t *testing.T, scope Scope, gates *scriptedGates) (*elicitor, *recordingReporter) {
	t.Helper()
	reporter := &recordingReporter{}
	deps := testDeps()
	deps.Gates = gates
	deps.Reporter = reporter
	deps.Events = &capturingEvents{}

	b := scriptedBinding("github", scope, okTransport("github"))
	if scope == ScopeLoop {
		b.Loop = loopA
	}
	m, err := NewManager([]Binding{b}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	return &elicitor{m: m, bs: m.states["github"]}, reporter
}

// formSchema builds an MCP elicitation requestedSchema.
func formSchema(t *testing.T, props map[string]any, required ...string) json.RawMessage {
	t.Helper()
	doc := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		doc["required"] = required
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// The credential rule
// ---------------------------------------------------------------------------

// TestFormRejectsCredentialFields is the security guard of this file.
//
// Design §Elicitation: form requests that solicit passwords, tokens, private
// keys, or other credentials are rejected, because a form answer is a DURABLE
// value — it reaches gate records and journals — and sensitive authorization
// belongs in URL elicitation or pkg/auth instead.
func TestFormRejectsCredentialFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		prop map[string]any
	}{
		// (1) the schema's own declaration.
		{"format password", map[string]any{"secret_field": map[string]any{"type": "string", "format": "password"}}},
		{"writeOnly", map[string]any{"opaque": map[string]any{"type": "string", "writeOnly": true}}},

		// (2) the field name, in every spelling the tokenizer must fold.
		{"password", map[string]any{"password": map[string]any{"type": "string"}}},
		{"passwd", map[string]any{"passwd": map[string]any{"type": "string"}}},
		{"passphrase", map[string]any{"passphrase": map[string]any{"type": "string"}}},
		{"snake api_key", map[string]any{"api_key": map[string]any{"type": "string"}}},
		{"camel apiKey", map[string]any{"apiKey": map[string]any{"type": "string"}}},
		{"screaming API_KEY", map[string]any{"API_KEY": map[string]any{"type": "string"}}},
		{"kebab access-token", map[string]any{"access-token": map[string]any{"type": "string"}}},
		{"camel refreshToken", map[string]any{"refreshToken": map[string]any{"type": "string"}}},
		{"privateKey", map[string]any{"privateKey": map[string]any{"type": "string"}}},
		{"clientSecret", map[string]any{"clientSecret": map[string]any{"type": "string"}}},
		{"sshKey", map[string]any{"sshKey": map[string]any{"type": "string"}}},
		{"bearer", map[string]any{"bearer": map[string]any{"type": "string"}}},
		{"token", map[string]any{"token": map[string]any{"type": "string"}}},
		{"credential", map[string]any{"credential": map[string]any{"type": "string"}}},
		{"authorization", map[string]any{"authorization": map[string]any{"type": "string"}}},
		{"otp", map[string]any{"otp": map[string]any{"type": "string"}}},
		{"cvv", map[string]any{"cvv": map[string]any{"type": "string"}}},
		{"pin", map[string]any{"pin": map[string]any{"type": "string"}}},

		// (3) the label, which is what a person actually reads. A field named
		// innocuously but LABELLED "API Key" is asking for a credential.
		{"innocent name, credential label", map[string]any{
			"f1": map[string]any{"type": "string", "title": "API Key"},
		}},
		{"label password", map[string]any{
			"value": map[string]any{"type": "string", "title": "Your Password"},
		}},

		// A credential field among innocent ones kills the whole form: a partial
		// answer is one the server would read as complete.
		{"one bad field among good", map[string]any{
			"repo":    map[string]any{"type": "string"},
			"apiKey":  map[string]any{"type": "string"},
			"dry_run": map[string]any{"type": "boolean"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{}
			e, reporter := elicitorFor(t, ScopeSession, gates)

			res, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github",
				Mode:    client.ElicitModeForm,
				Message: "please fill this in",
				Schema:  formSchema(t, tt.prop),
			})
			if err != nil {
				t.Fatalf("Elicit() error = %v; a refusal is a decline, never an error", err)
			}
			if res.Action != client.ElicitDecline {
				t.Errorf("Action = %v, want decline", res.Action)
			}
			// The whole point: nobody was ever asked.
			if opened := gates.opened(); len(opened) != 0 {
				t.Errorf("opened %d gates for a credential-soliciting form, want 0", len(opened))
			}
			if !reporter.sawKind(NoticeElicitationDeclined) {
				t.Error("no Notice explained the decline; the host cannot see why")
			}
		})
	}
}

// TestFormRejectsCredentialSolicitingBody covers the hole the field rules leave
// open: a server names a field "value", gives it no title, and asks for the
// secret in the MESSAGE instead. Every field-level check passes, and — since
// form answers are journaled unredacted — the secret lands in the journal.
//
// The body rule needs a credential token AND a solicitation verb AND a free-text
// field to land in. Each case below says which of those it is testing.
func TestFormRejectsCredentialSolicitingBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		message string
		props   map[string]any
	}{
		// The reported hole, verbatim: innocuous field, message does the asking.
		{
			name:    "innocuous field, message asks for an api key",
			message: "paste your API key here",
			props:   map[string]any{"value": map[string]any{"type": "string"}},
		},
		// Oblique: never says "password", but "authorization" + "copy" is a
		// request for a bearer token by another name.
		{
			name:    "oblique, header wording",
			message: "Copy the Authorization header from your dashboard and put it below.",
			props:   map[string]any{"value": map[string]any{"type": "string"}},
		},
		{
			name:    "oblique, pair only in the body",
			message: "To continue, provide the access token shown after you sign in.",
			props:   map[string]any{"input": map[string]any{"type": "string"}},
		},
		// A credential-soliciting body kills the WHOLE form, not the free-text
		// field: the body is addressed to the form, so there is no way to know
		// which field it meant, and a partial answer is one the server would read
		// as complete.
		{
			name:    "body solicits among several innocent fields",
			message: "Enter your API key to continue.",
			props: map[string]any{
				"repo":    map[string]any{"type": "string"},
				"dry_run": map[string]any{"type": "boolean"},
			},
		},
		// A numeric field is still a text box, and a PIN still fits in it.
		{
			name:    "free-text integer field",
			message: "Type the PIN from your authenticator.",
			props:   map[string]any{"n": map[string]any{"type": "integer"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{}
			e, reporter := elicitorFor(t, ScopeSession, gates)

			res, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github",
				Mode:    client.ElicitModeForm,
				Message: tt.message,
				Schema:  formSchema(t, tt.props),
			})
			if err != nil {
				t.Fatalf("Elicit() error = %v; a refusal is a decline, never an error", err)
			}
			if res.Action != client.ElicitDecline {
				t.Errorf("Action = %v, want decline for message %q", res.Action, tt.message)
			}
			if opened := gates.opened(); len(opened) != 0 {
				t.Errorf("opened %d gates for a credential-soliciting body, want 0", len(opened))
			}
			if !reporter.sawKind(NoticeElicitationDeclined) {
				t.Error("no Notice explained the decline; the host cannot see why")
			}
		})
	}
}

// TestFormBodyRuleFalsePositives is the load-bearing half of the body rule. The
// body is PROSE, and a rule over prose that fires too often declines legitimate
// servers' forms for the words in their own message — so every case here must be
// accepted, and each one is a shape a real server plausibly sends.
func TestFormBodyRuleFalsePositives(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		message string
		props   map[string]any
	}{
		{
			name:    "ordinary form, ordinary message",
			message: "Which repository should I open the pull request against?",
			props:   map[string]any{"repo": map[string]any{"type": "string"}},
		},
		{
			// A credential token with no solicitation verb is prose ABOUT a
			// credential, not a request for one. This is the condition that keeps
			// the rule off the majority of security-adjacent copy.
			name:    "credential token, no solicitation verb",
			message: "Your API key is already configured. Which repo?",
			props:   map[string]any{"repo": map[string]any{"type": "string"}},
		},
		{
			// A solicitation verb with no credential token is just a form asking a
			// question, which is what forms do.
			name:    "solicitation verb, no credential token",
			message: "Enter the branch name to deploy.",
			props:   map[string]any{"branch": map[string]any{"type": "string"}},
		},
		{
			// Both signals, but nowhere to type a secret: a confirm and a select
			// cannot carry one, so the body has no landing site. This is what lets
			// a disclaimer ("we will never ask you to enter your password") ship on
			// a confirmation dialog.
			name:    "disclaimer prose, no free-text field",
			message: "We will never ask you to enter your password. Continue?",
			props: map[string]any{
				"ok":   map[string]any{"type": "boolean"},
				"mode": map[string]any{"type": "string", "enum": []any{"fast", "safe"}},
			},
		},
		{
			// tokenize's camelCase/substring discipline has to hold on prose too:
			// "author" is not "auth", "shipping" is not "pin".
			name:    "substrings that are not tokens",
			message: "Enter the author and shipping details for the tokenizer.",
			props:   map[string]any{"author": map[string]any{"type": "string"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{
				answer: func(req GateRequest) (GateResponse, error) {
					values := make(map[string]string, len(tt.props))
					for name := range tt.props {
						values[name] = "x"
					}
					// A select must answer with a real option, and a confirm with
					// a bool the re-encode accepts.
					payload, ok := req.Payload.(gate.FormPayload)
					if !ok {
						return GateResponse{}, fmt.Errorf("payload is %T", req.Payload)
					}
					for _, f := range payload.Schema.Fields {
						switch f.Kind {
						case gate.FieldSelect:
							values[f.Name] = f.Options[0].Value
						case gate.FieldConfirm:
							values[f.Name] = "true"
						}
					}
					return GateResponse{Action: gate.FormActionAccept, Values: values}, nil
				},
			}
			e, _ := elicitorFor(t, ScopeSession, gates)
			res, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github",
				Mode:    client.ElicitModeForm,
				Message: tt.message,
				Schema:  formSchema(t, tt.props),
			})
			if err != nil {
				t.Fatalf("Elicit() error = %v", err)
			}
			if res.Action != client.ElicitAccept {
				t.Fatalf("Action = %v, want accept; %q is not a credential solicitation", res.Action, tt.message)
			}
		})
	}
}

// TestFormFieldRuleWinsOverBody pins the precedence: a structural signal is what
// the operator's Notice names even when the body would have fired too. The
// decline is the same either way; which reason is reported is not, and a
// "format": "password" is a fact where a body match is a guess.
func TestFormFieldRuleWinsOverBody(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{}
	e, reporter := elicitorFor(t, ScopeSession, gates)

	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github",
		Mode:    client.ElicitModeForm,
		Message: "Please enter your password below.",
		Schema: formSchema(t, map[string]any{
			"pw": map[string]any{"type": "string", "format": "password"},
		}),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action != client.ElicitDecline {
		t.Fatalf("Action = %v, want decline", res.Action)
	}
	if len(gates.opened()) != 0 {
		t.Error("a gate was opened for a credential form")
	}
	var explained string
	for _, n := range reporter.snapshot() {
		if n.Kind == NoticeElicitationDeclined {
			explained = n.Message
		}
	}
	if explained == "" {
		t.Fatal("no Notice explained the decline")
	}
	if !strings.Contains(explained, `"format": "password"`) {
		t.Errorf("Notice = %q; want the schema's own declaration named, not the body match", explained)
	}
}

// TestFormAcceptsInnocentFields is the other half of the credential rule, and it
// is what stops the rule being "reject everything".
//
// Each name here contains a credential token as a SUBSTRING but not as a token —
// "author" contains "auth", "pinned" contains "pin", "tokenizer" contains
// "token". A substring rule would reject all of them, which is why tokenize
// splits on camelCase and separators instead.
func TestFormAcceptsInnocentFields(t *testing.T) {
	t.Parallel()
	names := []string{
		"author", "authority", "pinned", "spinner", "tokenizer",
		"shipping", "secretary", "keyboard", "monkey", "description",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{
				answer: func(GateRequest) (GateResponse, error) {
					return GateResponse{Action: gate.FormActionAccept, Values: map[string]string{name: "x"}}, nil
				},
			}
			e, _ := elicitorFor(t, ScopeSession, gates)
			res, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github",
				Mode:    client.ElicitModeForm,
				Message: "hello",
				Schema:  formSchema(t, map[string]any{name: map[string]any{"type": "string"}}),
			})
			if err != nil {
				t.Fatalf("Elicit() error = %v", err)
			}
			if res.Action != client.ElicitAccept {
				t.Fatalf("Action = %v, want accept; %q is not a credential field", res.Action, name)
			}
		})
	}
}

func TestTokenize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want []string
	}{
		{"apiKey", []string{"api", "key"}},
		{"api_key", []string{"api", "key"}},
		{"API_KEY", []string{"api", "key"}},
		{"api-key", []string{"api", "key"}},
		{"APIKey", []string{"api", "key"}},
		{"author", []string{"author"}},
		{"XMLHttpRequest", []string{"xml", "http", "request"}},
		{"", nil},
		{"__", nil},
		{"repo2", []string{"repo2"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got := tokenize(tt.in)
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("tokenize(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Form translation
// ---------------------------------------------------------------------------

// TestFormTranslatesAndReTypesAnswers is the round trip: an MCP schema becomes a
// gate form, and the gate's string answers become JSON of the schema's types.
//
// The re-typing is the part that cannot be skipped. A gate answer is
// map[string]string by contract, but the SDK validates an accepted result
// against the server's schema — so a boolean field answered "true" must go back
// as `true` and not `"true"`, or the server's own request fails.
func TestFormTranslatesAndReTypesAnswers(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{
		answer: func(GateRequest) (GateResponse, error) {
			return GateResponse{Action: gate.FormActionAccept, Values: map[string]string{
				"repo":    "looprig/mcp",
				"dry_run": "true",
				"count":   "42",
				"ratio":   "0.5",
				"mode":    "fast",
			}}, nil
		},
	}
	e, _ := elicitorFor(t, ScopeSession, gates)

	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github",
		Mode:    client.ElicitModeForm,
		Message: "configure the run",
		Schema: formSchema(t, map[string]any{
			"repo":    map[string]any{"type": "string", "title": "Repository"},
			"dry_run": map[string]any{"type": "boolean"},
			"count":   map[string]any{"type": "integer"},
			"ratio":   map[string]any{"type": "number"},
			"mode":    map[string]any{"type": "string", "enum": []any{"fast", "slow"}},
		}, "repo"),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action != client.ElicitAccept {
		t.Fatalf("Action = %v, want accept", res.Action)
	}

	// The answer must be JSON of the schema's types, not of the gate's strings.
	var got map[string]any
	if err := json.Unmarshal(res.Content, &got); err != nil {
		t.Fatalf("the result content is not JSON: %v", err)
	}
	if got["repo"] != "looprig/mcp" {
		t.Errorf("repo = %#v, want the string", got["repo"])
	}
	if got["dry_run"] != true {
		t.Errorf("dry_run = %#v, want the boolean true (not the string \"true\")", got["dry_run"])
	}
	if got["count"] != float64(42) {
		t.Errorf("count = %#v, want the number 42", got["count"])
	}
	if got["ratio"] != 0.5 {
		t.Errorf("ratio = %#v, want the number 0.5", got["ratio"])
	}

	// And the gate must have been a real form gate.
	opened := gates.opened()
	if len(opened) != 1 {
		t.Fatalf("opened %d gates, want 1", len(opened))
	}
	req := opened[0]
	if req.Kind != gate.KindForm {
		t.Errorf("Kind = %q, want %q", req.Kind, gate.KindForm)
	}
	payload, ok := req.Payload.(gate.FormPayload)
	if !ok {
		t.Fatalf("Payload is %T, want gate.FormPayload", req.Payload)
	}
	if payload.Body != "configure the run" {
		t.Errorf("Body = %q, want the server's message", payload.Body)
	}
	if err := gate.ValidateFormSchema(payload.Schema); err != nil {
		t.Errorf("the payload's schema is not a valid form: %v", err)
	}

	byName := map[string]gate.Field{}
	for _, f := range payload.Schema.Fields {
		byName[f.Name] = f
	}
	if byName["dry_run"].Kind != gate.FieldConfirm {
		t.Errorf("dry_run kind = %q, want confirm", byName["dry_run"].Kind)
	}
	if byName["mode"].Kind != gate.FieldSelect {
		t.Errorf("mode kind = %q, want select", byName["mode"].Kind)
	}
	if len(byName["mode"].Options) != 2 {
		t.Errorf("mode options = %v, want 2", byName["mode"].Options)
	}
	if byName["repo"].Label != "Repository" {
		t.Errorf("repo label = %q, want the schema's title", byName["repo"].Label)
	}
	if !byName["repo"].Required {
		t.Error("repo is not required; the schema says it is")
	}
	if byName["count"].Kind != gate.FieldText {
		t.Errorf("count kind = %q, want text (gate has no numeric kind)", byName["count"].Kind)
	}
}

// TestFormFieldsAreOrderedDeterministically pins that a form does not reshuffle
// between renders. Go's map iteration is randomized and JSON object order is not
// recoverable from a decoded map, so name order is the only stable order
// available — and a form whose fields move is one a person cannot trust.
func TestFormFieldsAreOrderedDeterministically(t *testing.T) {
	t.Parallel()
	schema := formSchema(t, map[string]any{
		"zulu":    map[string]any{"type": "string"},
		"alpha":   map[string]any{"type": "string"},
		"mike":    map[string]any{"type": "string"},
		"bravo":   map[string]any{"type": "string"},
		"yankee":  map[string]any{"type": "string"},
		"charlie": map[string]any{"type": "string"},
	})
	want := []string{"alpha", "bravo", "charlie", "mike", "yankee", "zulu"}

	for i := 0; i < 20; i++ {
		gates := &scriptedGates{}
		e, _ := elicitorFor(t, ScopeSession, gates)
		if _, err := e.Elicit(context.Background(), client.ElicitRequest{
			Binding: "github", Mode: client.ElicitModeForm, Message: "m", Schema: schema,
		}); err != nil {
			t.Fatalf("Elicit() error = %v", err)
		}
		opened := gates.opened()
		if len(opened) != 1 {
			t.Fatalf("opened %d gates, want 1", len(opened))
		}
		payload := opened[0].Payload.(gate.FormPayload)
		var got []string
		for _, f := range payload.Schema.Fields {
			got = append(got, f.Name)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("field order = %v, want %v", got, want)
		}
	}
}

// TestFormDeclinesUnsupportedSchemas covers design §Elicitation's "Unsupported or
// unsafe schema constructs are declined with a classified error". Every case is a
// schema this host will not render, and every one must decline rather than crash
// or guess.
func TestFormDeclinesUnsupportedSchemas(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		schema json.RawMessage
	}{
		{"not JSON", json.RawMessage(`{not json`)},
		{"not an object", json.RawMessage(`{"type":"array"}`)},
		{"no properties", json.RawMessage(`{"type":"object","properties":{}}`)},
		{"nested object", json.RawMessage(`{"type":"object","properties":{"a":{"type":"object"}}}`)},
		{"array property", json.RawMessage(`{"type":"object","properties":{"a":{"type":"array"}}}`)},
		{"null property", json.RawMessage(`{"type":"object","properties":{"a":{"type":"null"}}}`)},
		{"typeless property", json.RawMessage(`{"type":"object","properties":{"a":{"title":"A"}}}`)},
		{"empty enum member", json.RawMessage(`{"type":"object","properties":{"a":{"type":"string","enum":["",""]}}}`)},
		{"boolean with enum", json.RawMessage(`{"type":"object","properties":{"a":{"type":"boolean","enum":[true]}}}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{}
			e, reporter := elicitorFor(t, ScopeSession, gates)
			res, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github", Mode: client.ElicitModeForm, Message: "m", Schema: tt.schema,
			})
			if err != nil {
				t.Fatalf("Elicit() error = %v; an unsupported schema is a decline, not an error", err)
			}
			if res.Action != client.ElicitDecline {
				t.Errorf("Action = %v, want decline", res.Action)
			}
			if len(gates.opened()) != 0 {
				t.Error("a gate was opened for a schema this host cannot render")
			}
			if !reporter.sawKind(NoticeElicitationDeclined) {
				t.Error("no Notice explained the decline")
			}
		})
	}
}

// TestFormDeclinesOverLongMessage pins the prompt bound. A server picks the
// message, so it needs a ceiling that is this adapter's and not the server's.
func TestFormDeclinesOverLongMessage(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{}
	e, _ := elicitorFor(t, ScopeSession, gates)
	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github",
		Mode:    client.ElicitModeForm,
		Message: strings.Repeat("m", maxElicitMessageBytes+1),
		Schema:  formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action != client.ElicitDecline {
		t.Errorf("Action = %v, want decline", res.Action)
	}
	if len(gates.opened()) != 0 {
		t.Error("a gate was opened for an over-long prompt")
	}
}

// TestFormDeclinesTooManyFields proves the adapter defers to Harness's own form
// contract rather than re-deriving it. gate.ValidateFormSchema caps a form at 32
// fields; this adapter must not open a gate the gate package would refuse.
func TestFormDeclinesTooManyFields(t *testing.T) {
	t.Parallel()
	props := map[string]any{}
	for i := 0; i < 40; i++ {
		props[fmt.Sprintf("field_%02d", i)] = map[string]any{"type": "string"}
	}
	gates := &scriptedGates{}
	e, _ := elicitorFor(t, ScopeSession, gates)
	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github", Mode: client.ElicitModeForm, Message: "m", Schema: formSchema(t, props),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action != client.ElicitDecline {
		t.Errorf("Action = %v, want decline", res.Action)
	}
	if len(gates.opened()) != 0 {
		t.Error("a gate was opened for a form the gate package would refuse")
	}
}

// TestFormRejectsUnknownAnswerField proves the answer is validated against the
// schema on the way back. A host that answers a question that was not asked has
// answered a different form, and forwarding the rest would send the server a
// partial answer it would read as complete.
func TestFormRejectsUnknownAnswerField(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{
		answer: func(GateRequest) (GateResponse, error) {
			return GateResponse{Action: gate.FormActionAccept, Values: map[string]string{
				"repo":     "looprig/mcp",
				"smuggled": "value",
			}}, nil
		},
	}
	e, _ := elicitorFor(t, ScopeSession, gates)
	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github", Mode: client.ElicitModeForm, Message: "m",
		Schema: formSchema(t, map[string]any{"repo": map[string]any{"type": "string"}}),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action != client.ElicitDecline {
		t.Errorf("Action = %v, want decline for an answer naming an undeclared field", res.Action)
	}
	if res.Content != nil {
		t.Errorf("Content = %s, want nil", res.Content)
	}
}

// TestFormRejectsMistypedAnswer proves the re-typing fails closed. A host that
// answers an integer field with "abc" must not have it coerced or forwarded.
func TestFormRejectsMistypedAnswer(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ jsonType, value string }{
		{"integer", "abc"},
		{"number", "abc"},
		{"boolean", "yes"},
	} {
		t.Run(tt.jsonType, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{
				answer: func(GateRequest) (GateResponse, error) {
					return GateResponse{Action: gate.FormActionAccept, Values: map[string]string{"a": tt.value}}, nil
				},
			}
			e, _ := elicitorFor(t, ScopeSession, gates)
			res, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github", Mode: client.ElicitModeForm, Message: "m",
				Schema: formSchema(t, map[string]any{"a": map[string]any{"type": tt.jsonType}}),
			})
			if err != nil {
				t.Fatalf("Elicit() error = %v", err)
			}
			if res.Action != client.ElicitDecline {
				t.Errorf("Action = %v, want decline for %q as a %s", res.Action, tt.value, tt.jsonType)
			}
		})
	}
}

// TestFormActionsMap covers the three ways a gate comes back, plus an action
// nobody offered.
func TestFormActionsMap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		action string
		want   client.ElicitAction
	}{
		{gate.FormActionAccept, client.ElicitAccept},
		{gate.FormActionDecline, client.ElicitDecline},
		{gate.FormActionCancel, client.ElicitCancel},
		// A host that answered with something nobody offered. Fail closed: an
		// unrecognized action is not an accept.
		{"approve", client.ElicitCancel},
		{"", client.ElicitCancel},
	}
	for _, tt := range tests {
		t.Run("action="+tt.action, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{
				answer: func(GateRequest) (GateResponse, error) {
					return GateResponse{Action: tt.action, Values: map[string]string{"a": "x"}}, nil
				},
			}
			e, _ := elicitorFor(t, ScopeSession, gates)
			res, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github", Mode: client.ElicitModeForm, Message: "m",
				Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
			})
			if err != nil {
				t.Fatalf("Elicit() error = %v", err)
			}
			if res.Action != tt.want {
				t.Errorf("Action = %v, want %v", res.Action, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// URL elicitation
// ---------------------------------------------------------------------------

// secretURL carries the things an authorization URL really carries: a state
// token and a PKCE challenge. None of it may reach a durable record.
const secretURL = "https://idp.example.com/authorize?state=CANARY-STATE-SECRET&code_challenge=CANARY-PKCE-SECRET#frag"

// TestURLElicitationKeepsTheURLOutOfDurableRecords is the other security guard.
//
// Design §Elicitation: "the full action URL and query parameters are not written
// to journals or ordinary events". gate.OpenURLPayload makes that structural for
// the payload — its URL field is `json:"-"` and the durable codec type has no URL
// field at all — but the PROMPT is the public envelope that rides
// event.GateOpened into a journal, so a URL rendered into Prompt.Body would
// defeat the whole design by the back door. This is that test.
func TestURLElicitationKeepsTheURLOutOfDurableRecords(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{
		answer: func(GateRequest) (GateResponse, error) {
			return GateResponse{Action: gate.FormActionAccept}, nil
		},
	}
	e, reporter := elicitorFor(t, ScopeSession, gates)

	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding:       "github",
		Mode:          client.ElicitModeURL,
		Message:       "authorize this app",
		URL:           secretURL,
		ElicitationID: "elicit-1",
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action != client.ElicitAccept {
		t.Errorf("Action = %v, want accept", res.Action)
	}
	if res.Content != nil {
		t.Errorf("Content = %s, want nil; a URL elicitation carries no answers", res.Content)
	}

	opened := gates.opened()
	if len(opened) != 1 {
		t.Fatalf("opened %d gates, want 1", len(opened))
	}
	req := opened[0]

	if req.Kind != gate.KindOpenURL {
		t.Errorf("Kind = %q, want %q", req.Kind, gate.KindOpenURL)
	}
	// A restorable open-url gate is refused by gate.ValidateGate, because its
	// action target is not journaled and a restored one could only ever present
	// an origin with no URL behind it.
	if req.Restorable {
		t.Error("Restorable = true; an open-url gate can never be restored")
	}
	if err := gate.ValidateGate(gate.Gate{Kind: req.Kind, Restorable: req.Restorable}); err != nil {
		t.Errorf("the gate this adapter builds is one ValidateGate refuses: %v", err)
	}

	payload, ok := req.Payload.(gate.OpenURLPayload)
	if !ok {
		t.Fatalf("Payload is %T, want gate.OpenURLPayload", req.Payload)
	}
	// The full URL travels ONLY here.
	if payload.URL != secretURL {
		t.Errorf("Payload.URL = %q, want the full action target", payload.URL)
	}
	if payload.DisplayOrigin != "https://idp.example.com" {
		t.Errorf("DisplayOrigin = %q, want the bare origin", payload.DisplayOrigin)
	}
	// The server gave an id, so it will send a completion.
	if !payload.RequiresCompletion {
		t.Error("RequiresCompletion = false, but the server supplied an elicitation id")
	}

	// Now the canary sweep: the secrets must appear NOWHERE but Payload.URL.
	for _, secret := range []string{"CANARY-STATE-SECRET", "CANARY-PKCE-SECRET"} {
		if strings.Contains(req.Prompt.Title, secret) {
			t.Errorf("Prompt.Title carries %s", secret)
		}
		if strings.Contains(req.Prompt.Body, secret) {
			t.Errorf("Prompt.Body carries %s: %q", secret, req.Prompt.Body)
		}
		if strings.Contains(payload.DisplayOrigin, secret) {
			t.Errorf("DisplayOrigin carries %s", secret)
		}
		for _, n := range reporter.snapshot() {
			if strings.Contains(n.Message, secret) {
				t.Errorf("a Notice carries %s: %q", secret, n.Message)
			}
		}
	}

	// And the payload, once through the codec that a journal uses, must have
	// lost the URL entirely.
	encoded, err := gate.MarshalPayload(payload)
	if err != nil {
		t.Fatalf("MarshalPayload() error = %v", err)
	}
	for _, secret := range []string{"CANARY-STATE-SECRET", "CANARY-PKCE-SECRET", "authorize?"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("the DURABLE payload carries %s: %s", secret, encoded)
		}
	}
}

// TestURLElicitationRequiresCompletionTracksTheID pins the mapping. Claiming
// RequiresCompletion without an id would park a human on a signal that can never
// arrive: MCP correlates elicitation/complete by the elicitationId, so a server
// that sent none has no way to send one.
func TestURLElicitationRequiresCompletionTracksTheID(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		id   string
		want bool
	}{
		{"with an id the server will complete", "elicit-1", true},
		{"without an id it cannot", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{}
			e, _ := elicitorFor(t, ScopeSession, gates)
			if _, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github", Mode: client.ElicitModeURL,
				Message: "go here", URL: "https://example.com/x", ElicitationID: tt.id,
			}); err != nil {
				t.Fatalf("Elicit() error = %v", err)
			}
			payload := gates.opened()[0].Payload.(gate.OpenURLPayload)
			if payload.RequiresCompletion != tt.want {
				t.Errorf("RequiresCompletion = %v, want %v", payload.RequiresCompletion, tt.want)
			}
		})
	}
}

// TestURLElicitationRejectsUnsafeURLs is the scheme boundary. A server picks this
// URL and a host is being asked to hand it to a browser: "javascript:" and
// "data:" are code, and "file:" is a local read. None of them is a link.
func TestURLElicitationRejectsUnsafeURLs(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, url string }{
		{"javascript", "javascript:alert(document.cookie)"},
		{"data", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="},
		{"file", "file:///etc/passwd"},
		{"ftp", "ftp://example.com/x"},
		{"no scheme", "example.com/x"},
		{"no host", "https:///path"},
		{"empty", ""},
		{"unparseable", "https://exa mple.com/\x7f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{}
			e, reporter := elicitorFor(t, ScopeSession, gates)
			res, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github", Mode: client.ElicitModeURL, Message: "go here", URL: tt.url,
			})
			if err != nil {
				t.Fatalf("Elicit() error = %v", err)
			}
			if res.Action != client.ElicitDecline {
				t.Errorf("Action = %v, want decline for %q", res.Action, tt.url)
			}
			if len(gates.opened()) != 0 {
				t.Errorf("a gate was opened for %q", tt.url)
			}
			if !reporter.sawKind(NoticeElicitationDeclined) {
				t.Error("no Notice explained the decline")
			}
		})
	}
}

// TestBareOrigin pins the origin reduction directly, including the userinfo case
// that gate.OpenURLPayload would reject anyway.
func TestBareOrigin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "https://example.com/a/b?c=d#e", want: "https://example.com"},
		{in: "http://example.com:8080/x", want: "http://example.com:8080"},
		{in: "https://user:pw@example.com/x", want: "https://example.com"},
		{in: "https://example.com", want: "https://example.com"},
		{in: "javascript:alert(1)", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := bareOrigin(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("bareOrigin(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Errorf("bareOrigin(%q) = %q, want %q", tt.in, got, tt.want)
			}
			// Whatever it returns must satisfy the payload codec's own bare-origin
			// check, or the gate could not be journaled.
			if _, err := gate.MarshalPayload(gate.OpenURLPayload{DisplayOrigin: got}); err != nil {
				t.Errorf("the origin this adapter derives is one the payload codec refuses: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Lifecycle: modes, deadlines, cancellation, shutdown, bounds
// ---------------------------------------------------------------------------

// TestUnknownModeIsDeclined fails closed on a mode this adapter does not serve.
// The modes differ in what they DO with the answer, so rendering an unknown one
// as a form would be this host inventing a meaning for a server's request.
func TestUnknownModeIsDeclined(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{}
	e, _ := elicitorFor(t, ScopeSession, gates)
	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github", Mode: client.ElicitMode(99), Message: "m",
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action != client.ElicitDecline {
		t.Errorf("Action = %v, want decline", res.Action)
	}
	if len(gates.opened()) != 0 {
		t.Error("a gate was opened for an unknown mode")
	}
}

// TestElicitationHonorsRequestCancellation covers design §Elicitation's "the
// originating MCP request remains cancellable".
func TestElicitationHonorsRequestCancellation(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{block: make(chan struct{})}
	e, _ := elicitorFor(t, ScopeSession, gates)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan client.ElicitResult, 1)
	go func() {
		res, err := e.Elicit(ctx, client.ElicitRequest{
			Binding: "github", Mode: client.ElicitModeForm, Message: "m",
			Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
		})
		if err != nil {
			t.Errorf("Elicit() error = %v", err)
		}
		done <- res
	}()

	waitFor(t, "the gate to open", func() bool { return len(gates.opened()) == 1 })
	cancel()

	select {
	case res := <-done:
		if res.Action != client.ElicitCancel {
			t.Errorf("Action = %v, want cancel", res.Action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled request did not resolve; the elicitation ignored its context")
	}
}

// TestShutdownResolvesPendingElicitationAsCancelled covers design §Elicitation's
// "shutdown or interrupt resolves the request as cancelled".
//
// It is a distinct fact from request cancellation: the MCP request's context is
// still perfectly alive here. What ends the wait is the MANAGER closing, which
// reaches the elicitation only through the context.AfterFunc joining m.ctx to the
// gate call. Delete that join and this test is the one that notices.
func TestShutdownResolvesPendingElicitationAsCancelled(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{block: make(chan struct{})}
	reporter := &recordingReporter{}
	deps := testDeps()
	deps.Gates = gates
	deps.Reporter = reporter
	deps.Events = &capturingEvents{}
	m, err := NewManager([]Binding{scriptedBinding("github", ScopeSession, okTransport("github"))}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	e := &elicitor{m: m, bs: m.states["github"]}

	done := make(chan client.ElicitResult, 1)
	go func() {
		// context.Background: the MCP request is NOT cancelled. Only the
		// Manager's shutdown can end this.
		res, err := e.Elicit(context.Background(), client.ElicitRequest{
			Binding: "github", Mode: client.ElicitModeForm, Message: "m",
			Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
		})
		if err != nil {
			t.Errorf("Elicit() error = %v", err)
		}
		done <- res
	}()

	waitFor(t, "the gate to open", func() bool { return len(gates.opened()) == 1 })
	_ = m.Close(context.Background())

	select {
	case res := <-done:
		if res.Action != client.ElicitCancel {
			t.Errorf("Action = %v, want cancel", res.Action)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not resolve a pending elicitation; a Close would wait for a human forever")
	}
}

// TestElicitationHonorsWallClockDeadline covers design §Elicitation's "an overall
// wall-clock deadline remains".
//
// A binding's request timeout bounds how long a SERVER may take to answer us;
// this bounds how long a server may keep a question in front of a person.
// Without it a server parks a gate forever simply by never withdrawing it.
func TestElicitationHonorsWallClockDeadline(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{block: make(chan struct{})} // never closed
	e, _ := elicitorFor(t, ScopeSession, gates)
	e.m.elicitIn = 20 * time.Millisecond

	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github", Mode: client.ElicitModeForm, Message: "m",
		Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action != client.ElicitCancel {
		t.Errorf("Action = %v, want cancel", res.Action)
	}
}

// lateGates ignores its context and answers after the deadline has passed. It is
// a host that does not honor GateOpener's contract — which this adapter does not
// get to assume it does.
type lateGates struct {
	delay time.Duration
}

func (g lateGates) OpenGate(context.Context, GateRequest) (GateResponse, error) {
	time.Sleep(g.delay)
	return GateResponse{Action: gate.FormActionAccept, Values: map[string]string{"a": "smuggled"}}, nil
}

// TestLateResponseIsRejected covers design §Elicitation's "late or duplicate
// responses are rejected".
//
// The gate opener here IGNORES its context and answers "accept" long after the
// wall-clock deadline. That answer is to a question that was already withdrawn,
// and adopting it would let a slow host commit a human's answer after the server
// stopped waiting for it. The re-check of callCtx.Err() after OpenGate returns is
// the only thing standing between this and an accept.
func TestLateResponseIsRejected(t *testing.T) {
	t.Parallel()
	reporter := &recordingReporter{}
	deps := testDeps()
	deps.Gates = lateGates{delay: 60 * time.Millisecond}
	deps.Reporter = reporter
	deps.Events = &capturingEvents{}
	m, err := NewManager([]Binding{scriptedBinding("github", ScopeSession, okTransport("github"))}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	m.elicitIn = 10 * time.Millisecond
	e := &elicitor{m: m, bs: m.states["github"]}

	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github", Mode: client.ElicitModeForm, Message: "m",
		Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action == client.ElicitAccept {
		t.Fatal("a late answer was accepted; the response arrived after the request was withdrawn")
	}
	if res.Action != client.ElicitCancel {
		t.Errorf("Action = %v, want cancel", res.Action)
	}
	if res.Content != nil {
		t.Errorf("Content = %s, want nil; a late answer's values must not reach the server", res.Content)
	}
}

// erroringGates fails to open.
type erroringGates struct{}

func (erroringGates) OpenGate(context.Context, GateRequest) (GateResponse, error) {
	return GateResponse{}, errors.New("no renderer is attached")
}

// TestGateOpenFailureIsCancelled proves a host that cannot ask resolves the
// server's request rather than hanging it or failing the connection.
func TestGateOpenFailureIsCancelled(t *testing.T) {
	t.Parallel()
	reporter := &recordingReporter{}
	deps := testDeps()
	deps.Gates = erroringGates{}
	deps.Reporter = reporter
	deps.Events = &capturingEvents{}
	m, err := NewManager([]Binding{scriptedBinding("github", ScopeSession, okTransport("github"))}, deps)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	e := &elicitor{m: m, bs: m.states["github"]}

	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github", Mode: client.ElicitModeForm, Message: "m",
		Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v; a gate that will not open is a cancel, not an error", err)
	}
	if res.Action != client.ElicitCancel {
		t.Errorf("Action = %v, want cancel", res.Action)
	}
	if !reporter.sawKind(NoticeElicitationDeclined) {
		t.Error("no Notice explained the failure")
	}
}

// TestPendingElicitationsAreBounded proves a server cannot exhaust the host's
// attention. Elicitation is the one server-initiated request that consumes a
// scarce resource on this side, and the server picks how many to open.
func TestPendingElicitationsAreBounded(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	gates := &scriptedGates{block: release}
	e, _ := elicitorFor(t, ScopeSession, gates)

	// Fill every slot with an elicitation that will not answer.
	var wg sync.WaitGroup
	for i := 0; i < maxPendingElicitations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github", Mode: client.ElicitModeForm, Message: "m",
				Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
			})
		}()
	}
	waitFor(t, "every slot to fill", func() bool { return len(gates.opened()) == maxPendingElicitations })

	// The next one must be refused without ever reaching a gate.
	res, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github", Mode: client.ElicitModeForm, Message: "m",
		Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action != client.ElicitDecline {
		t.Errorf("Action = %v, want decline past the bound", res.Action)
	}
	if got := len(gates.opened()); got != maxPendingElicitations {
		t.Errorf("opened %d gates, want %d; the one past the bound reached a gate", got, maxPendingElicitations)
	}

	close(release)
	wg.Wait()

	// And the slots must be released, or a binding would be poisoned for the
	// life of the Session by a burst it already survived.
	res, err = e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github", Mode: client.ElicitModeForm, Message: "m",
		Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
	})
	if err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if res.Action == client.ElicitDecline && len(gates.opened()) == maxPendingElicitations {
		t.Error("a slot was not released after its elicitation finished")
	}
}

// TestGateRequestCarriesOwner covers design §Elicitation's "responses are
// correlated to binding, MCP request, Harness gate, and owner".
//
// Binding and owner are what the adapter contributes: the MCP request and the
// gate are correlated structurally, since OpenGate is synchronous and its return
// IS this request's answer. A Session-scoped binding's LoopID is deliberately
// zero — a shared server's elicitation belongs to the Session, not to whichever
// Loop happened to be first.
func TestGateRequestCarriesOwner(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		scope Scope
		want  [16]byte
	}{
		{"loop-scoped names its owner", ScopeLoop, loopA},
		{"session-scoped has no loop owner", ScopeSession, [16]byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gates := &scriptedGates{}
			e, _ := elicitorFor(t, tt.scope, gates)
			if _, err := e.Elicit(context.Background(), client.ElicitRequest{
				Binding: "github", Mode: client.ElicitModeForm, Message: "m",
				Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
			}); err != nil {
				t.Fatalf("Elicit() error = %v", err)
			}
			opened := gates.opened()
			if len(opened) != 1 {
				t.Fatalf("opened %d gates, want 1", len(opened))
			}
			if opened[0].Binding != "github" {
				t.Errorf("Binding = %q, want github", opened[0].Binding)
			}
			if opened[0].LoopID != tt.want {
				t.Errorf("LoopID = %v, want %v", opened[0].LoopID, tt.want)
			}
		})
	}
}

// TestFormGateIsNotRestorable covers design §Elicitation's "Restore does not
// attempt to resume a stale server request from journal data".
//
// gate.ValidateGate only forbids a RESTORABLE open-url gate, so a form gate could
// legally be marked restorable — which makes this the adapter's own rule and not
// one the gate package will catch. A restorable form gate would outlive the
// connection its answer has to be delivered on, leaving a person answering a
// question no server is still listening for.
func TestFormGateIsNotRestorable(t *testing.T) {
	t.Parallel()
	gates := &scriptedGates{}
	e, _ := elicitorFor(t, ScopeSession, gates)
	if _, err := e.Elicit(context.Background(), client.ElicitRequest{
		Binding: "github", Mode: client.ElicitModeForm, Message: "m",
		Schema: formSchema(t, map[string]any{"a": map[string]any{"type": "string"}}),
	}); err != nil {
		t.Fatalf("Elicit() error = %v", err)
	}
	if gates.opened()[0].Restorable {
		t.Error("Restorable = true; a pending elicitation is tied to a live connection")
	}
}
