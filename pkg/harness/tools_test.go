package mcpharness

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/core/content"
	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/tool"
	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/client"
)

// sessionID is the Session every built tool belongs to. Build requires
// coordinates whatever a definition's Requirements are.
var sessionID = uuid.MustParse("55555555-5555-4555-8555-555555555555")

// recordingReporter collects the adapter's notices.
type recordingReporter struct {
	mu      sync.Mutex
	notices []Notice
}

func (r *recordingReporter) Report(n Notice) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notices = append(r.notices, n)
}

func (r *recordingReporter) snapshot() []Notice {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Notice(nil), r.notices...)
}

// waitFor polls until cond holds. A refresh is asynchronous by design — the
// notification returns before the fetch starts — so a test either polls or races.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// notify delivers a list-change notification the way a real one arrives:
// through the callback the client installed on the ConnectConfig it handed the
// transport. Nothing here reaches into the client.
func notify(t *testing.T, tr *scriptedTransport) {
	t.Helper()
	cb := tr.lastConfig().OnListChanged
	if cb == nil {
		t.Fatal("the client installed no OnListChanged callback: no notification can reach it")
	}
	cb(protocol.ListChange{Family: protocol.ListFamilyTools})
}

// managerWith builds and starts a Manager with explicit deps, and closes it on
// cleanup. It is startedManager's sibling for the tests that need to observe a
// Reporter or a ScopePolicy.
func managerWith(t *testing.T, deps Deps, bindings ...Binding) *Manager {
	t.Helper()
	// Required, like startedManager's: Start's return then means every binding
	// has settled, so a test asserting on a catalog is not racing discovery.
	required := make([]Binding, 0, len(bindings))
	for _, b := range bindings {
		required = append(required, requiredBinding(b))
	}
	m, err := NewManager(required, deps)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Close(ctx)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return m
}

// baseBindings is the minimal valid tool.Bindings: the coordinates every Build
// requires, and no capability at all. Building an MCP definition against it is
// the proof that an MCP tool needs nothing of the Loop it is installed on.
func baseBindings() tool.Bindings {
	return tool.Bindings{SessionID: sessionID, LoopID: loopA}
}

// buildOne builds the single tool of a single definition.
func buildOne(t *testing.T, defs []tool.Definition, modelName string) tool.InvokableTool {
	t.Helper()
	for _, def := range defs {
		tools, err := def.Build(context.Background(), baseBindings())
		if err != nil {
			t.Fatalf("Build(%s): %v", def.Name(), err)
		}
		for _, it := range tools {
			info, err := it.Info(context.Background())
			if err != nil {
				t.Fatalf("Info: %v", err)
			}
			if info.Name == modelName {
				return it
			}
		}
	}
	t.Fatalf("no tool named %q among %d definitions", modelName, len(defs))
	return nil
}

// modelNames returns every model-facing name the definitions produce.
func modelNames(defs []tool.Definition) []string {
	var out []string
	for _, def := range defs {
		out = append(out, def.ProducedToolNames()...)
	}
	return out
}

func run(t *testing.T, it tool.InvokableTool, args string) *tool.ToolResult {
	t.Helper()
	res, err := it.InvokableRun(context.Background(), args)
	if err != nil {
		t.Fatalf("InvokableRun returned a Go error (%v); an MCP tool's failures are tool results", err)
	}
	if res == nil {
		t.Fatal("InvokableRun returned a nil result")
	}
	return res
}

// resultText concatenates the text of every text block in a result.
func resultText(res *tool.ToolResult) string {
	var b strings.Builder
	for _, block := range res.Content {
		if text, ok := block.(*content.TextBlock); ok {
			b.WriteString(text.Text)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// TestSessionToolsAdaptsTheAdoptedCatalog is the base claim: the tools a Loop
// sees are the adopted catalog's, under the catalog's own model-facing names,
// and only from bindings its Visibility permits.
func TestSessionToolsAdaptsTheAdoptedCatalog(t *testing.T) {
	t.Parallel()

	loop := loopA
	shared := okTransport("github", "search_issues")
	private := &scriptedTransport{conn: newScriptedConn("secrets", fakeTool("read"))}

	m := managerWith(t, testDeps(),
		Binding{
			Name:       "github",
			Scope:      ScopeSession,
			Server:     client.Definition{Name: "github", Transport: shared},
			Visibility: Loops(loop),
		},
		Binding{
			Name:   "secrets",
			Scope:  ScopeLoop,
			Loop:   loop,
			Server: client.Definition{Name: "secrets", Transport: private},
		},
	)

	got := modelNames(m.SessionTools(loop, "primary"))
	if len(got) != 1 || got[0] != "mcp__github__search_issues" {
		t.Fatalf("SessionTools names = %v, want [mcp__github__search_issues]", got)
	}
	if owned := modelNames(m.LoopTools(loop)); len(owned) != 1 || owned[0] != "mcp__secrets__read" {
		t.Fatalf("LoopTools names = %v, want [mcp__secrets__read]", owned)
	}

	// A Loop the selector does not name sees nothing shared, and never sees
	// another Loop's private binding (design §Delegation).
	other := loopB
	if names := modelNames(m.SessionTools(other, "delegate")); len(names) != 0 {
		t.Errorf("SessionTools for an unpermitted Loop = %v, want none", names)
	}
	if names := modelNames(m.LoopTools(other)); len(names) != 0 {
		t.Errorf("LoopTools for a non-owner = %v, want none", names)
	}
}

// TestToolInfoCarriesTheGenerationSchema checks that the schema the model is
// shown is the adopted catalog's, not something re-derived.
func TestToolInfoCarriesTheGenerationSchema(t *testing.T) {
	t.Parallel()

	tr := &scriptedTransport{conn: newScriptedConn("srv")}
	tr.conn.tools = []protocol.ToolSpec{{
		RawName:     "search",
		Description: "search things",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
	}}
	m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, tr))

	loop := loopA
	it := buildOne(t, m.SessionTools(loop, "primary"), "mcp__srv__search")
	info, err := it.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Desc != "search things" {
		t.Errorf("Desc = %q, want the server's description", info.Desc)
	}
	if !strings.Contains(string(info.Schema), `"q"`) {
		t.Errorf("Schema = %s, want the catalog's input schema", info.Schema)
	}
}

// TestCollidingModelNameDegradesTheOffendingBinding is the union rule.
//
// The two bindings are individually valid and their catalogs individually
// unique — neither can see the other. Their qualified names collide only
// because "__" framing is ambiguous when a binding name contains an underscore:
//
//	binding "a",    raw tool "b__c" -> mcp__a__b__c
//	binding "a__b", raw tool "c"    -> mcp__a__b__c
//
// The incumbent (first in name order) keeps serving; the offender contributes
// nothing at all — not even its non-colliding tool — and is reported.
func TestCollidingModelNameDegradesTheOffendingBinding(t *testing.T) {
	t.Parallel()

	incumbent := okTransport("a", "b__c")
	offender := okTransport("a__b", "c", "unrelated")
	reporter := &recordingReporter{}
	deps := testDeps()
	deps.Reporter = reporter

	m := managerWith(t, deps,
		scriptedBinding("a", ScopeSession, incumbent),
		scriptedBinding("a__b", ScopeSession, offender),
	)

	loop := loopA
	got := modelNames(m.SessionTools(loop, "primary"))
	if len(got) != 1 || got[0] != "mcp__a__b__c" {
		t.Fatalf("names = %v, want only the incumbent's [mcp__a__b__c]", got)
	}

	// The whole offending binding is out, including the tool that collided with
	// nothing: a half-installed binding advertises an authority it cannot serve.
	for _, name := range got {
		if name == "mcp__a__b__unrelated" {
			t.Error("the offending binding still contributed a tool")
		}
	}

	notices := reporter.snapshot()
	if len(notices) != 1 {
		t.Fatalf("notices = %+v, want exactly one collision notice", notices)
	}
	if notices[0].Kind != NoticeToolNameCollision || notices[0].Binding != "a__b" || notices[0].LoopID != loop {
		t.Errorf("notice = %+v, want a collision notice naming binding a__b and the Loop", notices[0])
	}

	// The incumbent's tool routes to the incumbent's server, under its own raw
	// name — the contested display name resolves to exactly one tool.
	it := buildOne(t, m.SessionTools(loop, "primary"), "mcp__a__b__c")
	run(t, it, `{}`)
	if raw, _ := incumbent.conn.lastCall(); raw != "b__c" {
		t.Errorf("incumbent saw raw name %q, want b__c", raw)
	}
	if offender.conn.calls.Load() != 0 {
		t.Error("the offending binding's server was called")
	}
}

// TestCallRoutesByCarriedIdentityNotByName is the anti-reparse property.
//
// Both bindings offer a raw tool whose name, once qualified, is ambiguous under
// the "__" framing. If the call path recovered the binding by parsing the model
// name it would have to guess, and a guess sends one server's arguments to
// another server. Here the two servers are distinguishable, so a misroute is
// visible.
func TestCallRoutesByCarriedIdentityNotByName(t *testing.T) {
	t.Parallel()

	alpha := okTransport("alpha", "read_file")
	beta := okTransport("beta", "read_file")
	m := managerWith(t, testDeps(),
		scriptedBinding("alpha", ScopeSession, alpha),
		scriptedBinding("beta", ScopeSession, beta),
	)

	loop := loopA
	defs := m.SessionTools(loop, "primary")
	run(t, buildOne(t, defs, "mcp__beta__read_file"), `{"path":"x"}`)

	if beta.conn.calls.Load() != 1 {
		t.Errorf("beta calls = %d, want 1", beta.conn.calls.Load())
	}
	if alpha.conn.calls.Load() != 0 {
		t.Errorf("alpha calls = %d, want 0: the call went to the wrong binding", alpha.conn.calls.Load())
	}
	raw, args := beta.conn.lastCall()
	if raw != "read_file" {
		t.Errorf("raw name on the wire = %q, want the server's own name read_file", raw)
	}
	if args != `{"path":"x"}` {
		t.Errorf("args on the wire = %s, want them verbatim", args)
	}
}

// TestCallRefusesARetiringRoute checks that a call goes through the route
// reference seam. A retiring binding is out of future generations: a turn that
// already holds its route keeps it, but a call that has not started must not
// begin on a route on its way out.
func TestCallRefusesARetiringRoute(t *testing.T) {
	t.Parallel()

	tr := okTransport("srv", "do")
	m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, tr))
	loop := loopA
	it := buildOne(t, m.SessionTools(loop, "primary"), "mcp__srv__do")

	m.mu.Lock()
	state := m.states["srv"]
	m.mu.Unlock()
	<-state.markRetiring()

	res := run(t, it, `{}`)
	if !strings.Contains(resultText(res), "no longer serving") {
		t.Errorf("result = %q, want a structured refusal naming the retired route", resultText(res))
	}
	if tr.conn.calls.Load() != 0 {
		t.Error("the call reached a retiring route")
	}
}

// TestCallReleasesItsRoute is the other half of the seam: a finished call must
// drop its reference, or a retirement waits for a turn that is already over and
// the connection never closes.
func TestCallReleasesItsRoute(t *testing.T) {
	t.Parallel()

	tr := okTransport("srv", "do")
	m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, tr))
	loop := loopA
	it := buildOne(t, m.SessionTools(loop, "primary"), "mcp__srv__do")
	run(t, it, `{}`)

	m.mu.Lock()
	state := m.states["srv"]
	m.mu.Unlock()
	select {
	case <-state.markRetiring():
	case <-time.After(2 * time.Second):
		t.Fatal("retirement never became idle: a finished call still holds its route reference")
	}
}

// TestRemovedToolReturnsStructuredUnavailable is design §Calling a tool step 4.
//
// A candidate proves the tool gone. The tool a live turn holds was cut from the
// old generation; it must fail as itself rather than be re-pointed at whatever
// now answers, and the server must not be called at all. The Session and the
// Loop stay healthy: no Go error, and the binding keeps serving its other tools.
func TestRemovedToolReturnsStructuredUnavailable(t *testing.T) {
	t.Parallel()

	tr := &scriptedTransport{conn: newScriptedConn("srv", fakeTool("gone"), fakeTool("stays"))}
	m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, tr))
	loop := loopA
	defs := m.SessionTools(loop, "primary")
	removed := buildOne(t, defs, "mcp__srv__gone")
	kept := buildOne(t, defs, "mcp__srv__stays")

	m.mu.Lock()
	cl := m.states["srv"].client()
	m.mu.Unlock()

	tr.conn.setTools(fakeTool("stays"))
	notify(t, tr)
	waitFor(t, "a candidate without the removed tool", func() bool {
		cand, ok := cl.Candidate()
		if !ok {
			return false
		}
		_, still := cand.ToolByRawName("gone")
		return !still
	})

	before := tr.conn.calls.Load()
	res := run(t, removed, `{}`)
	if !strings.Contains(resultText(res), "ToolUnavailable") {
		t.Errorf("result = %q, want a structured ToolUnavailable", resultText(res))
	}
	if tr.conn.calls.Load() != before {
		t.Error("a tool a newer candidate proved removed was still invoked on the server")
	}

	// Healthy: the binding's surviving tool still works, and the binding is not
	// failed.
	run(t, kept, `{}`)
	if tr.conn.calls.Load() != before+1 {
		t.Error("the binding's surviving tool did not reach the server")
	}
	if st := m.Status(); st[0].Client.Failure != nil {
		t.Errorf("binding failure = %+v, want none: a removed tool is not a binding fault", st[0].Client.Failure)
	}
}

// TestSchemaChangeReturnsStructuredSchemaChanged is the design's rule that an
// old schema is never silently applied to a new tool definition: the raw name
// survived, the contract did not, and the arguments Harness validated describe
// a tool that no longer exists.
func TestSchemaChangeReturnsStructuredSchemaChanged(t *testing.T) {
	t.Parallel()

	tr := &scriptedTransport{conn: newScriptedConn("srv")}
	tr.conn.tools = []protocol.ToolSpec{{
		RawName:     "search",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
	}}
	m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, tr))
	loop := loopA
	it := buildOne(t, m.SessionTools(loop, "primary"), "mcp__srv__search")

	m.mu.Lock()
	cl := m.states["srv"].client()
	m.mu.Unlock()

	tr.conn.setTools(protocol.ToolSpec{
		RawName:     "search",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"number"}}}`),
	})
	notify(t, tr)
	waitFor(t, "a candidate with the new schema", func() bool {
		cand, ok := cl.Candidate()
		if !ok {
			return false
		}
		spec, found := cand.ToolByRawName("search")
		return found && strings.Contains(string(spec.InputSchema), "query")
	})

	res := run(t, it, `{"q":"x"}`)
	if !strings.Contains(resultText(res), "ToolSchemaChanged") {
		t.Errorf("result = %q, want a structured ToolSchemaChanged", resultText(res))
	}
	if tr.conn.calls.Load() != 0 {
		t.Error("a call from the old generation was made against the new schema")
	}
}

// TestCallFailureClassification covers step 8's mapping, including the two
// classes the client can produce between this adapter's own catalog check and
// the call itself (the check and the call are not atomic: an adoption can land
// in between, and the client's check is the authoritative one).
func TestCallFailureClassification(t *testing.T) {
	t.Parallel()

	at := &adaptedTool{binding: "srv", rawTool: "do", generation: 3}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "the client's own catalog check refuses the tool",
			err:  client.NewError(client.FailureToolUnavailable, "srv", "call_tool", "not in the adopted catalog", nil),
			want: "ToolUnavailable",
		},
		{
			name: "a schema change the client detected",
			err:  client.NewError(client.FailureToolSchemaChanged, "srv", "call_tool", "digest differs", nil),
			want: "ToolSchemaChanged",
		},
		{
			name: "a transport failure is an error result, not a Go error",
			err:  client.NewError(client.FailureTransportClosed, "srv", "call_tool", "the connection is gone", nil),
			want: "transport_closed",
		},
		{
			name: "an unclassified error is reported as indeterminate, never guessed at",
			err:  context.Canceled,
			want: "indeterminate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resultText(at.callFailure(tt.err))
			if !strings.Contains(got, tt.want) {
				t.Errorf("callFailure = %q, want it to name %q", got, tt.want)
			}
			if !strings.HasPrefix(got, errPrefix) {
				t.Errorf("callFailure = %q, want the runner's %q prefix", got, errPrefix)
			}
		})
	}
}

// TestClientErrorMessageIsNotForwarded checks that a *client.Error's text — which
// is server-influenced, however bounded — does not become model-facing content.
// The class is what a model or an operator can act on.
func TestClientErrorMessageIsNotForwarded(t *testing.T) {
	t.Parallel()

	const canary = "s3cret-bearer-token-from-a-server"
	at := &adaptedTool{binding: "srv", rawTool: "do"}
	got := resultText(at.callFailure(client.NewError(client.FailureRemoteHTTP, "srv", "call_tool", canary, nil)))
	if strings.Contains(got, canary) {
		t.Errorf("result = %q, want it not to carry the underlying error's text", got)
	}
}

// TestProtocolToolErrorIsAStructuredResult is design §Calling a tool step 7: a
// tool that ran and failed is information for the model, not a fault. The
// binding stays healthy and its next call still works.
func TestProtocolToolErrorIsAStructuredResult(t *testing.T) {
	t.Parallel()

	tr := okTransport("srv", "do")
	tr.conn.setCall(protocol.ToolResult{
		IsError: true,
		Content: []protocol.Content{protocol.TextContent{Text: "no such file"}},
	}, nil)
	m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, tr))
	loop := loopA
	it := buildOne(t, m.SessionTools(loop, "primary"), "mcp__srv__do")

	res := run(t, it, `{}`)
	text := resultText(res)
	if !strings.HasPrefix(text, errPrefix) {
		t.Errorf("result = %q, want it marked as an error for the model", text)
	}
	if !strings.Contains(text, "no such file") {
		t.Errorf("result = %q, want the tool's own explanation preserved", text)
	}

	// Healthy: the binding is not failed and serves the next call.
	if st := m.Status(); st[0].Client.Failure != nil {
		t.Errorf("binding failure = %+v, want none: a tool error is not a connection fault", st[0].Client.Failure)
	}
	tr.conn.setCall(protocol.ToolResult{Content: []protocol.Content{protocol.TextContent{Text: "ok"}}}, nil)
	if got := resultText(run(t, it, `{}`)); !strings.Contains(got, "ok") {
		t.Errorf("the next call = %q, want it to succeed", got)
	}
}

// TestEmptyResultIsNotAnError guards the boundary between "the server said
// nothing" and "the call failed": an empty ToolResult would be replaced by the
// runner's own empty-result error string, misreporting a successful call.
func TestEmptyResultIsNotAnError(t *testing.T) {
	t.Parallel()

	tr := okTransport("srv", "do")
	m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, tr))
	it := buildOne(t, m.SessionTools(loopA, "primary"), "mcp__srv__do")

	res := run(t, it, `{}`)
	if len(res.Content) == 0 {
		t.Fatal("result has no content: the runner would report it as an error")
	}
	if text := resultText(res); strings.HasPrefix(text, errPrefix) {
		t.Errorf("result = %q, want a successful empty result, not an error", text)
	}
}

// TestPermissionRequestCarriesNoArguments is design §Permissions: no
// credentials, no request bodies, no unbounded arguments in a gate or an audit
// event. The canary is in the arguments, where a real secret would be.
func TestPermissionRequestCarriesNoArguments(t *testing.T) {
	t.Parallel()

	const canary = "ghp_canary_token_do_not_leak"
	args := `{"token":"` + canary + `","body":"the whole request"}`

	tr := okTransport("github", "search_issues")
	m := managerWith(t, testDeps(), scriptedBinding("github", ScopeSession, tr))
	it := buildOne(t, m.SessionTools(loopA, "primary"), "mcp__github__search_issues")

	prompter, ok := it.(tool.PermissionPrompter)
	if !ok {
		t.Fatal("an MCP tool does not implement tool.PermissionPrompter: it would gate as an unknown capability")
	}
	req, err := prompter.BuildRequest(args, nil)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if strings.Contains(req.Description(), canary) {
		t.Errorf("gate description = %q, want it free of the arguments", req.Description())
	}
	if strings.Contains(req.ToolName(), canary) {
		t.Errorf("gate tool name = %q, want it free of the arguments", req.ToolName())
	}
	// The identity an approval persists against names the binding AND the raw
	// tool: a grant on one server must never satisfy a call to another.
	if req.ToolName() != "mcp:github:search_issues" {
		t.Errorf("permission identity = %q, want mcp:github:search_issues", req.ToolName())
	}
	// It must still say enough to decide on.
	if !strings.Contains(req.Description(), "github") || !strings.Contains(req.Description(), "search_issues") {
		t.Errorf("gate description = %q, want it to name the server and the tool", req.Description())
	}

	auditable, ok := it.(tool.Auditable)
	if !ok {
		t.Fatal("an MCP tool does not implement tool.Auditable")
	}
	if strings.Contains(auditable.AuditSummary(args), canary) {
		t.Errorf("audit summary = %q, want it free of the arguments", auditable.AuditSummary(args))
	}
}

// TestPermissionScopesComeFromThePolicy checks the host's ScopePolicy decides
// persistence breadth, and that a policy refusing every scope fails the prompt
// closed rather than offering nothing to grant.
func TestPermissionScopesComeFromThePolicy(t *testing.T) {
	t.Parallel()

	tr := okTransport("srv", "do")
	deps := testDeps()
	deps.ScopePolicy = fixedScopePolicy{scopes: []tool.ApprovalScope{tool.ScopeOnce}}
	m := managerWith(t, deps, scriptedBinding("srv", ScopeSession, tr))
	it := buildOne(t, m.SessionTools(loopA, "primary"), "mcp__srv__do")

	req, err := it.(tool.PermissionPrompter).BuildRequest(`{}`, nil)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if scopes := req.AllowedScopes(); len(scopes) != 1 || scopes[0] != tool.ScopeOnce {
		t.Errorf("scopes = %v, want the policy's [ScopeOnce]", scopes)
	}

	refusing := testDeps()
	refusing.ScopePolicy = fixedScopePolicy{}
	m2 := managerWith(t, refusing, scriptedBinding("srv", ScopeSession, okTransport("srv", "do")))
	it2 := buildOne(t, m2.SessionTools(loopA, "primary"), "mcp__srv__do")
	if _, err := it2.(tool.PermissionPrompter).BuildRequest(`{}`, nil); err == nil {
		t.Error("BuildRequest with no scopes succeeded; a policy that refuses must fail the prompt closed")
	}
}

// TestPermissionIdentityFailsClosedWhenOverLong is the aliasing guard.
//
// tool.NewExternalRequest bounds a tool name to 128 bytes, and a raw MCP tool
// name may be longer than that budget leaves. Truncating would make two tools
// share one identity, so an approval for one would silently authorize the
// other. Refusing costs a call; aliasing costs the boundary.
func TestPermissionIdentityFailsClosedWhenOverLong(t *testing.T) {
	t.Parallel()

	at := &adaptedTool{
		binding:  "srv",
		rawTool:  strings.Repeat("x", 200),
		scopes:   fixedScopePolicy{scopes: defaultScopes},
		identity: permissionIdentity("srv", strings.Repeat("x", 200)),
	}
	req, err := at.BuildRequest(`{}`, nil)
	if err == nil {
		t.Fatalf("BuildRequest = %q, want a refusal: a truncated identity is a shared identity", req.ToolName())
	}
}

// TestArgumentNormalization checks what actually reaches the wire.
func TestArgumentNormalization(t *testing.T) {
	t.Parallel()

	t.Run("no arguments become an empty object", func(t *testing.T) {
		t.Parallel()
		tr := okTransport("srv", "do")
		m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, tr))
		it := buildOne(t, m.SessionTools(loopA, "primary"), "mcp__srv__do")
		run(t, it, "")
		if _, args := tr.conn.lastCall(); args != `{}` {
			t.Errorf("args on the wire = %q, want {}: an empty string is not JSON", args)
		}
	})

	t.Run("arguments that are not JSON are refused, not forwarded", func(t *testing.T) {
		t.Parallel()
		tr := okTransport("srv", "do")
		m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, tr))
		it := buildOne(t, m.SessionTools(loopA, "primary"), "mcp__srv__do")
		res := run(t, it, `{"broken`)
		if !strings.Contains(resultText(res), "not valid JSON") {
			t.Errorf("result = %q, want a refusal", resultText(res))
		}
		if tr.conn.calls.Load() != 0 {
			t.Error("non-JSON arguments were posted to the server")
		}
	})
}

// TestContentConversion is design §Content conversion and limits: every kind
// Harness can carry becomes the matching block, and a kind it cannot becomes a
// labeled placeholder — never a panic, never a silent disappearance.
func TestContentConversion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		in    client.Content
		check func(*testing.T, content.Block)
	}{
		{
			name: "text",
			in:   client.Text{Text: "hello"},
			check: func(t *testing.T, b content.Block) {
				if text, ok := b.(*content.TextBlock); !ok || text.Text != "hello" {
					t.Errorf("block = %#v, want a TextBlock carrying the text", b)
				}
			},
		},
		{
			name: "truncated text says so",
			in:   client.Text{Text: "hello", Truncated: true},
			check: func(t *testing.T, b content.Block) {
				text, ok := b.(*content.TextBlock)
				if !ok || !strings.Contains(text.Text, "truncated") {
					t.Errorf("block = %#v, want the truncation marked", b)
				}
			},
		},
		{
			name: "image",
			in:   client.Image{Data: []byte{1, 2, 3}, MIMEType: "image/png"},
			check: func(t *testing.T, b content.Block) {
				img, ok := b.(*content.ImageBlock)
				if !ok || img.MediaType != "image/png" || len(img.Source.Data) != 3 {
					t.Errorf("block = %#v, want an ImageBlock with the data and media type", b)
				}
			},
		},
		{
			name: "audio",
			in:   client.Audio{Data: []byte{1}, MIMEType: "audio/wav"},
			check: func(t *testing.T, b content.Block) {
				au, ok := b.(*content.AudioBlock)
				if !ok || au.MediaType != "audio/wav" || len(au.Data) != 1 {
					t.Errorf("block = %#v, want an AudioBlock", b)
				}
			},
		},
		{
			name: "embedded resource",
			in:   client.EmbeddedResource{URI: "file:///x", MIMEType: "text/plain", Text: "body"},
			check: func(t *testing.T, b content.Block) {
				doc, ok := b.(*content.DocumentBlock)
				if !ok || doc.Name != "file:///x" || doc.Text != "body" {
					t.Errorf("block = %#v, want a DocumentBlock named by its URI", b)
				}
			},
		},
		{
			name: "unsupported becomes a labeled placeholder",
			in:   client.Unsupported{Kind: client.KindResourceLink, Bytes: 42},
			check: func(t *testing.T, b content.Block) {
				text, ok := b.(*content.TextBlock)
				if !ok || !strings.Contains(text.Text, client.KindResourceLink) || !strings.Contains(text.Text, "42") {
					t.Errorf("block = %#v, want a placeholder naming the kind and its size", b)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			blocks := convertContents([]client.Content{tt.in}, nil)
			if len(blocks) != 1 {
				t.Fatalf("blocks = %d, want 1: nothing may be dropped", len(blocks))
			}
			tt.check(t, blocks[0])
		})
	}

	t.Run("structured content becomes its own bounded text block", func(t *testing.T) {
		t.Parallel()
		blocks := convertContents(nil, json.RawMessage(`{"count":3}`))
		if len(blocks) != 1 {
			t.Fatalf("blocks = %d, want 1", len(blocks))
		}
		text, ok := blocks[0].(*content.TextBlock)
		if !ok || !strings.Contains(text.Text, `{"count":3}`) {
			t.Errorf("block = %#v, want the structured document as text", blocks[0])
		}
	})
}

// TestUnmodeledContentIsAPlaceholderNotAPanic exercises the default case.
//
// client.Content is a sealed union, so a member this adapter does not model
// cannot be declared here — which is precisely why the default case must still
// hold: the next member added to the union arrives as a value this type switch
// has never seen. A nil item is the one such value a test can construct, and it
// takes the same branch. A new kind must become a visible item, not a crash and
// not a silence.
func TestUnmodeledContentIsAPlaceholderNotAPanic(t *testing.T) {
	t.Parallel()

	blocks := convertContents([]client.Content{nil}, nil)
	if len(blocks) != 1 {
		t.Fatalf("blocks = %d, want 1: an unmodeled kind must not disappear", len(blocks))
	}
	text, ok := blocks[0].(*content.TextBlock)
	if !ok || !strings.Contains(text.Text, "unrecognized") {
		t.Errorf("block = %#v, want a labeled placeholder", blocks[0])
	}
}

// TestLargeResultsAreBounded is the design's "the model receives a bounded
// summary, never an unbounded payload". The client's per-item limits do not
// imply a bounded result: a server can stay within every one of them and still
// return more than a context can hold.
func TestLargeResultsAreBounded(t *testing.T) {
	t.Parallel()

	t.Run("total text is capped with a visible marker", func(t *testing.T) {
		t.Parallel()
		items := []client.Content{
			client.Text{Text: strings.Repeat("a", maxResultTextBytes)},
			client.Text{Text: strings.Repeat("b", 4096)},
		}
		blocks := convertContents(items, nil)
		total := 0
		for _, b := range blocks {
			total += len(b.(*content.TextBlock).Text)
		}
		if total > maxResultTextBytes+256 {
			t.Errorf("total text = %d bytes, want it bounded near %d", total, maxResultTextBytes)
		}
		if !strings.Contains(resultText(&tool.ToolResult{Content: blocks}), "truncated at this adapter's result limit") {
			t.Error("the result was cut without saying so")
		}
	})

	t.Run("truncation does not split a rune", func(t *testing.T) {
		t.Parallel()
		// A multi-byte rune straddling the budget's last byte.
		items := []client.Content{client.Text{Text: strings.Repeat("é", maxResultTextBytes)}}
		blocks := convertContents(items, nil)
		for _, b := range blocks {
			if text, ok := b.(*content.TextBlock); ok && strings.ContainsRune(text.Text, '�') {
				t.Error("truncation split a rune: the text carries a replacement character")
			}
		}
	})

	t.Run("block count is capped with a visible marker", func(t *testing.T) {
		t.Parallel()
		items := make([]client.Content, 0, maxResultBlocks*2)
		for range maxResultBlocks * 2 {
			items = append(items, client.Image{Data: []byte{1}, MIMEType: "image/png"})
		}
		blocks := convertContents(items, nil)
		if len(blocks) != maxResultBlocks {
			t.Fatalf("blocks = %d, want %d", len(blocks), maxResultBlocks)
		}
		last, ok := blocks[len(blocks)-1].(*content.TextBlock)
		if !ok || !strings.Contains(last.Text, "omitted") {
			t.Errorf("last block = %#v, want a marker naming what was omitted", blocks[len(blocks)-1])
		}
	})
}

// TestBundleRequiresNothingOfTheLoop checks that an MCP definition demands no
// runtime binding. Its route, credentials and limits came from its own
// Definition, so it must not be able to acquire a Loop capability — and Build
// must succeed for a Loop that has none.
func TestBundleRequiresNothingOfTheLoop(t *testing.T) {
	t.Parallel()

	m := managerWith(t, testDeps(), scriptedBinding("srv", ScopeSession, okTransport("srv", "do")))
	defs := m.SessionTools(loopA, "primary")
	if len(defs) != 1 {
		t.Fatalf("definitions = %d, want 1", len(defs))
	}
	if req := defs[0].Requirements(); req != 0 {
		t.Errorf("Requirements = %v, want none: an MCP tool cannot escalate a Loop's privileges", req)
	}
	// It builds against coordinates alone: no workspace, no delegate controller,
	// nothing a Loop might have been provisioned with.
	if _, err := defs[0].Build(context.Background(), baseBindings()); err != nil {
		t.Errorf("Build with no capability bindings: %v, want success", err)
	}
}
