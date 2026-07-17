// This file defines what the adapter needs from its host.
//
// Every interface here is declared on the consumer side, by the package that
// calls it, and each is the narrowest thing that will do: the adapter asks a
// host to open a gate, to publish an event, to say which approval scopes an MCP
// tool may offer, and to tell the time. It does not ask for a Session, a Hub, or
// a config object it would then have to be trusted with (CLAUDE.md: least
// privilege — never pass a god-object when a narrow interface suffices).
//
// # What is deliberately absent: TokenStore and BrowserOpener
//
// The implementation plan lists a token store and a browser opener among these
// dependencies. They are not here, and their absence is a finding rather than an
// omission: this module's own layering means the Manager can never consume them.
//
// A TokenStore and a BrowserOpener are the inputs to auth.NewOAuthProvider,
// which yields an auth.HeaderProvider that an application installs on
// streamablehttp.Config.Auth. That happens while the application is BUILDING the
// transport — and a Binding carries an already-built client.Definition, whose
// Transport is a sealed TransportFactory the Manager only ever dials. By the
// time a Binding exists, auth is wired and its credentials are the transport's
// private business, which is exactly where they should be. Taking a TokenStore
// here would mean holding every binding's credentials in a component that has no
// use for them.
//
// URL elicitation does not need a BrowserOpener either: it becomes a
// gate.OpenURLPayload and the host decides how to present it (design
// §Elicitation), which is the whole point of routing it through a gate.

package mcpharness

import (
	"context"
	"fmt"
	"time"

	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/event"
	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/tool"
)

// Clock reports the current time. It exists so tests can drive timeouts and
// timestamps deterministically rather than sleeping.
type Clock interface {
	Now() time.Time
}

// systemClock is the real clock, used when Deps.Clock is nil.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// GateRequest asks the host to put a question to a human (or to a policy that
// answers for one). It is the adapter's whole human-input vocabulary: an MCP
// elicitation becomes one of these, and nothing MCP-shaped goes any further
// (design §Elicitation).
type GateRequest struct {
	// Kind is the gate scenario: gate.KindForm or gate.KindOpenURL.
	Kind gate.Kind
	// Payload is the authoritative request. It is a sealed gate.Payload, so a
	// host cannot be handed a shape the gate codec would reject.
	Payload gate.Payload
	// Prompt is the presentation projection an opener renders.
	Prompt gate.Prompt
	// Restorable states whether the gate may survive a restore boundary. An
	// open-url gate must never be restorable — its action target is
	// deliberately not journaled, so a restored gate could only ever be a
	// broken one, and gate.ValidateGate rejects it (see gate.OpenURLPayload).
	Restorable bool
	// Binding names the MCP binding that asked, for attribution.
	Binding string
	// LoopID is the Loop the request is on behalf of, or zero for a
	// Session-scoped binding's own startup — an elicitation raised during
	// initialization belongs to no Loop yet.
	LoopID uuid.UUID
}

// GateResponse is how the gate was answered. Action is one of the
// gate.FormAction* values; Values carries form answers and is nil for anything
// but an accepted form.
type GateResponse struct {
	Action string
	Values map[string]string
}

// GateOpener opens a Harness gate and blocks until it is resolved.
//
// It must honor ctx: the adapter cancels a pending elicitation when its MCP
// request is cancelled or its binding shuts down, and a host that ignored that
// would strand a server request nobody can answer.
type GateOpener interface {
	OpenGate(ctx context.Context, req GateRequest) (GateResponse, error)
}

// EventPublisher receives the adapter's protocol-neutral integration events.
//
// The method is named PublishEvent so that *hub.Hub satisfies this interface
// structurally, with no adapter in between — the same deliberately structural
// coupling harness uses for its CommandRunner seam. The adapter still declares
// the interface, so it depends on the one method it calls rather than on the
// Hub.
type EventPublisher interface {
	PublishEvent(ctx context.Context, ev event.Event) error
}

// ScopePolicy decides how broadly a user may persist an approval for one MCP
// tool. It is consulted per permission request, so a host may narrow a binding
// it has come to distrust without restarting it.
//
// This is the "binding-wide allow/ask/deny plus tool-specific overrides" seam of
// design §Permissions, reduced to the part the adapter can honestly own. The
// adapter does not decide whether a call is permitted — Harness's permission
// boundary does, exactly as it does for native tools — it decides which
// persistence breadths the prompt may offer, which is the choice that depends on
// how far the host trusts a third-party server.
type ScopePolicy interface {
	// Scopes returns the approval scopes offered for identity (the
	// "mcp:<binding>:<raw-tool>" permission identity). Returning an empty slice
	// is how a policy refuses: NewExternalRequest rejects an empty scope set,
	// so the call fails closed rather than prompting with nothing to grant.
	Scopes(identity string) []tool.ApprovalScope
}

// defaultScopes is the scope set used when Deps.ScopePolicy is nil.
//
// Once and Session, never Workspace. A stable permission identity is what makes
// persistence safe at all (see tool.NewExternalRequest), and "mcp:<binding>:<tool>"
// is stable — so Session is honest: it lasts as long as the connection the user
// was looking at when they approved it.
//
// Workspace is withheld because it outlives the thing it describes. A workspace
// approval persists to disk and would silently re-apply to whatever a binding of
// that name points at next week — a different server version, a different
// endpoint, a different tool behind the same raw name. That is a decision a host
// may make with knowledge the adapter does not have, so a host must opt into it
// through a ScopePolicy rather than receive it by default.
var defaultScopes = []tool.ApprovalScope{tool.ScopeOnce, tool.ScopeSession}

// fixedScopePolicy is a ScopePolicy that offers the same scopes to every tool.
type fixedScopePolicy struct{ scopes []tool.ApprovalScope }

func (p fixedScopePolicy) Scopes(string) []tool.ApprovalScope { return p.scopes }

// Deps are the host capabilities the Manager needs. Gates and Events are
// required; the rest select documented defaults when nil.
type Deps struct {
	// Gates routes elicitation to a human. Required: a binding that advertises
	// the elicitation capability with nowhere to ask would be a lie told to a
	// server.
	Gates GateOpener
	// Events receives integration events. Required: a binding whose failures
	// nobody can observe is one an operator cannot fix.
	Events EventPublisher
	// ScopePolicy decides approval persistence breadth. Nil selects
	// defaultScopes.
	ScopePolicy ScopePolicy
	// Clock is the time source. Nil selects the system clock.
	Clock Clock
}

// normalized returns deps with its optional members filled in. It never mutates
// the caller's value.
func (d Deps) normalized() Deps {
	if d.ScopePolicy == nil {
		d.ScopePolicy = fixedScopePolicy{scopes: defaultScopes}
	}
	if d.Clock == nil {
		d.Clock = systemClock{}
	}
	return d
}

// validate rejects a Deps missing a required member. It fails closed at
// construction: a nil Gates discovered at the moment a server asks for input is
// a server request that hangs, and a nil Events discovered during a failure is a
// failure nobody sees.
func (d Deps) validate() error {
	if d.Gates == nil {
		return fmt.Errorf("Deps.Gates is nil; supply a GateOpener")
	}
	if d.Events == nil {
		return fmt.Errorf("Deps.Events is nil; supply an EventPublisher")
	}
	return nil
}
