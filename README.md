# mcp

An MCP (Model Context Protocol) **client** for Looprig. It lets a Harness agent
consume existing MCP servers; it does not expose Harness agents as MCP servers.

The module wraps the official [go-sdk](https://github.com/modelcontextprotocol/go-sdk)
(pinned at v1.6.1) **without leaking its types**: no SDK type appears in any
`pkg/...` exported API. Only `internal/protocol`, `internal/mcptest`, and
`pkg/transport/*` may import the SDK, and `internal/protocol/leakguard_test.go`
enforces both halves of that rule.

Design doc: `../harness/docs/plans/2026-07-16-mcp-client-module-design.md`

## Packages

| Package | What it is |
| --- | --- |
| `pkg/client` | The protocol-neutral MCP client: one initialized peer connected to one server. Catalogs, calls, elicitation, sampling, logging, progress, cancellation, reconnect, compatibility profiles. |
| `pkg/auth` | OAuth 2.1 + PKCE, dynamic client registration, token storage. Secrets are closure-held. |
| `pkg/transport/{stdio,streamablehttp,sse}` | Transports. Each wraps an SDK transport and keeps it on the inside. |
| `pkg/harness` | The **optional** adapter from MCP capabilities to Harness tools, gates, events, and configuration identity. |
| `internal/*` | SDK conversion, catalog model, bounds, scheduling, test fixtures. Not importable. |

Harness does not import this module. The TUI knows nothing about MCP. An
application composes the three.

## Composition

The application owns the wiring. A `Manager` owns a Session's bindings; an
`Adopter` carries Loops to new catalog generations at safe boundaries.

```go
// 1. A binding is a named server definition attached to a scope.
tr, err := stdio.New(stdio.Config{Command: "some-mcp-server", Args: []string{"--stdio"}})
if err != nil {
	return err
}

bindings := []mcpharness.Binding{
	{
		Name:       "docs",
		Server:     client.Definition{Name: "docs", Transport: tr},
		Scope:      mcpharness.ScopeSession, // shared by the Loops allowed to use it
		Visibility: mcpharness.AllLoops(),   // ...which is all of them, here
		Required:   true,                    // a failure here stops the Session coming up
	},
	{
		Name:     "scratch",
		Server:   client.Definition{Name: "scratch", Transport: other},
		Scope:    mcpharness.ScopeLoop, // private to one Loop
		Loop:     plannerLoopID,
		Required: false, // a failure degrades only this binding
	},
}

// 2. The Manager needs a gate opener (for elicitation), an event publisher, and
//    a reporter for out-of-band notices.
mgr, err := mcpharness.NewManager(bindings, mcpharness.Deps{
	SessionID: sess.SessionID(),
	Gates:     myHost,      // implements GateOpener — see "Elicitation" below
	Events:    myPublisher, // implements EventPublisher
	Reporter:  myReporter,  // implements Reporter
})
if err != nil {
	return err
}
defer mgr.Close(ctx)

// 3. Start connects every binding. Required failures return a *StartupError.
if err := mgr.Start(ctx); err != nil {
	var startup *mcpharness.StartupError
	if errors.As(err, &startup) {
		// startup.Failures names each binding and its class.
	}
	return err
}

// 4. StartAdoption watches the Session for idle boundaries and installs
//    refreshed toolsets there — never mid-turn.
adopter, err := mgr.StartAdoption(sess, sess)
if err != nil {
	return err
}
defer adopter.Close()

// 5. Install the first toolset on a Loop.
if err := adopter.Install(ctx, loopID, "planner"); err != nil {
	return err
}
```

`Manager.SessionTools(loopID, loopName)` and `Manager.LoopTools(loopID)` return
the `tool.Definition`s the composition root hands to Harness. Model-facing names
are `mcp__<binding>__<tool>`; colliding names fail closed rather than shadow.

### Scopes and selectors

- **Session-scoped**: one logical connection, shared by the Loops a selector
  admits — `AllLoops()`, `Loops(ids...)`, or `Named(names...)`.
- **Loop-scoped**: a connection private to one Loop (`Binding.Loop`).
- **Delegation never copies bindings.** A delegate owns none of its parent's
  Loop-scoped bindings, and sees a Session-scoped binding only if that binding's
  own selector names it.

### `BindSession`

`NewManager` takes a `SessionID` in `Deps`, but a Manager may be constructed
before its Session exists — the common case, since a Session's configuration
fingerprint wants the Manager's `ConfigDigest()`. `BindSession(sessionID)`
attaches it afterwards. `ConfigDigest()` and `ConfigIdentity()` are available
before either call, which is what lets an application stamp MCP identity into a
Session's fingerprint at creation and detect drift at restore — reported as a
`session.ConfigMismatchError`, never as journal corruption.

### Elicitation and the host gate surface

When a server elicits, the adapter translates the request into a **Harness gate
envelope** and hands it to `Deps.Gates` (a `GateOpener`). The host — a TUI, an
HTTP client, a headless policy — renders it and answers. Three modes are
supported: form, confirm, and open-url. The adapter validates the schema, builds
a real `gate.FormSchema`, and parses the answer back into what the server asked.

**Know the seam here.** Harness has no public route to *open* a `gate.KindForm`
or `gate.KindOpenURL` gate in a Session's gate directory — `sessionruntime`'s
`PrepareGateOpen`/`ActivateGate` are internal, and `RespondGate` translates only
the loop-actor gate kinds. MCP's initialize-time elicitation also has no Loop to
hang a gate on in the first place. So a host implementing `GateOpener` **is** the
contract: the adapter produces a valid, round-trippable Harness gate envelope and
delivers the answer back to the server, but it is the host, not a Session, that
opens it. `session.GateHost` is the harness-side capability for raising a
host-owned gate; wiring a `GateOpener` to it is the application's job and is not
covered by this module's tests.

Permission gates for MCP **tool calls** are ordinary Harness gates, opened by the
real loop runner and answered through `session.SessionController.RespondGate`.

### Sampling

Sampling is **opt-in and never advertised without a handler**: install both a
handler and a `SamplingPolicy`, or the capability is not offered to the server at
all. Each request is bounded by a depth cap and a concurrency cap and routed
through the application's policy. See the limits on depth below.

## Transports

| Transport | Status | Notes |
| --- | --- | --- |
| `stdio` | Recommended | Real subprocess: process-group teardown, child reaping, no orphans on crash. `RedactedOrigin` is basename + arg count. |
| `streamablehttp` | Recommended | The current MCP HTTP transport. Refuses credential-leaking redirects. |
| `sse` | **Compatibility only, opt-in** | The legacy HTTP+SSE transport, for servers that speak nothing else. It must be enabled explicitly through a compatibility profile; it is never selected by default. Prefer `streamablehttp`. |

All three redact their origins: no argument, path, query, header, or userinfo
reaches an origin string or an error.

## Security posture

### What is guaranteed

- **SDK containment.** No consumer is forced to name an SDK type. Enforced by two
  independent checks in `internal/protocol/leakguard_test.go` — an import
  allowlist and a syntactic exported-API walk — both of which fail under
  mutation.
- **Secrets are not reachable from the exported surface.** `pkg/auth` holds
  tokens, client secrets, PKCE verifiers, and CSRF state in closures.
  `internal/secrettest` is a deliberately hostile reflector — it defeats
  `CanInterface` via `unsafe`, recurses through pointers and unexported fields,
  and ignores `String()`/`Format()` — and cannot reach them.
- **The open-url `URL` is structurally excluded from the gate _payload_.**
  `gate.OpenURLPayload.URL` is `json:"-"`: the durable codec type has no URL
  field at all, so the payload journals only a bare `scheme://host` origin.
  `javascript:`, `data:`, and `file:` are refused, and userinfo is dropped.
  This covers the URL *the adapter handles* — see the caveat below for the URL
  *a server writes into its own message*.
- **Origins and events are redacted on every transport**, proven per-transport
  rather than by one shared helper. Event payloads carry no server-authored text
  into a status; `ConnectionRestored` deliberately drops server-claimed drift
  text.
- **Bounds are real.** Catalogs, prompts, resources, log messages, and JSON depth
  are bounded, and an over-limit server is refused rather than truncated into
  something that looks fine.
- **Failure isolation.** A required binding's failure stops its owner coming up;
  an optional binding's failure degrades only itself.
- **Turn immutability.** A turn runs under the catalog generation it started
  with. A tool the server removed or re-schema'd underneath a live snapshot
  returns a structured `ToolUnavailable`/`ToolSchemaChanged` result — it never
  ends the turn, gets silently re-pointed, or makes the Session unrestorable.

### What is NOT guaranteed

Read this section as carefully as the one above.

- **The credential-field rejection is a good-faith guardrail, NOT a security
  boundary.** Form answers are journaled **unredacted**, by owner decision, and
  consistently with `command.UserInput`, which journals raw user text. There is
  no redaction layer behind the check.

  The rejection is a heuristic over English tokens: a schema-level check (field
  name, title, `format: password`, `writeOnly`) plus a body scan requiring a
  credential token paired with a solicitation verb. `format: password` and
  `writeOnly: true` are the only reliable signals, and they are reliable only
  because a server **volunteered** them.

  It defends against a *careless cooperative* server — the integrator who adds an
  `api_key` field without thinking about where the answer lands. It does **not**
  defend against a hostile one. **A determined server can still get a secret into
  the durable journal**, by naming a field innocuously (`value`, `mot_de_passe`)
  and asking for the secret in words the token list does not recognize. What the
  rule buys is that doing so must be *deliberate* rather than accidental. That is
  the whole claim. Stronger controls — a human confirmation before a free-text
  answer is journaled, or a per-binding policy refusing free-text from untrusted
  servers — **do not exist**; they are an owner's decision.

  The open-url **payload** `URL` remains structurally excluded regardless — but
  see the next point before reading that as "the URL cannot be journaled".

- **A server's own elicitation `Message` is journaled verbatim, including an
  open-url one.** `translateURL` builds the gate `Prompt.Body` as
  `req.Message + "\n\nThis will open <origin> in your browser."`, and
  `gate.Prompt.Body` is `json:"body,omitempty"` — it rides `event.GateOpened`
  into the journal. `req.Message` is server-authored and only length-bounded.

  So the payload's structural exclusion of `URL` protects the URL the *adapter*
  puts there; it does **not** stop a server from writing its full authorization
  URL — `state`, `code_challenge` and all — into its own message, where it is
  journaled in the clear. The in-code comment asserting that `Prompt.Body`
  closes this "back door" is establishing the property for only one of `Body`'s
  two inputs. Treat an open-url elicitation's *message* as untrusted,
  server-controlled text with a durable destination.

- **Sampling depth counts one observable causal link.** A chain is attributed
  only when the host's handler calls back into *this* client *with the handler's
  context* — the single link the module can see. A chain that leaves by another
  door (a server reaching a second host; a host driving an unrelated client
  without passing the handler's context) is **not** depth-bounded; it is bounded
  only by the concurrency cap. MCP gives an inbound request no correlation to
  whatever caused it, so this is structural, not an oversight. Attribution is
  conservative: an ambiguous chain is read as the longer one.

- **Elicitation gates are not opened by a Session.** See the seam above. The
  adapter's contract ends at `GateOpener`; what a host does with the envelope is
  the host's business, and this module cannot vouch for it.

- **Compatibility tolerances are a decision, not a safety net.** A profile that
  tolerates a server's drift is an application choosing to accept it. Every
  tolerance applied is recorded on the catalog, and they are worth reading.

## Testing

| Command | What it runs |
| --- | --- |
| `make test` | Unit tests. No subprocesses, no network. |
| `make test-integration` | The `integration`-tagged tests: real child processes, real pipes, real MCP servers. |
| `make secure` | gofmt check, vet, staticcheck, gosec, go mod verify, govulncheck. |

Anything that crosses a process boundary is tagged `//go:build integration` and lives in a `*_integration_test.go` file, so it is excluded from the default `go test ./...` run. `make secure` deliberately does not depend on `test-integration`: the pre-commit gate stays fast, and CI runs both.

End-to-end tests that need a real Harness rig — real Sessions, real turns, real
delegates — live in the `github.com/looprig/tests` module. That is why this
module does not depend on `storage`.
