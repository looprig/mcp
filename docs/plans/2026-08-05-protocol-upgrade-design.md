# MCP protocol upgrade — SDK v1.7.0, all spec revisions (2024-11-05 → 2026-07-28)

**Date:** 2026-08-05
**Status:** Approved

## Goal

Upgrade the wrapped `github.com/modelcontextprotocol/go-sdk` from v1.6.1 to v1.7.0 so
clients negotiate any of the five MCP spec revisions, with 2026-07-28 (stateless /
`server/discover` / MRTR / `subscriptions/listen`) fully exercised and tested — not
merely "compiles against v1.7.0."

Standing constraint (CLAUDE.md): SDK types never leak past `pkg/client` /
`internal/protocol` into any exported `pkg/...` API.

## Background

Spec 2026-07-28 is a semantic shift, not a version bump:

- `initialize`/`notifications/initialized` handshake removed; each request carries
  `_meta.io.modelcontextprotocol/{protocolVersion,clientInfo,clientCapabilities}`;
  a new `server/discover` RPC probes capabilities up front (SDK falls back to
  legacy `initialize` if discover fails).
- Server-initiated sampling/elicitation replaced by multi-round-trip (MRTR)
  "input-required" results; the SDK's client-side MRTR middleware (enabled by
  default) auto-fulfills these via the existing `ElicitationHandler` etc.
- Free-floating change notifications replaced by a unified `subscriptions/listen`
  stream; the SDK maps it back onto `ToolListChangedHandler` /
  `ResourceListChangedHandler`.
- HTTP resumability (`Last-Event-ID`, standalone GET) removed on the new revision;
  `ping`, `logging/setLevel`, `resources/subscribe`/`unsubscribe` rejected with
  `MethodNotFound`.
- Roots, sampling, and logging formally deprecated (SEP-2577) but functional.
- Streamable HTTP servers speak 2026-07-28 only when stateless; stateful servers
  negotiate down to 2025-11-25. Backward compat with ≤2025-11-25 is preserved by
  SDK version negotiation on every endpoint.

Because the SDK keeps the same client handler surface across revisions, this is a
substantial upgrade of our layers, not a rewrite.

## Design

### 1. Dependency + mechanical layer

Bump `go-sdk` to v1.7.0, re-vendor, fix compile breaks (mandatory
`NotificationSubscriptions` field, elicit-mode inference, JSON-RPC invalid-params
wrapping, renamed options). Update the CLAUDE.md approved-package pin to v1.7.0.

### 2. Protocol layer (`internal/protocol`)

Teach it the 2026-07-28 revision explicitly. The handshake result may now come from
`server/discover` rather than `initialize`; the SDK normalizes both into
`InitializeResult`, so our `Handshake` / `ProtocolVersion` types stay, but
validation/truncation must accept the discover-sourced shape and the version-string
set widens. Catalog digest already tags `protocol_version`, so catalog identity
handles new values for free.

### 3. Reconnect/refresh (`pkg/client`) — riskiest area

`reconnect.go`/`refresh.go` re-run initialize on reconnect today. They must branch on
the negotiated version: for 2026-07-28 sessions, reconnect means a fresh discover +
catalog re-verify rather than stream resumption (resumability no longer exists).
Sessions that negotiated ≤2025-11-25 keep the current path unchanged.

### 4. Server-initiated features

Keep the SDK's MRTR middleware enabled (default) so existing elicitation and
sampling handlers work identically on both wire models — no harness-facing API
change. Roots/sampling/logging stay supported for legacy servers; document the
in-spec deprecation on our wrappers. Negotiated version already surfaces in
`Status`.

### 5. Transports

All three stay: stdio (new protocol unchanged over it), streamable HTTP (SDK
negotiates 2026-07-28 vs stateless servers, 2025-11-25 vs stateful), legacy SSE
(2024-11-05 only, unchanged). No new transport exists to add.

### 6. Auth

Adopt v1.7.0's OAuth session-persistence hooks (`NewTokenSource` /
`InitialTokenSource`) in `pkg/auth`'s tokenstore so tokens survive restarts.

### 7. Testing

Extend `internal/mcptest` with a 2026-07-28 stateless streamable-HTTP server mode.
Run the existing integration matrix (catalog discovery, refresh, reconnect,
elicitation, sampling, limits/fuzz) across all four negotiable versions. Add
end-to-end regressions through `pkg/harness` against a 2026-07-28-only server and a
2024-11-05-only server.
