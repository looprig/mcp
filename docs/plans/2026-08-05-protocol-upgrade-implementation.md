# MCP Protocol Upgrade Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade `looprig/mcp` from go-sdk v1.6.1 to v1.7.0 so clients negotiate every MCP spec revision (2024-11-05 → 2026-07-28), with the new stateless protocol exercised end-to-end.

**Architecture:** The SDK keeps one client handler surface across all revisions — it maps `server/discover` (SEP-2575), MRTR input-required retries (SEP-2322), and the unified `subscriptions/listen` stream internally, and falls back to legacy `initialize` against old servers. Our layered wrapper therefore survives intact: transports (`pkg/transport/*`) → SDK-conversion boundary (`internal/protocol`, `internal/httpconn`) → client lifecycle (`pkg/client`) → harness facade (`pkg/harness`). The work is: (1) mechanical SDK bump, (2) a version predicate in the protocol layer, (3) a stateless test fixture, (4) integration coverage proving discovery/reconnect/refresh/elicitation on the new protocol, (5) a protocol-version matrix, (6) auth verification.

**Tech Stack:** Go 1.26, `github.com/modelcontextprotocol/go-sdk` v1.7.0 (vendored), stdlib elsewhere.

**Design doc:** `docs/plans/2026-08-05-protocol-upgrade-design.md`. Two deliberate deviations from it, discovered during planning and recorded here: (a) design §6 proposed adopting the SDK's OAuth `NewTokenSource`/`InitialTokenSource` hooks — not applicable, because `pkg/auth` is a hand-rolled OAuth provider that never uses SDK auth handlers and already persists tokens via its own `TokenStore` (see Task 10); (b) design §8 proposed the version matrix "through `pkg/harness`" — `pkg/harness` has no real-server integration harness (its tests are fake-conn unit tests), so the matrix lives at the `pkg/client` level where the fixture helpers exist (see Task 9).

---

## 0. Executor context primer — READ THIS FIRST

### Where you are

- Working directory: `/Users/ipotter/code/looprig/mcp`. This directory is **its own git repository** (not a subdir of a parent repo's tree for commit purposes). Commit here.
- Commits: conventional-commit style (`feat(scope):`, `test(scope):`, `chore(deps):`). **No `Co-Authored-By` trailer** — this project omits it.
- The module vendors its dependencies (`vendor/` is checked in). After any `go.mod` change run `go mod tidy && go mod vendor` and commit the vendor diff too.
- `CLAUDE.md` at the repo root is binding: TDD, `-race` on every test run, `make secure` before commit, strict typing, no new dependencies without user approval.
- **The one inviolable API rule:** types from `github.com/modelcontextprotocol/go-sdk` may appear only inside `internal/*` and `pkg/client`'s *unexported* internals. No exported identifier in any `pkg/...` package may mention an SDK type. `internal/mcptest` (a test fixture) is exempt — it exists to build SDK servers.

### Commands

```bash
# unit tests (excludes integration files)
go test -race ./...
# integration tests (process/socket-crossing; build tag "integration")
go test -tags integration -race ./...
# build
CGO_ENABLED=0 go build -trimpath ./...
# format + full gate (gofmt check, vet, staticcheck, gosec, govulncheck)
make fmt
make secure
```

Integration test files start with `//go:build integration` and are named `*_integration_test.go`.

### Module map (what each layer is)

| Path | Role |
|---|---|
| `pkg/transport/stdio` | Launches an MCP server subprocess; `stdio.New(stdio.Config{Command, Args})` returns a `client.TransportFactory`. |
| `pkg/transport/streamablehttp` | Streamable HTTP client transport; `streamablehttp.New(Config{Endpoint: url})`. Wraps `internal/httpconn`. |
| `pkg/transport/sse` | Legacy 2024-11-05 HTTP+SSE client transport; `sse.New(sse.Config{...})`. |
| `internal/protocol` | The SDK boundary: neutral types (`InitializeResult`, `ProtocolVersion`, `ToolResult`, `Conn` interface) + conversions from SDK types, with limits/truncation. External input is untrusted; conversions bound everything. |
| `internal/httpconn` | The `protocol.Conn` implementation over the SDK's streamable HTTP client. |
| `internal/catalog` | Catalog generations, identity, digest. Digest already includes a `protocol_version` field — new version strings need no digest work. |
| `pkg/client` | Connection lifecycle: `client.Connect(ctx, Definition, Handlers)` → discovery → adopted `Catalog`; reconnect (`reconnect.go`), refresh on list-changed (`refresh.go`), elicitation/sampling/roots adapters. |
| `pkg/harness` | Facade binding clients into the looprig harness. Unit-tested with fakes only. |
| `pkg/auth` | Hand-rolled OAuth (PKCE, discovery, refresh) + `TokenStore`. Does **not** use SDK auth. |
| `internal/mcptest` | The fixture MCP server (a real SDK server). Stdio mode: built binary via `mcptest.BuildFixture(t)` + flags. HTTP mode: `mcptest.NewHTTPHandler(Config)` / `NewSSEHandler(Config)` mounted on `httptest.NewServer`. |

### Test-helper inventory (reuse these; do not reinvent)

- `pkg/client/client_integration_test.go:36` — `fixtureClient(t, handlers, shape, args...)`: stdio fixture + `client.Connect`, cleanup registered. `shape` mutates the `client.Definition` (e.g. enable capabilities).
- `pkg/client/client_integration_test.go:69` — `testCtx(t)`; `:77` — `resultText(t, res)`.
- `pkg/client/reconnect_integration_test.go:27` — `awaitState(t, c, want client.State)`.
- `pkg/client/refresh_integration_test.go:27` — `awaitCandidate(t, c)`; `:41` — `mutate(t, c, add bool)` (drives the fixture's mutate tool → real `tools/list_changed`).
- `pkg/transport/streamablehttp/streamablehttp_integration_test.go:46` — `newFixtureServer(t, mcptest.Config)` → URL; `:61` — `connectFixture`; `:95` — `callTool`.
- Fixture constants in `internal/mcptest/server.go`: `ToolEcho`, `ToolMutate`, `ToolMutated`, `ToolCrash`, `ToolElicit`, `EchoInput{Text}`, `MutateInput{Add}`, `ServerName`, `ServerVersion`.

### v1.7.0 SDK facts you will rely on (verified against the release)

- Spec constants in `vendor/.../mcp/shared.go` after the bump: `2026-07-28` (latest, in `supportedProtocolVersions`), `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`.
- `(*mcp.ClientSession).InitializeResult() *mcp.InitializeResult` exposes the negotiated result (`.ProtocolVersion` string).
- `mcp.StreamableHTTPOptions{Stateless: true}` serves the stateless mode that negotiates `2026-07-28`; stateful streamable HTTP **caps at `2025-11-25`** (release note: "cap negotiated protocolVersion in legacy initialize to 2025-11-25"). In stateless mode GET/DELETE return 405 and the server cannot make server→client *requests*; server→client interaction happens via MRTR, and notifications flow through the client-opened `subscriptions/listen` stream (SDK `client.go` opens it automatically when list-changed handlers are registered).
- Client-side MRTR middleware is **enabled by default** (`MultiRoundTripOptions.Disabled=false` in `vendor/.../mcp/mrtr.go`): a `2026-07-28` server returning input-required results causes the SDK to invoke the client's `ElicitationHandler` and retry — our existing `OnElicit` adapter keeps working with zero changes.
- Roots/sampling/logging are deprecated in-spec (SEP-2577) but functional against ≤`2025-11-25` peers; the SDK marks its option fields `// Deprecated:`.
- Error change: params-decoding failures now wrap `jsonrpc2.ErrInvalidParams` → wire code −32602 (was 0).

### General decision rules

1. **A test that fails after the bump:** first decide whether the *new* behavior is spec-correct (check the release notes quoted above and the SDK doc comments in `vendor/`). If yes, fix the assertion; if the wrapper now violates its own documented contract, fix the wrapper. Never delete a test to make the suite pass.
2. **Never edit anything under `vendor/`** except by running `go mod vendor`.
3. **staticcheck SA1019** (use of deprecated SDK fields): suppress per call site with `//lint:ignore SA1019 <reason>` where the reason is "supported for peers ≤2025-11-25 (SEP-2577)". No blanket disables in the Makefile or config.
4. If something in this plan contradicts what you find in the code, stop and re-read the relevant file — the code wins; adapt the step minimally and note the deviation in the commit message.

---

## Phase 1 — SDK bump (mechanical)

### Task 1: Upgrade the dependency and fix compile breaks

**Files:**
- Modify: `go.mod`, `go.sum`, `vendor/` (regenerated)
- Modify: whatever breaks — expected candidates: `internal/protocol/*.go`, `internal/httpconn/conn.go`, `pkg/client/errors.go` + tests, `internal/mcptest/server.go`
- Modify: `CLAUDE.md` (approved-package pin)

**Step 1: Bump and vendor**

```bash
cd /Users/ipotter/code/looprig/mcp
go get github.com/modelcontextprotocol/go-sdk@v1.7.0
go mod tidy && go mod vendor
```

Note: `go.work` at the workspace root may interfere with resolution; if `go get` resolves a wrong version, run with `GOWORK=off`.

**Step 2: Build; fix each break minimally**

Run: `CGO_ENABLED=0 go build -trimpath ./...` and then `go vet ./...`.

Known breaking changes to expect and how to handle each:

| Break | Fix |
|---|---|
| `NotificationSubscriptions` now a mandatory field on subscription-related SDK options | Set it explicitly at the call site that constructs SDK client options (search: `grep -rn 'ClientOptions{' internal/ --include='*.go' \| grep -v vendor`). Choose the value that preserves current behavior (subscriptions on — our refresh path depends on list-changed events). |
| Elicit mode now inferred from `ElicitParams` | If `internal/protocol/elicit.go` or `conv.go` sets an explicit mode field that no longer exists, delete the assignment; the SDK infers it. |
| Invalid-params errors wrap `jsonrpc2.ErrInvalidParams` (code −32602, was 0) | If `pkg/client/errors.go` or its tests classify by JSON-RPC code, update the classifier/assertions. −32602 is a server-protocol failure, same class as before — only the numeric code shifted. |
| Deprecation markers on sampling/roots/logging SDK fields | Compile is unaffected; staticcheck will flag in Step 4 — apply decision rule 3. |

Do not restructure anything in this task; smallest possible diffs.

**Step 3: Update the CLAUDE.md pin**

In `CLAUDE.md`'s approved-packages list, change `v1.6.1` → `v1.7.0` on the go-sdk line and append: `Upgraded 2026-08-05 for all-protocol support (docs/plans/2026-08-05-protocol-upgrade-design.md).`

**Step 4: Full suite**

```bash
go test -race ./...
go test -tags integration -race ./...
make secure
```

Expected: PASS / clean. Note: after this bump, the **stdio fixture negotiates `2026-07-28` by default** (both ends are v1.7.0), so every existing stdio integration test now runs on the new protocol. Failures here are the upgrade's real findings — triage with decision rule 1; use @superpowers:systematic-debugging for anything not obviously an assertion drift.

**Step 5: Commit**

```bash
git add -A
git commit -m "chore(deps): upgrade modelcontextprotocol/go-sdk to v1.7.0"
```

---

## Phase 2 — Protocol layer

### Task 2: `ProtocolVersion.Stateless()` predicate

The module treats `ProtocolVersion` as an untrusted server-supplied string (keep that). The lifecycle layers need exactly one question answered: does the negotiated revision speak the stateless wire model?

**Files:**
- Modify: `internal/protocol/protocol.go` (the `ProtocolVersion` type is at ~line 313)
- Create: `internal/protocol/protocol_version_test.go`

**Step 1: Write the failing test**

```go
package protocol

import "testing"

func TestProtocolVersionStateless(t *testing.T) {
	tests := []struct {
		name    string
		version ProtocolVersion
		want    bool
	}{
		{name: "2026-07-28 is stateless", version: "2026-07-28", want: true},
		{name: "2025-11-25 is stateful", version: "2025-11-25", want: false},
		{name: "2025-06-18 is stateful", version: "2025-06-18", want: false},
		{name: "2025-03-26 is stateful", version: "2025-03-26", want: false},
		{name: "2024-11-05 is stateful", version: "2024-11-05", want: false},
		{name: "empty is stateful", version: "", want: false},
		{name: "later unknown date is stateless", version: "2027-01-01", want: true},
		{name: "garbage is stateful", version: "not-a-date", want: false},
		{name: "date-length garbage is stateful", version: "aaaa-bb-cc", want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.version.Stateless(); got != tt.want {
				t.Errorf("ProtocolVersion(%q).Stateless() = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
```

**Step 2: Run to verify it fails**

Run: `go test -race ./internal/protocol/ -run TestProtocolVersionStateless -v`
Expected: compile FAIL — `v.Stateless undefined`.

**Step 3: Implement**

Add to `internal/protocol/protocol.go`, directly below the `ProtocolVersion` type declaration:

```go
// statelessSince is the first spec revision with the stateless wire model
// (SEP-2575): no initialize handshake, no resumability, MRTR in place of
// server-initiated requests.
const statelessSince = "2026-07-28"

// Stateless reports whether this revision speaks the stateless wire model.
// Version strings are ISO dates, so lexical comparison is date comparison. A
// value that is not date-shaped is treated as legacy: the string is
// server-supplied and untrusted, and the legacy path is the conservative one.
func (v ProtocolVersion) Stateless() bool {
	if len(v) != len(statelessSince) {
		return false
	}
	for i, r := range v {
		if i == 4 || i == 7 {
			if r != '-' {
				return false
			}
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return string(v) >= statelessSince
}
```

**Step 4: Run the package's full suite**

Run: `go test -race ./internal/protocol/ -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/protocol/
git commit -m "feat(protocol): ProtocolVersion.Stateless for the 2026-07-28 wire model"
```

### Task 3: Handshake conversion covers discover-sourced results

The SDK normalizes `server/discover` into `*mcp.InitializeResult`, so `FromSDKInitializeResult` (`internal/protocol/initialize.go:31`) keeps working. Lock the new shapes in with tests; change code only if a test exposes a real gap.

**Files:**
- Modify: `internal/protocol/initialize_test.go` (extend its existing table)

**Step 1: Read the normalization**

Read `vendor/github.com/modelcontextprotocol/go-sdk/mcp/client.go` — the `discover` method (~line 410) and the connect path (~line 319) that turns a `DiscoverResult` into the session's `InitializeResult`. Note which fields discover can leave zero.

**Step 2: Add table cases**

Extend `initialize_test.go`'s table (match its existing case shape exactly) with:
- version `"2026-07-28"`, nil `Capabilities`, empty `ServerInfo` → succeeds; converted result has `ProtocolVersion == "2026-07-28"`, zero-value capabilities.
- version `"2026-07-28"`, `Instructions` longer than the test's `Bounds.MaxTextBytes` → succeeds; instructions truncated (mirror however the existing truncation case asserts).
- empty version with otherwise-full result → still the fatal error (existing case probably covers empty version; keep it and add the 2026-07-28 rows).

**Step 3: Run**

Run: `go test -race ./internal/protocol/ -v`
Expected: PASS with no production-code change. If conversion actually rejects a legal discover shape, fix `initialize.go` minimally and say so in the commit message.

**Step 4: Commit**

```bash
git add internal/protocol/
git commit -m "test(protocol): handshake conversion covers discover-sourced results"
```

---

## Phase 3 — Test fixture

### Task 4: Stateless mode in `internal/mcptest`

**Files:**
- Modify: `internal/mcptest/server.go` (`Config` struct, ~line 172 region; `Config.Validate` at line 242)
- Modify: `internal/mcptest/http.go` (`NewHTTPHandler` line 42, `newHTTPServer` line 74, `NewSSEHandler` line 64)
- Modify: `internal/mcptest/server_test.go` (extend)

**Step 1: Write the failing tests**

Append to `internal/mcptest/server_test.go` (unit file, no build tag — check its imports; add `net/http/httptest` and the SDK `mcp` import if missing):

```go
func TestStatelessHandlerNegotiates20260728(t *testing.T) {
	t.Parallel()
	h, err := NewHTTPHandler(Config{Stateless: true})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	probe := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "0"}, nil)
	cs, err := probe.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer cs.Close()
	if got := cs.InitializeResult().ProtocolVersion; got != "2026-07-28" {
		t.Errorf("negotiated %q, want 2026-07-28", got)
	}
}

func TestStatefulHandlerCapsAt20251125(t *testing.T) {
	t.Parallel()
	h, err := NewHTTPHandler(Config{})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	probe := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "0"}, nil)
	cs, err := probe.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer cs.Close()
	if got := cs.InitializeResult().ProtocolVersion; got != "2025-11-25" {
		t.Errorf("negotiated %q, want 2025-11-25 (stateful HTTP caps below 2026-07-28)", got)
	}
}

func TestSSEHandlerRefusesStateless(t *testing.T) {
	t.Parallel()
	if _, err := NewSSEHandler(Config{Stateless: true}); err == nil {
		t.Fatal("NewSSEHandler(Stateless) succeeded, want a refusal: the legacy transport predates the concept")
	}
}
```

(If the fixture's `Config` requires other fields per `Validate`, use the zero config plus `Stateless` exactly as the existing tests in that file do.)

**Step 2: Run to verify failure**

Run: `go test -race ./internal/mcptest/ -run 'Stateless|Stateful|SSEHandlerRefuses' -v`
Expected: compile FAIL — unknown field `Stateless`.

**Step 3: Implement**

In `server.go`, add to `Config` (match the doc-comment voice of neighboring fields):

```go
// Stateless serves the Streamable HTTP handler in stateless mode
// (SEP-2567), which is what lets a client negotiate spec revision
// 2026-07-28: no Mcp-Session-Id, no server-initiated requests, GET and
// DELETE answered 405. Meaningless for the stdio and SSE fixtures, whose
// constructors refuse it.
Stateless bool
```

In `http.go`:

```go
func NewHTTPHandler(cfg Config) (http.Handler, error) {
	s, err := newHTTPServer(cfg)
	if err != nil {
		return nil, err
	}
	var opts *mcp.StreamableHTTPOptions
	if cfg.Stateless {
		opts = &mcp.StreamableHTTPOptions{Stateless: true}
	}
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, opts), nil
}
```

In `NewSSEHandler`, before building the server:

```go
	if cfg.Stateless {
		return nil, fmt.Errorf("mcptest: Config.Stateless is not supported over the legacy SSE transport: " +
			"stateless is a Streamable HTTP mode (SEP-2567); use NewHTTPHandler")
	}
```

If the stdio fixture's flag parsing (`cmd/fixture` — find with `grep -rn 'flag.' internal/mcptest/ cmd/ 2>/dev/null | grep -v vendor | head`) rejects unknown Config fields, nothing to do: do NOT add a stdio flag for `Stateless`.

**Step 4: Run**

Run: `go test -race ./internal/mcptest/ -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/mcptest/
git commit -m "feat(mcptest): stateless HTTP fixture mode for protocol 2026-07-28"
```

---

## Phase 4 — Client lifecycle on the new protocol

All tasks in this phase add integration tests to `pkg/transport/streamablehttp/streamablehttp_integration_test.go` or a new sibling file — that is where the existing real-HTTP e2e tests and helpers (`newFixtureServer`, `connectFixture`) live, and `pkg/client` is imported there already (`TestClientConnectOverHTTP` at ~line 117 is the template: fixture URL → `New(Config{Endpoint: url + "/mcp"})`... note whether the existing tests append `/mcp` to the httptest URL — copy whatever they do exactly; the SDK handler serves at the mount root, so the existing code is authoritative).

Create the new file as `pkg/transport/streamablehttp/stateless_integration_test.go`, package `streamablehttp`, starting with `//go:build integration` and importing the same set the existing integration file uses.

### Task 5: End-to-end discovery + tool call against a stateless server

**Step 1: Write the integration test**

```go
// TestClientConnectStateless is TestClientConnectOverHTTP against a stateless
// fixture: the shape a 2026-07-28-only deployment has. What is under test is
// the whole client stack — discover instead of initialize, catalog discovery,
// a real tool call — over the new wire model.
func TestClientConnectStateless(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{Stateless: true, Instructions: "stateless fixture"})
	f, err := New(Config{Endpoint: url})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := client.Connect(ctx, client.Definition{Name: "fixture", Transport: f}, client.Handlers{})
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		_ = c.Close(closeCtx)
	})

	cat := c.Catalog()
	if !cat.Valid() {
		t.Fatal("no adopted catalog against a stateless server")
	}
	if cat.ProtocolVersion != "2026-07-28" {
		t.Errorf("ProtocolVersion = %q, want 2026-07-28", cat.ProtocolVersion)
	}
	if _, ok := cat.ToolByRawName(mcptest.ToolEcho); !ok {
		t.Error("echo tool missing from the stateless catalog")
	}

	args, err := json.Marshal(mcptest.EchoInput{Text: "stateless"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := c.CallTool(ctx, mcptest.ToolEcho, args, client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool(echo) error = %v", err)
	}
	if res.IsError {
		t.Errorf("CallTool(echo) tool error: %+v", res.Content)
	}
}
```

Adjust only mechanically: endpoint suffix (`/mcp` or not) per the existing tests, and any `Definition` fields the existing e2e test sets.

**Step 2: Run**

Run: `go test -tags integration -race ./pkg/transport/streamablehttp/ -run TestClientConnectStateless -v`
Expected: PASS — the SDK does the discover/negotiation. If `client.Connect` fails, the failure is the real work: debug with @superpowers:systematic-debugging; likely suspects are `internal/httpconn` assumptions about GET streams (405 in stateless mode) or an error-classification drift.

**Step 3: Commit**

```bash
git add pkg/transport/streamablehttp/
git commit -m "test(streamablehttp): end-to-end client discovery against a stateless 2026-07-28 server"
```

### Task 6: Reconnect against a stateless server

`pkg/client/reconnect.go`'s `reconnectOnce` (line 287) already dials a **new logical connection** and re-verifies the catalog — the correct shape for a protocol without resumability. Verify no layer still assumes resumption, then prove reconnect end-to-end.

**Step 1: Audit for resumption assumptions**

Run: `grep -rn -i 'last-event\|resum' pkg/ internal/ --include='*.go' | grep -v vendor | grep -v _test`

For each hit, read the surrounding code and decide: does it *implement* stream resumption toward the server (bad under 2026-07-28 — the SDK client won't resume against stateless servers, so this should be dead code on that path), or is it the transport's own connection-retry bookkeeping (fine — e.g. `streamReconnects` in `streamablehttp.go:107` bounds SDK-level stream retries and is version-agnostic)? Only change code if something outside the SDK sends `Last-Event-ID` itself. Expected outcome: no changes.

**Step 2: Write the integration test**

Reconnect needs a connection to die. Over HTTP the fixture can't crash (see `http.go`'s refusals), so kill the *server*: mount the stateless handler, note the listener address, close the httptest server, and bring a new one up on the same address. Append to `stateless_integration_test.go`:

```go
// TestReconnectStateless proves the reconnect sequence over the stateless
// protocol: the server goes away, the binding classifies the loss, redials,
// re-runs discovery (there is no stream to resume on 2026-07-28), and serves
// calls again with the adopted catalog intact.
func TestReconnectStateless(t *testing.T) {
	t.Parallel()

	h, err := mcptest.NewHTTPHandler(mcptest.Config{Stateless: true})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	srv := httptest.NewServer(h)
	addr := srv.Listener.Addr().String()

	f, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	def := client.Definition{Name: "fixture", Transport: f}
	def.Reconnect.Attempts = 5
	def.Reconnect.BaseDelay = 20 * time.Millisecond
	def.Reconnect.MaxDelay = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := client.Connect(ctx, def, client.Handlers{})
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		_ = c.Close(closeCtx)
	})
	before := c.Catalog()

	// Kill the server, then resurrect it on the same address so redials land.
	srv.CloseClientConnections()
	srv.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("relisten on %s: %v", addr, err)
	}
	srv2 := &httptest.Server{Listener: ln, Config: &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}}
	srv2.Start()
	t.Cleanup(srv2.Close)

	// A call during/after the outage must eventually succeed again.
	deadline := time.Now().Add(45 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		args, _ := json.Marshal(mcptest.EchoInput{Text: "back"})
		res, err := c.CallTool(ctx, mcptest.ToolEcho, args, client.CallOpts{})
		if err == nil && !res.IsError {
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("binding never recovered: last error = %v", lastErr)
	}

	after := c.Catalog()
	if after.Generation != before.Generation || after.Digest != before.Digest {
		t.Errorf("adopted catalog changed across reconnect: (gen %d, %s) -> (gen %d, %s)",
			before.Generation, before.Digest, after.Generation, after.Digest)
	}
	if got := c.Status().ProtocolVersion; got != "2026-07-28" {
		t.Errorf("ProtocolVersion after reconnect = %q, want 2026-07-28", got)
	}
}
```

Caveat for the executor: in stateless mode each POST is its own exchange, so the client may not *notice* the outage until it makes a call — that is why the test polls calls rather than awaiting a state transition. If the client turns out to surface no `StateReconnecting` at all here (calls just fail then succeed), that is acceptable stateless behavior: keep the recovered-call and catalog-stability assertions, drop any state assertions, and say so in the commit message.

**Step 3: Run**

Run: `go test -tags integration -race ./pkg/transport/streamablehttp/ -run TestReconnectStateless -v`
Expected: PASS, or a real defect — fix minimally in `pkg/client/reconnect.go` gated on `res.ProtocolVersion.Stateless()` (Task 2's predicate; the neutral `protocol.InitializeResult` carries it).

**Step 4: Commit**

```bash
git add pkg/transport/streamablehttp/ pkg/client/
git commit -m "test(streamablehttp): reconnect over stateless 2026-07-28 (fresh discovery, no resumption)"
```

### Task 7: List-changed refresh via `subscriptions/listen`

**Step 1: Write the integration test**

Append to `stateless_integration_test.go` (this mirrors `pkg/client/refresh_integration_test.go`'s stdio flow; on 2026-07-28 the wire mechanism is the client-opened `subscriptions/listen` stream, which the SDK opens automatically because our conn registers list-changed handlers):

```go
// TestListChangedStateless: the fixture mutates its tool list; on 2026-07-28
// the change notification arrives on the subscriptions/listen stream rather
// than as a free-floating notification, and must still produce a candidate
// generation.
func TestListChangedStateless(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{Stateless: true, Mutate: true})
	f, err := New(Config{Endpoint: url})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := client.Connect(ctx, client.Definition{Name: "fixture", Transport: f}, client.Handlers{})
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		_ = c.Close(closeCtx)
	})

	args, err := json.Marshal(mcptest.MutateInput{Add: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := c.CallTool(ctx, mcptest.ToolMutate, args, client.CallOpts{})
	if err != nil || res.IsError {
		t.Fatalf("CallTool(mutate) error = %v, IsError = %v", err, res.IsError)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cand, ok := c.Candidate(); ok {
			if _, ok := cand.ToolByRawName(mcptest.ToolMutated); !ok {
				t.Errorf("candidate lacks the mutated tool %q", mcptest.ToolMutated)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no candidate generation arrived over subscriptions/listen")
}
```

**Step 2: Run**

Run: `go test -tags integration -race ./pkg/transport/streamablehttp/ -run TestListChangedStateless -v`
Expected: PASS. If no candidate arrives: check whether `internal/httpconn`/`internal/protocol` construct the SDK client with the list-changed handlers registered *before* connect (the SDK only opens the listen stream when handlers exist at connect time — see `vendor/.../mcp/client.go` ~line 333), and whether the Task 1 `NotificationSubscriptions` value opted subscriptions on. Fix at the SDK-options construction site; do not add public API.

**Step 3: Commit**

```bash
git add pkg/transport/streamablehttp/ internal/
git commit -m "test(streamablehttp): catalog refresh driven by subscriptions/listen on 2026-07-28"
```

### Task 8: Elicitation over MRTR; legacy features still pass; deprecation notes

**Step 1: Write the integration test**

Append to `stateless_integration_test.go`. The elicitor double lives in `pkg/client/elicit_integration_test.go:28` (`scriptedElicitor`) but is in another package's test — re-declare a minimal local copy:

```go
type statelessElicitor struct {
	mu   sync.Mutex
	seen []client.ElicitRequest
}

func (e *statelessElicitor) Elicit(_ context.Context, req client.ElicitRequest) (client.ElicitResult, error) {
	e.mu.Lock()
	e.seen = append(e.seen, req)
	e.mu.Unlock()
	return client.ElicitResult{Action: client.ElicitAccept, Content: json.RawMessage(`{"name":"ada"}`)}, nil
}

// TestElicitationStateless: on 2026-07-28 a server cannot call the client, so
// the elicit tool comes back input-required and the SDK's MRTR middleware
// invokes our handler and retries. The application-visible contract — the
// handler sees the server's prompt, the answer reaches the tool — is identical
// to the legacy flow, and that identity is what this test pins.
func TestElicitationStateless(t *testing.T) {
	t.Parallel()

	url := newFixtureServer(t, mcptest.Config{Stateless: true, Elicit: true})
	f, err := New(Config{Endpoint: url})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	el := &statelessElicitor{}
	def := client.Definition{Name: "fixture", Transport: f}
	def.Capabilities.Elicitation = true

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := client.Connect(ctx, def, client.Handlers{Elicitation: el})
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer closeCancel()
		_ = c.Close(closeCtx)
	})

	res, err := c.CallTool(ctx, mcptest.ToolElicit, json.RawMessage(`{}`), client.CallOpts{})
	if err != nil {
		t.Fatalf("CallTool(elicit) error = %v", err)
	}
	if res.IsError {
		t.Fatalf("CallTool(elicit) tool error: %+v", res.Content)
	}

	el.mu.Lock()
	seen := len(el.seen)
	el.mu.Unlock()
	if seen != 1 {
		t.Errorf("elicitation handler invoked %d times, want 1", seen)
	}
}
```

Check `pkg/client/elicit_integration_test.go` for how the accepted answer surfaces in the elicit tool's result (it asserts the server "reports it back") and add the same content assertion here — copy its expected-string logic.

**Step 2: Run**

Run: `go test -tags integration -race ./pkg/transport/streamablehttp/ -run TestElicitationStateless -v`
Expected: PASS with the SDK's MRTR middleware at its default (enabled). Do not add a disable knob (YAGNI).

**Step 3: Legacy features still pass**

Run: `go test -tags integration -race ./pkg/client/ -run 'Sampling|Roots|Elicit' -v`
Expected: PASS. Note which protocol version those stdio tests now negotiate (post-bump it is 2026-07-28): sampling/roots remain functional per SEP-2577's deprecation window; if any fail because the new revision rejects the method outright, the correct fix is to run those specific fixtures at a legacy revision — check whether the SDK server offers a version-pinning option (`grep -n 'ProtocolVersion' vendor/.../mcp/server.go`) and wire it through a `mcptest.Config` field, mirroring Task 4's pattern. Only do this if actually forced.

**Step 4: Deprecation doc comments**

On the exported elicitation/sampling/roots surfaces — the capability fields in `pkg/client/definition.go` (find with `grep -n 'Sampling\|Roots\|Elicitation' pkg/client/definition.go`) and the handler types in `pkg/client/sampling.go` / `roots.go` — add one sentence to the existing doc comments: "The server-initiated form of this feature is deprecated in spec revision 2026-07-28 (SEP-2577) and served via multi-round-trip requests there; it remains fully functional against peers negotiating ≤2025-11-25." Do **not** add Go `// Deprecated:` markers — harness callers legitimately use these and must not get lint noise.

**Step 5: Commit**

```bash
git add pkg/transport/streamablehttp/ pkg/client/
git commit -m "test(streamablehttp): elicitation over MRTR; document SEP-2577 deprecation"
```

### Task 9: Protocol-version matrix

One table test proving which revision each transport/mode lands on, end to end through `pkg/client`. (Design §8 said "through pkg/harness"; `pkg/harness` has no real-server harness — its coverage is fake-based unit tests — so the matrix lives here, at the highest layer that has fixture plumbing. Revisions 2025-06-18/2025-03-26 have no fixture that forces them; the SDK only lands on them against servers pinned there, and building a pinning knob nobody needs fails YAGNI — say so in a comment.)

**Files:**
- Create: `pkg/client/protocol_matrix_integration_test.go` (package `client_test`, `//go:build integration`)

**Step 1: Determine the SSE expectation empirically**

The SSE handler is served by a v1.7.0 SDK server whose legacy initialize caps at `2025-11-25`; whether SSE lands there or lower is an SDK detail. Before writing the assertion, run a one-off probe (throwaway test or `go run` snippet): connect `pkg/transport/sse` to `mcptest.NewSSEHandler(Config{})` and print `c.Catalog().ProtocolVersion`. Pin the observed value in the matrix with a comment citing this step. It must be one of `2025-11-25`/`2025-06-18`/`2025-03-26`/`2024-11-05`; anything else is a bug to investigate.

**Step 2: Write the matrix test**

```go
//go:build integration

// The protocol-version matrix: which spec revision each transport/mode
// negotiates, proven end to end through pkg/client against real fixture
// servers. Revisions 2025-06-18 and 2025-03-26 are reachable only against
// servers pinned there; no fixture pins them, deliberately — the SDK's own
// negotiation tests cover the middle of the range.
package client_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/pkg/client"
	"github.com/looprig/mcp/pkg/transport/sse"
	"github.com/looprig/mcp/pkg/transport/streamablehttp"
	"github.com/looprig/mcp/pkg/transport/stdio"
)

func TestProtocolVersionMatrix(t *testing.T) {
	t.Parallel()

	newHTTP := func(t *testing.T, cfg mcptest.Config) client.TransportFactory {
		t.Helper()
		h, err := mcptest.NewHTTPHandler(cfg)
		if err != nil {
			t.Fatalf("NewHTTPHandler() error = %v", err)
		}
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		f, err := streamablehttp.New(streamablehttp.Config{Endpoint: srv.URL})
		if err != nil {
			t.Fatalf("streamablehttp.New() error = %v", err)
		}
		return f
	}

	tests := []struct {
		name        string
		transport   func(t *testing.T) client.TransportFactory
		wantVersion string
	}{
		{
			name: "stdio negotiates the latest revision",
			transport: func(t *testing.T) client.TransportFactory {
				f, err := stdio.New(stdio.Config{Command: mcptest.BuildFixture(t)})
				if err != nil {
					t.Fatalf("stdio.New() error = %v", err)
				}
				return f
			},
			wantVersion: "2026-07-28",
		},
		{
			name:        "stateless streamable HTTP negotiates 2026-07-28",
			transport:   func(t *testing.T) client.TransportFactory { return newHTTP(t, mcptest.Config{Stateless: true}) },
			wantVersion: "2026-07-28",
		},
		{
			name:        "stateful streamable HTTP caps at 2025-11-25",
			transport:   func(t *testing.T) client.TransportFactory { return newHTTP(t, mcptest.Config{}) },
			wantVersion: "2025-11-25",
		},
		{
			name: "legacy SSE lands on a legacy revision",
			transport: func(t *testing.T) client.TransportFactory {
				h, err := mcptest.NewSSEHandler(mcptest.Config{})
				if err != nil {
					t.Fatalf("NewSSEHandler() error = %v", err)
				}
				srv := httptest.NewServer(h)
				t.Cleanup(srv.Close)
				f, err := sse.New(sse.Config{Endpoint: srv.URL})
				if err != nil {
					t.Fatalf("sse.New() error = %v", err)
				}
				return f
			},
			wantVersion: "PINNED-IN-STEP-1", // replace with the probed value + comment
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := client.Connect(testCtx(t), client.Definition{Name: "fixture", Transport: tt.transport(t)}, client.Handlers{})
			if err != nil {
				t.Fatalf("client.Connect() error = %v", err)
			}
			t.Cleanup(func() { _ = c.Close(testCtx(t)) })

			cat := c.Catalog()
			if cat.ProtocolVersion != tt.wantVersion {
				t.Errorf("ProtocolVersion = %q, want %q", cat.ProtocolVersion, tt.wantVersion)
			}
			if len(cat.Tools) == 0 {
				t.Fatal("no tools discovered")
			}
			args, err := json.Marshal(mcptest.EchoInput{Text: "matrix"})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			res, err := c.CallTool(testCtx(t), mcptest.ToolEcho, args, client.CallOpts{})
			if err != nil {
				t.Fatalf("CallTool(echo) error = %v", err)
			}
			if res.IsError {
				t.Errorf("CallTool(echo) tool error: %+v", res.Content)
			}
		})
	}
}
```

Mechanical adjustments allowed: the `sse.Config` field names (read `pkg/transport/sse/sse.go:101` first — the endpoint field may be named differently), the endpoint path suffix, and the SSE `wantVersion`.

**Step 3: Run**

Run: `go test -tags integration -race ./pkg/client/ -run TestProtocolVersionMatrix -v`
Expected: PASS, four subtests.

**Step 4: Commit**

```bash
git add pkg/client/
git commit -m "test(client): protocol-version matrix across stdio, HTTP (both modes) and SSE"
```

---

## Phase 5 — Auth

### Task 10: Verify OAuth persistence needs nothing from v1.7.0

The design assumed we would adopt the SDK's new `NewTokenSource`/`InitialTokenSource` hooks. Planning found `pkg/auth` never uses SDK auth: it is a hand-rolled provider whose `token()` path (`pkg/auth/oauth.go:401-443`) already loads from the `TokenStore`, refreshes with the stored refresh token, and stores results back — persistence across restarts already exists wherever the application supplies a persistent `TokenStore`.

**Step 1: Verify, don't assume**

Read `pkg/auth/oauth.go:387-460` and confirm: (a) a valid stored token is used without a browser flow; (b) a refreshed token is written back to the store. Then check the tests: `grep -n 'restart\|second provider\|NewOAuthProvider' pkg/auth/oauth_test.go | head`.

**Step 2: Add the restart test only if missing**

If no existing test builds a **second** `OAuthProvider` over the same store and asserts no re-authorization happens, add one to `pkg/auth/oauth_test.go` following that file's existing fake-endpoint structure: provider A completes a token exchange into a shared `MemoryStore`; provider B with the same config and store serves `Headers(ctx)` without hitting the authorization endpoint (assert via the fake's request counter, the same way existing tests count endpoint hits). If such a test already exists, this task is a no-op — state that in the commit message of Task 11 and move on.

**Step 3: Run and commit (only if a test was added)**

```bash
go test -race ./pkg/auth/ -v
git add pkg/auth/
git commit -m "test(auth): tokens persist across provider restarts via the shared store"
```

---

## Phase 6 — Close out

### Task 11: Full verification, docs, release note

**Step 1: Full suite — evidence before claims** (@superpowers:verification-before-completion)

```bash
go test -race ./...
go test -tags integration -race ./...
make secure
```

Expected: all PASS, `make secure` clean. Paste real output in the report; no success claims without it.

**Step 2: Fuzz spot-check**

The protocol layer's inputs changed shape. List targets: `grep -rn 'func Fuzz' internal/ pkg/ --include='*.go' | grep -v vendor`. Run each protocol-adjacent target for 30s, e.g.:

```bash
go test -race ./internal/protocol/ -run '^$' -fuzz FuzzXxx -fuzztime 30s
```

(One `-fuzz` per invocation; repeat per target. New crashers land in `testdata/fuzz/` — triage before committing anything.)

**Step 3: README**

If `README.md` names an SDK version or protocol revisions (`grep -n -i 'sdk\|protocol\|2025-\|2024-' README.md`), update to v1.7.0 and "spec revisions 2024-11-05 through 2026-07-28".

**Step 4: Final commit and branch finish**

```bash
git add -A
git commit -m "docs: note SDK v1.7.0 and supported protocol revisions"
```

Then use @superpowers:finishing-a-development-branch. Release tagging follows the looprig workspace's `repositories.mk` managed-tag flow — coordinate at the workspace root before tagging; `tests/` and `kosa/` consume this module and will need version bumps after a tag exists (outside this repo; flag it, don't do it silently).

---

## Risks / watch items

- **Error-code shift (−32602):** `pkg/client/errors.go` classification and its tests may assert the old code 0. Fix the classifier or assertions per decision rule 1 — the failure class should not change, only the numeric code.
- **Stdio tests silently migrating to 2026-07-28:** after Task 1 every stdio integration test runs the new protocol. That is coverage, not a bug — but a sampling/roots stdio test failing there means the deprecation window behaves differently than the release notes claim; investigate before "fixing."
- **`subscriptions/listen` not opening:** the SDK opens it only when list-changed handlers are registered at connect; our conn layer registers `OnListChanged` — if Task 7 sees no events, the bug is in SDK-option construction order in `internal/httpconn`/`internal/protocol`, plus the Task 1 `NotificationSubscriptions` value.
- **staticcheck SA1019** on deprecated SDK fields: per-use `//lint:ignore` with the SEP-2577 justification; `make secure` stays clean with no blanket disables.
- **httptest resurrection race (Task 6):** re-listening on a just-closed port can flake with `EADDRINUSE` on some kernels; if it does, retry the `net.Listen` in a short loop inside the test rather than weakening assertions.
