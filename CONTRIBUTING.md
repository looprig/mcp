# Contributing to looprig/mcp

Thanks for considering a contribution. `mcp` is part of a multi-module Go
ecosystem; this file is the short guide for working in *this* repository.

## Before you write code

1. Read [`CLAUDE.md`](CLAUDE.md). It is the authoritative source for the
   design, security, dependency, build, and code rules this module follows.
   PRs that contradict it will be asked to change.
2. Skim [`README.md`](README.md) for the module's shape and how it wraps
   the MCP Go SDK.
3. Open an issue for anything non-trivial so we can agree on direction
   before you spend the time.

## Design and security rules (the short version)

- **Strict typing everywhere.** No `any`/`interface{}` past a serialization
  boundary. Named types (`type UserID string`) over bare primitives when the
  value has domain meaning. All domain concepts are typed structs, never
  `map[string]interface{}`.
- **All errors are typed.** Sentinel or typed errors for public failures
  callers classify with `errors.As`; wrapped ordinary errors for contextual
  failures callers only report. Never swallow with `_`.
- **Security is first-class.** Validate at every boundary — HTTP, CLI args,
  env vars, files, and MCP server responses are all untrusted until
  validated. Authenticate before authorize, authorize before act. Fail
  secure: on error or ambiguity, deny by default. Never log secrets,
  tokens, or PII. Use `crypto/rand` for anything security-sensitive.
- **MCP SDK types stay behind the boundary.** `github.com/modelcontextprotocol/go-sdk`
  types must never leak from any `pkg/...` exported API; they stay behind
  `pkg/client` / `internal/protocol`.
- **Prefer stdlib.** External packages require explicit user approval in
  the conversation that adds them. Once approved, the package is added to
  the approved list in `CLAUDE.md` with its rationale — that list is
  exhaustive. Never `go get` without that approval.
- **Interface Segregation + Liskov Substitution.** Small, focused
  interfaces defined at the consumer; never force a caller to depend on
  methods it doesn't use. Every implementation of an interface honors the
  full contract.

## Build, test, and secure

Run these before pushing. CI runs the same.

```sh
make fmt              # gofmt the whole module in place
make test             # go test -race ./...
make secure           # lint (fmt-check + vet + staticcheck + gosec)
                      # + vuln (go mod verify + govulncheck)
```

Build with `CGO_ENABLED=0 go build -trimpath` so binaries never leak local
paths.

`make test-integration` runs the tests tagged `//go:build integration`:
real subprocesses, real pipes, real MCP servers. It's kept out of `make
test` (and therefore out of `make secure`) on purpose — those tests exec
child processes and are slower than a unit run, and the gate developers
hit on every commit should stay fast. CI runs both `make secure test` and
`make test-integration`; run the integration target yourself whenever you
touch a transport (stdio, HTTP) or anything that crosses a process
boundary.

Fuzz any parser of external input: `go test -fuzz=FuzzXxx ./pkg -fuzztime=30s`.

**Dependencies are pinned, not vendored.** `go.mod` pins exact versions and
`go.sum` verifies their content hashes, which is what makes a build
reproducible. This module deliberately has no `vendor/`: a vendor tree is
ignored under a `go.work` but silently satisfies a `GOWORK=off` build, so a
stale one lets standalone verification pass against the vendored copy rather
than the version `go.mod` actually pins — defeating the purpose of verifying
standalone. Run `GOWORK=off go test ./...` to check this module against its
real pinned dependencies. Do not run `go get` casually.

## Tests

- **Table-driven tests, mandatory** when several cases share setup and
  assertion shape. Each subtest calls `t.Parallel()`. Cover the happy path,
  boundary values (zero/empty/max), error cases (invalid/missing/wrong
  type), and domain edge cases (malformed server responses, closed
  transports, cancelled contexts).
- A test that passes without `-race` but fails with it is **not passing**.
- Integration tests live in `*_integration_test.go` files, tagged
  `//go:build integration`, and are excluded from the default
  `go test ./...` run — see "Build, test, and secure" above.
- Never assume a test framework or script. The `Makefile` is the source of
  truth; if you change how tests run, update it.

## Pull requests

- Branch from `main`, name the branch something descriptive.
- One logical change per PR.
- Write a clear description: what, why, the design alternative you
  rejected, and how you verified. `make secure` output is welcome in the
  PR body.
- Don't force-push after review; add commits and let the reviewer squash.
- Don't commit secrets, tokens, or credentials. Don't add a new external
  dependency without prior approval (see `CLAUDE.md`).
- Don't update `CLAUDE.md`, `Makefile`, or `go.mod` unless the change is
  the point of the PR.

## Code of conduct

Be excellent to each other. Discussions stay technical and respectful;
personal attacks, harassment, and discrimination are not welcome.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0, as described in [`LICENSE`](LICENSE).
