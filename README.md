# mcp

MCP client for Looprig: protocol-neutral client (`pkg/client`), auth (`pkg/auth`), transports (`pkg/transport/{stdio,streamablehttp,sse}`), and the optional Harness adapter (`pkg/harness`). Wraps the official go-sdk without leaking its types.

Design doc: `../harness/docs/plans/2026-07-16-mcp-client-module-design.md`

## Testing

| Command | What it runs |
| --- | --- |
| `make test` | Unit tests. No subprocesses, no network. |
| `make test-integration` | The `integration`-tagged tests: real child processes, real pipes, real MCP servers. |
| `make secure` | gofmt check, vet, staticcheck, gosec, go mod verify, govulncheck. |

Anything that crosses a process boundary is tagged `//go:build integration` and lives in a `*_integration_test.go` file, so it is excluded from the default `go test ./...` run. `make secure` deliberately does not depend on `test-integration`: the pre-commit gate stays fast, and CI runs both.
