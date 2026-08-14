.PHONY: test test-integration fmt fmt-check lint vuln secure

# Module's own package dirs (go list ./... stops at nested module boundaries).
# GO_DIRS scopes gosec, which takes package dirs. Never hand GO_DIRS to gofmt:
# gofmt recurses into directory operands, and for a module with a root package
# GO_DIRS contains the module root, so gofmt would walk the entire tree —
# including the nested .worktrees/ checkouts, which are separate modules. Use
# GO_FILES for gofmt: it expands to each package dir's own .go files (including
# platform-specific ones go list omits for the host) without descending.
GO_DIRS = $(shell go list -f '{{.Dir}}' ./... 2>/dev/null)
GO_FILES = $(foreach dir,$(GO_DIRS),$(wildcard $(dir)/*.go))

# This module does not vendor. go.mod pins exact versions and go.sum verifies
# their content hashes, which is what makes a build reproducible; a vendor tree
# adds only offline builds and source-level dependency diffs. It also actively
# misleads: a stale vendor/ is ignored under a go.work but silently satisfies a
# GOWORK=off build, so standalone verification tests the vendored copy rather
# than the version go.mod actually pins — which is precisely what standalone
# verification exists to check.

test:
	@if [ -n "$(GO_DIRS)" ]; then go test -race ./...; fi

# The tagged tests: real subprocesses, real pipes, real MCP servers. Kept out of
# `test` (and therefore out of `secure`) on purpose — they exec children and are
# slower than a unit run, and the gate developers hit on every commit should
# stay fast. CI runs both: `make secure test` and `make test-integration`.
#
# -count=1 defeats the test cache: a cached pass here would be a claim about a
# process that was never started.
test-integration:
	@if [ -n "$(GO_DIRS)" ]; then go test -tags integration -race -count=1 ./...; fi

# Format the whole module in place.
fmt:
	@if [ -n "$(GO_DIRS)" ]; then gofmt -w $(GO_FILES); fi

# Fail (non-zero exit) if any tracked Go file is not gofmt-clean. Wired into lint.
fmt-check:
	@if [ -n "$(GO_DIRS)" ]; then \
		unformatted=$$(gofmt -l $(GO_FILES)); \
		if [ -n "$$unformatted" ]; then \
			echo "gofmt needed (run 'make fmt'):"; echo "$$unformatted"; exit 1; \
		fi; \
	fi

lint: fmt-check
	@if [ -n "$(GO_DIRS)" ]; then go vet ./...; fi
	@if [ -n "$(GO_DIRS)" ]; then go tool staticcheck ./...; fi
	# gosec is NOT module-aware: its ./... is a filesystem walk that descends into
	# any nested .worktrees/ checkouts, which are separate modules. Scope it to THIS
	# module's package dirs via GO_DIRS.
	@if [ -n "$(GO_DIRS)" ]; then go tool gosec $(GO_DIRS); fi

vuln:
	go mod verify
	@if [ -n "$(GO_DIRS)" ]; then go tool govulncheck ./...; fi

secure: lint vuln
