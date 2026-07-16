.PHONY: test fmt fmt-check vendor vendor-check lint vuln secure

# Module's own package dirs, excluding vendor/ and the nested .worktrees/ modules
# (go list ./... stops at nested module boundaries and skips vendor). Empty while
# the module has no Go packages yet; targets tolerate that.
GO_DIRS = $(shell go list -f '{{.Dir}}' ./... 2>/dev/null)

# Build from the vendored dependency tree: offline, reproducible, and auditable.
# Go auto-selects -mod=vendor when vendor/ is present; we export it explicitly so
# a stray global GOFLAGS (e.g. -mod=mod) can't silently switch the build off the
# vendored tree. Do NOT use -mod=readonly here — it ignores vendor/ entirely.
export GOFLAGS := -mod=vendor

test:
	@if [ -n "$(GO_DIRS)" ]; then go test -race ./...; fi

# Format the whole module in place.
fmt:
	@if [ -n "$(GO_DIRS)" ]; then gofmt -w $(GO_DIRS); fi

# Fail (non-zero exit) if any tracked Go file is not gofmt-clean. Wired into lint.
fmt-check:
	@if [ -n "$(GO_DIRS)" ]; then \
		unformatted=$$(gofmt -l $(GO_DIRS)); \
		if [ -n "$$unformatted" ]; then \
			echo "gofmt needed (run 'make fmt'):"; echo "$$unformatted"; exit 1; \
		fi; \
	fi

# Refresh the auditable dependency tree.
vendor:
	go mod vendor
	$(MAKE) vendor-check

vendor-check:
	@metadata=$$(find vendor -name .git -print); \
	if [ -n "$$metadata" ]; then \
		echo "forbidden VCS metadata in vendor/:"; echo "$$metadata"; exit 1; \
	fi

lint: fmt-check vendor-check
	@if [ -n "$(GO_DIRS)" ]; then go vet ./...; fi
	@if [ -n "$(GO_DIRS)" ]; then go tool staticcheck ./...; fi
	# gosec is NOT module-aware: its ./... is a filesystem walk that descends into
	# vendor/ and any nested .worktrees/ checkouts. Scope it to THIS module's
	# package dirs via GO_DIRS (the same go-list idiom fmt/fmt-check use).
	@if [ -n "$(GO_DIRS)" ]; then go tool gosec $(GO_DIRS); fi

vuln:
	go mod verify
	@if [ -n "$(GO_DIRS)" ]; then go tool govulncheck ./...; fi

secure: lint vuln
