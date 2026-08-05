//go:build integration

// The protocol-version matrix: which spec revision each transport/mode
// negotiates, proven end to end through pkg/client against real fixture
// servers. Revisions 2025-06-18 and 2025-03-26 are reachable only against
// servers pinned there; no fixture pins them, deliberately — the SDK's own
// negotiation tests cover the middle of the range, and building a pinning
// knob nobody in this module needs would fail YAGNI.
package client_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/looprig/mcp/pkg/client"
	"github.com/looprig/mcp/pkg/transport/sse"
	"github.com/looprig/mcp/pkg/transport/stdio"
	"github.com/looprig/mcp/pkg/transport/streamablehttp"
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
		compat      client.Profile
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
			name: "legacy SSE also negotiates 2026-07-28",
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
			// Empirically probed (Task 9 step 1): a throwaway test connecting
			// pkg/transport/sse to mcptest.NewSSEHandler(Config{}) and printing
			// c.Catalog().ProtocolVersion consistently printed "2026-07-28", not
			// a legacy revision as this table originally assumed. That is not a
			// bug: the SDK's version cap for 2026-07-28 lives on
			// StreamableServerTransport.SupportsProtocolVersion (streamable.go),
			// which restricts it to Stateless mode. SSEServerTransport
			// (sse.go) never implements ProtocolVersionSupporter at all, and
			// per filterSupportedVersions' own doc comment (server.go),
			// a transport that doesn't implement that interface has every
			// SDK-supported version, including 2026-07-28, offered to the
			// client unfiltered. The legacy SSE wire framing (hanging GET +
			// endpoint event + POSTs) is transport-level only; it carries
			// server/discover and 2026-07-28 semantics exactly like any other
			// transport once negotiation isn't capped. So SSE lands on the
			// newest revision, same as stdio and stateless HTTP — the
			// "legacy" in its name describes the wire framing, not the
			// protocol version it is capable of speaking.
			compat:      client.ProfileLegacy, // required: SSE is compatibility-only under ProfileDefault.
			wantVersion: "2026-07-28",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := client.Connect(testCtx(t), client.Definition{Name: "fixture", Transport: tt.transport(t), Compat: tt.compat}, client.Handlers{})
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
