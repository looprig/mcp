package protocol_test

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
)

// initBounds is a generous bound set for tests that are not about bounding.
func initBounds() protocol.Bounds {
	return protocol.Bounds{
		MaxSchemaBytes:     1 << 20,
		MaxSchemaDepth:     32,
		MaxTextBytes:       1 << 16,
		MaxStructuredBytes: 1 << 20,
		MaxBinaryItemBytes: 1 << 20,
		MaxBinaryItems:     8,
	}
}

// tightTextBounds is initBounds with MaxTextBytes cut down to max, so a
// table case can exercise truncation without special-casing the shared
// assertion.
func tightTextBounds(max int) protocol.Bounds {
	b := initBounds()
	b.MaxTextBytes = max
	return b
}

func TestFromSDKInitializeResult(t *testing.T) {
	t.Parallel()

	// truncatedInstructions is what a 4096-byte instructions string becomes
	// once bounded to 16 bytes, computed via the same TruncateText the
	// conversion itself uses rather than hand-derived, so the case can't
	// silently drift from limits' truncation-marker behavior.
	truncatedInstructions, _ := limits.TruncateText(strings.Repeat("a", 4096), 16)

	tests := []struct {
		name    string
		in      *mcp.InitializeResult
		bounds  protocol.Bounds
		want    protocol.InitializeResult
		wantErr bool
	}{
		{
			name:    "nil result is rejected",
			in:      nil,
			bounds:  initBounds(),
			wantErr: true,
		},
		{
			name: "missing protocol version is rejected",
			in: &mcp.InitializeResult{
				ServerInfo: &mcp.Implementation{Name: "srv", Version: "1"},
			},
			bounds:  initBounds(),
			wantErr: true,
		},
		{
			name: "full result converts",
			in: &mcp.InitializeResult{
				ProtocolVersion: "2025-06-18",
				Instructions:    "be nice",
				ServerInfo:      &mcp.Implementation{Name: "srv", Version: "1.2.3", Title: "Server"},
				Capabilities: &mcp.ServerCapabilities{
					Tools:     &mcp.ToolCapabilities{},
					Prompts:   &mcp.PromptCapabilities{},
					Resources: &mcp.ResourceCapabilities{Subscribe: true},
					//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
					Logging:     &mcp.LoggingCapabilities{},
					Completions: &mcp.CompletionCapabilities{},
				},
			},
			bounds: initBounds(),
			want: protocol.InitializeResult{
				Server:          protocol.ServerIdentity{Name: "srv", Version: "1.2.3", Title: "Server"},
				ProtocolVersion: "2025-06-18",
				Instructions:    "be nice",
				Capabilities: protocol.ServerCapabilities{
					Tools:              true,
					Prompts:            true,
					Resources:          true,
					ResourcesSubscribe: true,
					Logging:            true,
					Completions:        true,
				},
			},
		},
		{
			name: "nil capabilities means none advertised",
			in: &mcp.InitializeResult{
				ProtocolVersion: "2025-06-18",
				ServerInfo:      &mcp.Implementation{Name: "srv"},
			},
			bounds: initBounds(),
			want: protocol.InitializeResult{
				Server:          protocol.ServerIdentity{Name: "srv"},
				ProtocolVersion: "2025-06-18",
			},
		},
		{
			name: "nil server info yields the zero identity",
			in: &mcp.InitializeResult{
				ProtocolVersion: "2025-06-18",
			},
			bounds: initBounds(),
			want: protocol.InitializeResult{
				ProtocolVersion: "2025-06-18",
			},
		},
		{
			name: "resources without subscribe",
			in: &mcp.InitializeResult{
				ProtocolVersion: "v",
				Capabilities:    &mcp.ServerCapabilities{Resources: &mcp.ResourceCapabilities{}},
			},
			bounds: initBounds(),
			want: protocol.InitializeResult{
				ProtocolVersion: "v",
				Capabilities:    protocol.ServerCapabilities{Resources: true},
			},
		},
		{
			// The SDK normalizes a server/discover response into this same
			// shape (see mcp.Client.discover): nil capabilities and a nil
			// ServerInfo are both legal when the server omits them.
			name: "discover-sourced result with no capabilities or server info",
			in: &mcp.InitializeResult{
				ProtocolVersion: "2026-07-28",
			},
			bounds: initBounds(),
			want: protocol.InitializeResult{
				ProtocolVersion: "2026-07-28",
			},
		},
		{
			name: "discover-sourced instructions are truncated like any other",
			in: &mcp.InitializeResult{
				ProtocolVersion: "2026-07-28",
				Instructions:    strings.Repeat("a", 4096),
			},
			bounds: tightTextBounds(16),
			want: protocol.InitializeResult{
				ProtocolVersion: "2026-07-28",
				Instructions:    truncatedInstructions,
			},
		},
		{
			name: "empty version from discover is still rejected",
			in: &mcp.InitializeResult{
				Instructions: "be nice",
				Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
				ServerInfo:   &mcp.Implementation{Name: "srv", Version: "1"},
			},
			bounds:  initBounds(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKInitializeResult(tt.in, tt.bounds)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromSDKInitializeResult() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Errorf("FromSDKInitializeResult() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestFromSDKInitializeResultIsBounded proves a hostile server cannot make the
// client retain unbounded text from the handshake. Everything here survives for
// the life of the connection and is rendered freely afterwards, so every
// server-supplied string must be capped — not just the obviously long one.
func TestFromSDKInitializeResultIsBounded(t *testing.T) {
	t.Parallel()

	const max = 16
	b := initBounds()
	b.MaxTextBytes = max
	huge := strings.Repeat("a", 4096)

	got, err := protocol.FromSDKInitializeResult(&mcp.InitializeResult{
		ProtocolVersion: huge,
		Instructions:    huge,
		ServerInfo:      &mcp.Implementation{Name: huge, Version: huge, Title: huge},
	}, b)
	if err != nil {
		t.Fatalf("FromSDKInitializeResult() error = %v", err)
	}

	for _, f := range []struct {
		name  string
		value string
	}{
		{"Instructions", got.Instructions},
		{"ProtocolVersion", string(got.ProtocolVersion)},
		{"Server.Name", got.Server.Name},
		{"Server.Version", got.Server.Version},
		{"Server.Title", got.Server.Title},
	} {
		if len(f.value) > max {
			t.Errorf("%s = %d bytes, want <= %d", f.name, len(f.value), max)
		}
	}
}
