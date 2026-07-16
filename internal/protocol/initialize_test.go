package protocol_test

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

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

func TestFromSDKInitializeResult(t *testing.T) {
	t.Parallel()

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
					Tools:       &mcp.ToolCapabilities{},
					Prompts:     &mcp.PromptCapabilities{},
					Resources:   &mcp.ResourceCapabilities{Subscribe: true},
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
