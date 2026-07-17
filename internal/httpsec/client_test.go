// Tests for the shared HTTP layer's own values: the wire limits every transport
// built on this package normalizes its caller's bounds through.

package httpsec

import (
	"testing"

	"github.com/looprig/mcp/internal/protocol"
)

func TestNewWireLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		in            protocol.WireLimits
		wantBody      int
		wantFrame     int
		wantDefaulted bool
	}{
		{
			name:      "positive values are kept",
			in:        protocol.WireLimits{MaxBodyBytes: 10, MaxFrameBytes: 20},
			wantBody:  10,
			wantFrame: 20,
		},
		{
			name:      "zero takes the default",
			in:        protocol.WireLimits{},
			wantBody:  DefaultMaxBodyBytes,
			wantFrame: DefaultMaxFrameBytes,
		},
		{
			name:      "negative is not unbounded",
			in:        protocol.WireLimits{MaxBodyBytes: -1, MaxFrameBytes: -1},
			wantBody:  DefaultMaxBodyBytes,
			wantFrame: DefaultMaxFrameBytes,
		},
		{
			name:      "one set, one not",
			in:        protocol.WireLimits{MaxBodyBytes: 99},
			wantBody:  99,
			wantFrame: DefaultMaxFrameBytes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NewWireLimits(tt.in)
			if got.MaxBody != tt.wantBody {
				t.Errorf("MaxBody = %d, want %d", got.MaxBody, tt.wantBody)
			}
			if got.MaxFrame != tt.wantFrame {
				t.Errorf("MaxFrame = %d, want %d", got.MaxFrame, tt.wantFrame)
			}
		})
	}
}
