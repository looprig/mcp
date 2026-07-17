// Tests for the shared HTTP layer's own values: the wire limits every transport
// built on this package normalizes its caller's bounds through.

package httpsec

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

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

// TestVetTransportBoundsTheDial pins Timeouts.Dial on the supplied-client path.
//
// It was applied only by DefaultTransport, so a caller who supplied a transport
// — the very path VetTransport exists to serve — got no dial bound at all when
// their transport had no DialContext, which is the usual shape for someone
// cloning a transport just to pin a CA. The doc said the timeouts always
// applied; for Dial it was true of one path out of two.
//
// The timeout VALUE is not observable through a DialContext func, so this
// asserts the two things that are: that a bound is installed where there was
// none, and that a caller's own dialer is left alone.
func TestVetTransportBoundsTheDial(t *testing.T) {
	t.Parallel()
	timeouts := Timeouts{Dial: time.Second, TLSHandshake: time.Second, ResponseHeader: time.Second, IdleConn: time.Second}

	t.Run("a nil DialContext is filled in", func(t *testing.T) {
		t.Parallel()
		got, err := VetTransport(&http.Client{Transport: &http.Transport{}}, timeouts)
		if err != nil {
			t.Fatalf("VetTransport() error = %v", err)
		}
		if got.DialContext == nil {
			t.Fatal("DialContext is nil: the connect is bounded only by the OS TCP stack")
		}
	})

	t.Run("a caller's own dialer is kept", func(t *testing.T) {
		t.Parallel()
		called := false
		mine := func(ctx context.Context, network, addr string) (net.Conn, error) {
			called = true
			return nil, errors.New("mine")
		}
		got, err := VetTransport(&http.Client{Transport: &http.Transport{DialContext: mine}}, timeouts)
		if err != nil {
			t.Fatalf("VetTransport() error = %v", err)
		}
		if _, err := got.DialContext(context.Background(), "tcp", "example.invalid:80"); err == nil {
			t.Fatal("DialContext() error = nil, want the caller's dialer's error")
		}
		if !called {
			t.Error("the caller's DialContext was replaced; a supplied dialer is theirs to own")
		}
	})
}
