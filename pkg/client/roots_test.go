package client

import (
	"context"
	"errors"
	"testing"

	"github.com/looprig/mcp/internal/protocol"
)

// recordingRoots is a provider a test can script and interrogate.
type recordingRoots struct {
	roots []Root
	err   error
}

func (r *recordingRoots) Roots(context.Context) ([]Root, error) {
	return r.roots, r.err
}

// TestRootsCapabilityIsGated is the gate at Connect, asserted on what the
// transport actually received. A provider with no request must install the
// callback but not advertise; a request with no provider must not connect.
func TestRootsCapabilityIsGated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		request       bool
		provider      RootsProvider
		wantErr       bool
		wantAdvertise bool
		wantCallback  bool
	}{
		{
			name:          "requested and provided is advertised",
			request:       true,
			provider:      &recordingRoots{roots: []Root{{URI: "file:///work"}}},
			wantAdvertise: true,
			wantCallback:  true,
		},
		{
			name:     "requested with no provider is a configuration error",
			request:  true,
			provider: nil,
			wantErr:  true,
		},
		{
			name:          "provider with no request is not advertised",
			request:       false,
			provider:      &recordingRoots{},
			wantAdvertise: false,
			wantCallback:  true,
		},
		{
			name:          "neither is not advertised",
			request:       false,
			provider:      nil,
			wantAdvertise: false,
			wantCallback:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tr := newFakeTransport(okConn())
			def := okDefinition(tr)
			def.Capabilities.Roots = tt.request

			c, err := Connect(context.Background(), def, Handlers{Roots: tt.provider})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Connect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				var e *Error
				if !errors.As(err, &e) || e.Class != FailureInvalidConfig {
					t.Fatalf("Connect() error = %v, want class FailureInvalidConfig", err)
				}
				return
			}
			t.Cleanup(func() { _ = c.Close(context.Background()) })

			cfg := tr.lastConfig()
			if got := cfg.Capabilities.Roots; got != tt.wantAdvertise {
				t.Errorf("transport received Capabilities.Roots = %v, want %v", got, tt.wantAdvertise)
			}
			if got := cfg.OnRoots != nil; got != tt.wantCallback {
				t.Errorf("transport received OnRoots != nil = %v, want %v", got, tt.wantCallback)
			}
		})
	}
}

// TestRootsAdapterReachesTheProvider drives the callback the client actually
// installed, so a client that wired nothing fails here rather than passing on a
// technicality. This is the pkg/client half of Fix #4a; the SDK round-trip is
// proven in internal/protocol's TestRootsRoundTrip.
func TestRootsAdapterReachesTheProvider(t *testing.T) {
	t.Parallel()

	p := &recordingRoots{roots: []Root{{URI: "file:///a", Name: "a"}, {URI: "file:///b", Name: "b"}}}
	tr := newFakeTransport(okConn())
	def := okDefinition(tr)
	def.Capabilities.Roots = true

	c, err := Connect(context.Background(), def, Handlers{Roots: p})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	onRoots := tr.lastConfig().OnRoots
	if onRoots == nil {
		t.Fatal("the client installed no OnRoots callback, so no server request can reach the provider")
	}
	got, err := onRoots(context.Background())
	if err != nil {
		t.Fatalf("OnRoots() error = %v", err)
	}
	want := []protocol.Root{{URI: "file:///a", Name: "a"}, {URI: "file:///b", Name: "b"}}
	if len(got) != len(want) {
		t.Fatalf("OnRoots() returned %d roots, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("OnRoots()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestRootsProviderErrorPropagates: an erroring provider surfaces its error to
// the caller of the callback (which internal/protocol turns into a failed
// handshake), rather than being swallowed into an empty root set.
func TestRootsProviderErrorPropagates(t *testing.T) {
	t.Parallel()

	p := &recordingRoots{err: errors.New("no workspace")}
	tr := newFakeTransport(okConn())
	def := okDefinition(tr)
	def.Capabilities.Roots = true

	c, err := Connect(context.Background(), def, Handlers{Roots: p})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	if _, err := tr.lastConfig().OnRoots(context.Background()); err == nil {
		t.Fatal("OnRoots() error = nil, want the provider's error propagated")
	}
}
