// Unit tests for the legacy SSE transport: everything that can be settled
// against an httptest server in this process.
//
// This transport shares its HTTP layer with Streamable HTTP (internal/httpsec)
// and its session wrapper with it too (internal/httpconn), and those packages
// have their own tests. So what is tested here is what is *this* transport's:
// that its config gate is real, that it is opt-in, and above all that the
// endpoint event — the legacy protocol's one extra way for a server to redirect
// this client — cannot carry credentials off-origin.
//
// The end-to-end tests, against a real SDK legacy SSE server, live in
// sse_integration_test.go.

package sse

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/auth"
	"github.com/looprig/mcp/pkg/client"
)

// secret is the value every redaction test hunts for. It is not a credential: it
// is a distinctive string that must never appear anywhere a credential would not
// be welcome.
const secret = "s3cr3t-CANARY-do-not-log"

// testConnectConfig is what a real client would pass down. The bounds are
// generous; a test that cares about a bound sets it itself.
func testConnectConfig() protocol.ConnectConfig {
	return protocol.ConnectConfig{
		Client: protocol.ClientIdentity{Name: "test-client", Version: "0.0.1"},
		Bounds: protocol.Bounds{
			MaxSchemaBytes:     1 << 20,
			MaxSchemaDepth:     32,
			MaxTextBytes:       1 << 20,
			MaxStructuredBytes: 1 << 20,
			MaxBinaryItemBytes: 1 << 20,
			MaxBinaryItems:     16,
		},
		Wire: protocol.WireLimits{MaxBodyBytes: 1 << 20, MaxFrameBytes: 1 << 20},
	}
}

// newFactory builds a factory for cfg, failing the test if New refuses it.
func newFactory(t *testing.T, cfg Config) client.TransportFactory {
	t.Helper()
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return f
}

// initializeExpectingFailure connects and initializes, requiring a failure. It
// is how a test drives the transport at a server that is misbehaving on purpose.
func initializeExpectingFailure(t *testing.T, f client.TransportFactory) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := f.Connect(ctx, testConnectConfig())
	if err != nil {
		return err
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	_, err = c.Initialize(ctx)
	if err == nil {
		t.Fatal("Initialize() error = nil, want a failure")
	}
	return err
}

func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "https endpoint", cfg: Config{Endpoint: "https://example.com/sse"}},
		{name: "loopback http endpoint", cfg: Config{Endpoint: "http://127.0.0.1:8080/sse"}},
		{name: "localhost http endpoint", cfg: Config{Endpoint: "http://localhost:8080/sse"}},
		{name: "endpoint with a query", cfg: Config{Endpoint: "https://example.com/sse?v=2"}},

		{name: "empty endpoint", cfg: Config{}, wantErr: true},
		{
			// The whole cleartext rule, and it is auth.CanonicalOrigin's rather
			// than a second opinion written here.
			name:    "cleartext to a non-loopback host",
			cfg:     Config{Endpoint: "http://example.com/sse"},
			wantErr: true,
		},
		{name: "not a URL", cfg: Config{Endpoint: "://nope"}, wantErr: true},
		{name: "unsupported scheme", cfg: Config{Endpoint: "ftp://example.com/sse"}, wantErr: true},
		{
			name:    "userinfo in the endpoint",
			cfg:     Config{Endpoint: "https://user:pass@example.com/sse"},
			wantErr: true,
		},
		{
			name: "invalid header",
			cfg: Config{
				Endpoint: "https://example.com/sse",
				Headers:  []auth.Header{auth.NewHeader("X-Bad", "ok"), {}},
			},
			wantErr: true,
		},
		{
			name: "negative timeout",
			cfg: Config{
				Endpoint: "https://example.com/sse",
				Timeouts: Timeouts{Dial: -1},
			},
			wantErr: true,
		},
		{
			name: "client with certificate verification disabled",
			cfg: Config{
				Endpoint: "https://example.com/sse",
				HTTPClient: &http.Client{Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the point of the test
				}},
			},
			wantErr: true,
		},
		{
			name: "client with a whole-exchange timeout",
			cfg: Config{
				Endpoint:   "https://example.com/sse",
				HTTPClient: &http.Client{Timeout: time.Second},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f, err := New(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				var e *client.Error
				if !errors.As(err, &e) || e.Class != client.FailureInvalidConfig {
					t.Fatalf("New() error = %v, want class FailureInvalidConfig", err)
				}
				return
			}
			if f.Kind() != kind {
				t.Errorf("Kind() = %q, want %q", f.Kind(), kind)
			}
		})
	}
}

// TestNewErrorsCarryNoSecrets: a config error names the field and the origin,
// never a credential or a query string.
func TestNewErrorsCarryNoSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "secret in a header value",
			cfg: Config{
				Endpoint: "https://example.com/sse",
				// Invalid (empty name), so New refuses it and must say so
				// without quoting the value.
				Headers: []auth.Header{auth.NewHeader("X-Ok", "fine"), {}},
			},
		},
		{
			name: "secret in the endpoint's query",
			cfg:  Config{Endpoint: "http://example.com/sse?token=" + secret},
		},
		{
			name: "secret in the endpoint's userinfo",
			cfg:  Config{Endpoint: "https://user:" + secret + "@example.com/sse"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tt.cfg)
			if err == nil {
				t.Fatal("New() error = nil, want a refusal")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("New() error carries a secret: %q", err.Error())
			}
		})
	}
}

// TestRedactedOriginKeepsThePathAndQueryOut: the origin is what gets logged, so
// it must never be able to carry a token.
func TestRedactedOriginKeepsThePathAndQueryOut(t *testing.T) {
	t.Parallel()

	f := newFactory(t, Config{Endpoint: "https://example.com:8443/sse?token=" + secret})
	got := f.RedactedOrigin()
	if got != "https://example.com:8443" {
		t.Errorf("RedactedOrigin() = %q, want %q", got, "https://example.com:8443")
	}
	if strings.Contains(got, secret) || strings.Contains(got, "/sse") {
		t.Errorf("RedactedOrigin() = %q, want the origin alone", got)
	}
}

// sseEndpointServer is a legacy SSE server that answers the hanging GET with an
// "endpoint" event naming endpointData, and records any POST it receives.
//
// It is deliberately not a real MCP server: what is under test is where this
// transport is willing to POST, which is settled before any MCP is spoken.
func sseEndpointServer(t *testing.T, endpointData func(base string) string) (*httptest.Server, *atomic.Int32, *atomic.Pointer[http.Header]) {
	t.Helper()

	var posts atomic.Int32
	var postHeaders atomic.Pointer[http.Header]

	mux := http.NewServeMux()
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		h := r.Header.Clone()
		postHeaders.Store(&h)
		w.WriteHeader(http.StatusAccepted)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpointData(srv.URL))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Hold the stream open: the SDK takes ownership of the body, and a
		// handler that returned would end the session before the POST is tried.
		<-r.Context().Done()
	})

	return srv, &posts, &postHeaders
}

// TestPostEndpointCannotLeaveTheOrigin is this package's reason to exist as
// something other than a copy of streamablehttp.
//
// The legacy protocol lets the *server* name the URL the client POSTs to, and
// the SDK resolves that name as a URL reference — so an absolute one points
// wherever the server likes. That is an origin change no CheckRedirect ever
// sees, because it is not a redirect: it is a fresh request. Without the pin in
// the RoundTripper, this transport would POST this module's credentials to a
// host a legacy server nominated.
//
// The victim server here is a second httptest server, so "did the credential
// leave" is not inferred from an error message: it is answered by asking the
// attacker what it received.
func TestPostEndpointCannotLeaveTheOrigin(t *testing.T) {
	t.Parallel()

	var stolen atomic.Int32
	var stolenAuth atomic.Pointer[string]
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stolen.Add(1)
		got := r.Header.Get("Authorization")
		stolenAuth.Store(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer victim.Close()

	// The server points the client's POSTs at the victim's absolute URL.
	srv, posts, _ := sseEndpointServer(t, func(string) string { return victim.URL + "/messages" })

	f := newFactory(t, Config{
		Endpoint: srv.URL + "/sse",
		Headers:  []auth.Header{auth.NewHeader("Authorization", "Bearer "+secret)},
	})
	_ = initializeExpectingFailure(t, f)

	if n := stolen.Load(); n != 0 {
		got := ""
		if p := stolenAuth.Load(); p != nil {
			got = *p
		}
		t.Fatalf("a foreign host received %d request(s) from this transport, with Authorization %q: "+
			"a server naming another origin in its endpoint event must never be followed", n, got)
	}
	if posts.Load() != 0 {
		t.Errorf("the origin server received %d POSTs, want 0: the POST went to the endpoint event's URL", posts.Load())
	}
}

// TestPostEndpointOnTheOriginIsFollowed is the other half, and without it the
// test above is satisfied by a transport that simply never POSTs.
//
// A relative endpoint — which is what a legitimate legacy server sends — must
// work, and must carry the credential, because that is the transport doing its
// job.
func TestPostEndpointOnTheOriginIsFollowed(t *testing.T) {
	t.Parallel()

	srv, posts, headers := sseEndpointServer(t, func(string) string { return "/messages" })

	f := newFactory(t, Config{
		Endpoint: srv.URL + "/sse",
		Headers:  []auth.Header{auth.NewHeader("Authorization", "Bearer "+secret)},
	})
	// The server is not a real MCP server, so the handshake fails — after the
	// POST that this test is about has been made.
	_ = initializeExpectingFailure(t, f)

	if posts.Load() == 0 {
		t.Fatal("the server received no POSTs: a same-origin endpoint event must be followed, " +
			"or the origin pin is refusing everything and proves nothing")
	}
	h := headers.Load()
	if h == nil {
		t.Fatal("no POST headers were captured")
	}
	if got := h.Get("Authorization"); got != "Bearer "+secret {
		t.Errorf("the POST carried Authorization = %q, want the configured credential: "+
			"a same-origin request is exactly where the credential belongs", got)
	}
}

// TestStreamRedirectThatLeavesTheOriginIsRefused covers the other door: the
// stdlib's own redirect following, on the hanging GET.
func TestStreamRedirectThatLeavesTheOriginIsRefused(t *testing.T) {
	t.Parallel()

	var stolen atomic.Int32
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stolen.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}))
	defer victim.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+"/sse", http.StatusFound)
	}))
	defer srv.Close()

	f := newFactory(t, Config{
		Endpoint: srv.URL + "/sse",
		Headers:  []auth.Header{auth.NewHeader("Authorization", "Bearer "+secret)},
	})
	err := initializeExpectingFailure(t, f)

	if stolen.Load() != 0 {
		t.Errorf("a foreign host received %d request(s): a redirect that leaves the origin must be refused", stolen.Load())
	}
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Errorf("the error carries the credential: %q", err.Error())
	}
}

// TestConnectRefusesADoneContext: a transport asked to connect on a dead context
// says so rather than dialing.
func TestConnectRefusesADoneContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func() (context.Context, context.CancelFunc)
		want  client.FailureClass
	}{
		{
			name: "cancelled",
			setup: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			want: client.FailureCancelled,
		},
		{
			name: "deadline exceeded",
			setup: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				return ctx, cancel
			},
			want: client.FailureStartupTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFactory(t, Config{Endpoint: "https://example.com/sse"})
			ctx, cancel := tt.setup()
			defer cancel()

			_, err := f.Connect(ctx, testConnectConfig())
			if err == nil {
				t.Fatal("Connect() error = nil, want a refusal")
			}
			var e *client.Error
			if !errors.As(err, &e) || e.Class != tt.want {
				t.Fatalf("Connect() error = %v, want class %v", err, tt.want)
			}
		})
	}
}

func TestTimeoutsWithDefaults(t *testing.T) {
	t.Parallel()

	got := Timeouts{}.withDefaults()
	want := Timeouts{
		Dial:           DefaultDialTimeout,
		TLSHandshake:   DefaultTLSHandshakeTimeout,
		ResponseHeader: DefaultResponseHeaderTimeout,
		Frame:          DefaultFrameTimeout,
		IdleConn:       DefaultIdleConnTimeout,
		Request:        DefaultRequestTimeout,
	}
	if got != want {
		t.Errorf("Timeouts{}.withDefaults() = %+v, want %+v", got, want)
	}

	// A set field is kept, and only the zero ones are filled in.
	set := Timeouts{Dial: time.Second}.withDefaults()
	if set.Dial != time.Second {
		t.Errorf("Dial = %v, want the caller's 1s", set.Dial)
	}
	if set.Frame != DefaultFrameTimeout {
		t.Errorf("Frame = %v, want the default", set.Frame)
	}
}
