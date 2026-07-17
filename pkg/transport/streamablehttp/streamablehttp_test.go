// Unit tests for the Streamable HTTP transport: everything that can be settled
// against an httptest server in this process.
//
// The tests that matter most here are the ones that make a *negative* claim,
// because a negative claim is what this transport is for. That a secret never
// reaches an error, that a tool call is never sent twice, that a hostile body is
// never fully buffered, that TLS verification is never off — none of those can
// be established by watching the happy path work, so each has a test that would
// fail if the guarantee were quietly dropped.
//
// The end-to-end tests, against a real SDK MCP server over real HTTP, live in
// streamablehttp_integration_test.go.

package streamablehttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/auth"
	"github.com/looprig/mcp/pkg/client"
)

// secret is the value every redaction test hunts for. It is not a credential:
// it is a distinctive string that must never appear anywhere a credential would
// not be welcome.
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

// newFactory builds a factory for endpoint, failing the test if New refuses it.
func newFactory(t *testing.T, cfg Config) client.TransportFactory {
	t.Helper()
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}
	return f
}

func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "https endpoint", cfg: Config{Endpoint: "https://example.com/mcp"}},
		{name: "https with port and query", cfg: Config{Endpoint: "https://example.com:8443/mcp?v=2"}},
		{name: "http on loopback ip", cfg: Config{Endpoint: "http://127.0.0.1:8080/mcp"}},
		{name: "http on localhost", cfg: Config{Endpoint: "http://localhost:8080/mcp"}},
		{name: "http on ipv6 loopback", cfg: Config{Endpoint: "http://[::1]:8080/mcp"}},

		{name: "empty endpoint", cfg: Config{}, wantErr: true},
		{name: "http on non-loopback", cfg: Config{Endpoint: "http://example.com/mcp"}, wantErr: true},
		{name: "not a url", cfg: Config{Endpoint: "://nonsense"}, wantErr: true},
		{name: "no scheme", cfg: Config{Endpoint: "example.com/mcp"}, wantErr: true},
		{name: "unsupported scheme", cfg: Config{Endpoint: "ftp://example.com/mcp"}, wantErr: true},
		{name: "userinfo carries a credential", cfg: Config{Endpoint: "https://user:pw@example.com/mcp"}, wantErr: true},
		{name: "opaque url", cfg: Config{Endpoint: "https:example.com"}, wantErr: true},

		{
			name:    "header with an invalid name",
			cfg:     Config{Endpoint: "https://example.com/mcp", Headers: []auth.Header{auth.NewHeader("bad name", "v")}},
			wantErr: true,
		},
		{
			name:    "header value smuggling a second header",
			cfg:     Config{Endpoint: "https://example.com/mcp", Headers: []auth.Header{auth.NewHeader("X-A", "v\r\nX-Evil: 1")}},
			wantErr: true,
		},
		{
			name: "valid header",
			cfg:  Config{Endpoint: "https://example.com/mcp", Headers: []auth.Header{auth.NewHeader("X-A", "v")}},
		},

		{
			name:    "negative timeout",
			cfg:     Config{Endpoint: "https://example.com/mcp", Timeouts: Timeouts{Dial: -time.Second}},
			wantErr: true,
		},
		{
			name:    "http client with a whole-exchange timeout",
			cfg:     Config{Endpoint: "https://example.com/mcp", HTTPClient: &http.Client{Timeout: time.Second}},
			wantErr: true,
		},
		{
			name: "http client with insecure skip verify",
			cfg: Config{Endpoint: "https://example.com/mcp", HTTPClient: &http.Client{
				Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // the point of the test
			}},
			wantErr: true,
		},
		{
			name: "http client with an unreadable round tripper",
			cfg: Config{Endpoint: "https://example.com/mcp", HTTPClient: &http.Client{
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil }),
			}},
			wantErr: true,
		},
		{
			name: "http client with no transport",
			cfg:  Config{Endpoint: "https://example.com/mcp", HTTPClient: &http.Client{}},
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
				var cerr *client.Error
				if !errors.As(err, &cerr) {
					t.Fatalf("New() error is %T, want *client.Error", err)
				}
				if cerr.Class != client.FailureInvalidConfig {
					t.Errorf("New() class = %v, want %v", cerr.Class, client.FailureInvalidConfig)
				}
				return
			}
			if f == nil {
				t.Fatal("New() returned a nil factory with a nil error")
			}
		})
	}
}

func TestKind(t *testing.T) {
	t.Parallel()
	f := newFactory(t, Config{Endpoint: "https://example.com/mcp"})
	if got := f.Kind(); got != "streamablehttp" {
		t.Errorf("Kind() = %q, want %q", got, "streamablehttp")
	}
}

func TestRedactedOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "path is dropped", endpoint: "https://example.com/mcp", want: "https://example.com"},
		{name: "default port is dropped", endpoint: "https://example.com:443/mcp", want: "https://example.com"},
		{name: "explicit port is kept", endpoint: "https://example.com:8443/mcp", want: "https://example.com:8443"},
		{name: "case is normalized", endpoint: "HTTPS://Example.COM/mcp", want: "https://example.com"},
		{name: "loopback http", endpoint: "http://127.0.0.1:8080/mcp", want: "http://127.0.0.1:8080"},
		{
			name:     "query is dropped, tokens and all",
			endpoint: "https://example.com/mcp?access_token=" + secret,
			want:     "https://example.com",
		},
		{
			name:     "fragment is dropped",
			endpoint: "https://example.com/mcp#" + secret,
			want:     "https://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFactory(t, Config{Endpoint: tt.endpoint})
			if got := f.RedactedOrigin(); got != tt.want {
				t.Errorf("RedactedOrigin() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestEndpointKeepsPathAndQuery checks the other half of RedactedOrigin's
// contract: what is withheld from the display string is still sent on the wire.
// A transport that redacted by discarding would pass every redaction test here
// and talk to the wrong URL.
func TestEndpointKeepsPathAndQuery(t *testing.T) {
	t.Parallel()

	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.URL.String())
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := newFactory(t, Config{Endpoint: srv.URL + "/mcp?v=2"})
	initializeExpectingFailure(t, f)

	if want := "/mcp?v=2"; got.Load() != want {
		t.Errorf("server saw %q, want %q", got.Load(), want)
	}
}

// TestNoSecretsInOriginOrErrors is the redaction sweep: a secret in every place
// a caller can put one, and a check that none of them reaches RedactedOrigin or
// any error text the transport produces.
func TestNoSecretsInOriginOrErrors(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A hostile server reflecting the credential it was given straight back,
		// hoping the transport puts its answer in an error.
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "denied: %s", r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	f := newFactory(t, Config{
		Endpoint: srv.URL + "/mcp?access_token=" + secret,
		Headers:  []auth.Header{auth.NewHeader("X-Static", secret)},
		Auth:     staticProvider{auth.NewHeader("Authorization", "Bearer "+secret)},
	})

	if origin := f.RedactedOrigin(); strings.Contains(origin, secret) {
		t.Errorf("RedactedOrigin() leaked the secret: %q", origin)
	}
	err := initializeExpectingFailure(t, f)
	if text := err.Error(); strings.Contains(text, secret) {
		t.Errorf("error leaked the secret: %q", text)
	}
	// %+v and friends do not go through Error(); a struct field holding the
	// secret would surface here.
	if text := fmt.Sprintf("%+v %#v", err, err); strings.Contains(text, secret) {
		t.Error("formatting the error leaked the secret")
	}
}

// TestNoSecretsWhenTheServerIsUnreachable is the redaction case that the
// server-answered ones cannot reach, and it is the one that actually bit.
//
// When a request never gets a status, classify has nothing specific to report,
// and the tempting thing — leave the message empty and let client.Error render
// the wrapped cause — prints the credential: every network failure arrives
// wrapped in a *url.Error, whose text quotes the request URL, whose query is
// where "?access_token=" lives. The failure mode needs no hostile server and no
// unusual configuration, only a server that is down.
func TestNoSecretsWhenTheServerIsUnreachable(t *testing.T) {
	t.Parallel()

	// Port 1 is reserved and nothing listens on it: the connection is refused
	// immediately, so no status is ever recorded and no timeout is waited out.
	f := newFactory(t, Config{Endpoint: "http://127.0.0.1:1/mcp?access_token=" + secret})
	err := initializeExpectingFailure(t, f)

	if strings.Contains(err.Error(), secret) {
		t.Errorf("the error leaked the query string's secret: %v", err)
	}
	// The diagnostic survives the redaction: an operator still learns why.
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("error = %q, want it to still name the cause (connection refused)", err)
	}
}

// TestRedirectsThatLeaveTheOriginAreRefused is the credential-leak case, and it
// is the one where this transport was, briefly, strictly worse than the
// http.Client it wraps.
//
// http.Client strips Authorization when a redirect crosses origins. This
// package's RoundTripper runs below that logic and attaches credentials to every
// request it sees — so without CheckRedirect it puts the stripped header back,
// and hands the bearer token to whoever the 302 names. The subtests cover both
// facets: the credential must not travel, and the hop must not reach a host New
// itself would refuse.
func TestRedirectsThatLeaveTheOriginAreRefused(t *testing.T) {
	t.Parallel()

	// newEvil returns a server that records the Authorization it was given, and
	// the origin to redirect to — spelled with a different hostname for the same
	// address, which is a different origin to the stdlib and to this package.
	newEvil := func(t *testing.T) (*atomic.Value, string) {
		t.Helper()
		var saw atomic.Value
		saw.Store("")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			saw.Store(r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)
		return &saw, strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	}

	t.Run("the credential does not follow a cross-origin redirect", func(t *testing.T) {
		t.Parallel()

		saw, evil := newEvil(t)
		legit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, evil+"/mcp", http.StatusFound)
		}))
		t.Cleanup(legit.Close)

		f := newFactory(t, Config{
			Endpoint: legit.URL + "/mcp",
			Auth:     staticProvider{auth.NewHeader("Authorization", "Bearer "+secret)},
		})
		err := initializeExpectingFailure(t, f)

		if got := saw.Load().(string); got != "" {
			t.Errorf("the redirect target saw Authorization = %q; a credential must never leave its origin", got)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error leaked the credential: %v", err)
		}
	})

	t.Run("a redirect to a host New would refuse is not followed", func(t *testing.T) {
		t.Parallel()

		// The exact URL New rejects at config time: cleartext, non-loopback.
		const forbidden = "http://nonloopback.invalid/mcp"
		if _, err := New(Config{Endpoint: forbidden}); err == nil {
			t.Fatalf("New(%q) was accepted; this test assumes it is refused", forbidden)
		}

		var reached atomic.Bool
		legit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached.Store(true)
			http.Redirect(w, r, forbidden, http.StatusFound)
		}))
		t.Cleanup(legit.Close)

		f := newFactory(t, Config{Endpoint: legit.URL + "/mcp"})
		err := initializeExpectingFailure(t, f)

		if !reached.Load() {
			t.Fatal("the endpoint was never reached; the test proved nothing")
		}
		// Config time and run time must agree: what New refuses, a 302 must not
		// smuggle in.
		if !strings.Contains(err.Error(), "refusing a redirect") {
			t.Errorf("error = %q, want a refusal to follow the redirect", err)
		}
		if strings.Contains(err.Error(), "lookup") || strings.Contains(err.Error(), "no such host") {
			t.Errorf("error = %q: the transport tried to resolve the forbidden host, so it followed the redirect", err)
		}
	})

	t.Run("a same-origin redirect is followed", func(t *testing.T) {
		t.Parallel()

		// Same origin, different path: an ordinary thing for a server to do, and
		// the credential is not going anywhere new. Refusing this would be a
		// policy that breaks real servers for no gain.
		var mu sync.Mutex
		var paths []string
		var auths []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			auths = append(auths, r.Header.Get("Authorization"))
			mu.Unlock()
			if r.URL.Path == "/mcp" {
				http.Redirect(w, r, "/mcp/v2", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		f := newFactory(t, Config{
			Endpoint: srv.URL + "/mcp",
			Auth:     staticProvider{auth.NewHeader("Authorization", "Bearer "+secret)},
		})
		initializeExpectingFailure(t, f)

		mu.Lock()
		defer mu.Unlock()
		if !slices.Contains(paths, "/mcp/v2") {
			t.Errorf("paths = %v, want the same-origin redirect to have been followed to /mcp/v2", paths)
		}
		for i, a := range auths {
			if a != "Bearer "+secret {
				t.Errorf("request %d (%s) carried Authorization = %q, want the credential: it never left its origin", i, paths[i], a)
			}
		}
	})

	t.Run("a redirect loop is bounded", func(t *testing.T) {
		t.Parallel()

		// POSTs only: the connection also makes a DELETE at close, which is a
		// separate request with a redirect budget of its own. Counting both
		// would measure the number of requests rather than the hop bound.
		var hops atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				hops.Add(1)
			}
			// Same origin, so the origin check passes and only the hop bound can
			// stop this — which is why the hop bound is not redundant with it.
			http.Redirect(w, r, "/mcp?n="+fmt.Sprint(hops.Load()), http.StatusTemporaryRedirect)
		}))
		t.Cleanup(srv.Close)

		f := newFactory(t, Config{Endpoint: srv.URL + "/mcp"})
		initializeExpectingFailure(t, f)

		// The client makes the first request, then follows at most maxRedirects-1
		// more before CheckRedirect refuses the next: maxRedirects requests reach
		// the server. What matters is that the number is finite and small.
		if n := hops.Load(); n > maxRedirects {
			t.Errorf("the server saw %d POST hops, want at most %d: a redirect loop must be bounded", n, maxRedirects)
		}
		if hops.Load() == 0 {
			t.Error("the server saw no POSTs; the test proved nothing")
		}
	})
}

// TestStallingStreamIsBounded is the slowloris case: a server that satisfies
// every other bound and then simply stops.
//
// It flushes its headers at once, which disarms ResponseHeaderTimeout, and then
// dribbles bytes without ever completing a frame. No byte limit catches this in
// useful time (a byte every two seconds against a four-mebibyte cap is about
// ninety-seven days), and the standalone SSE stream has no caller deadline to
// fall back on. Only the frame clock ends it.
func TestStallingStreamIsBounded(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		// A frame that starts and never finishes.
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := io.WriteString(w, "d"); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(srv.Close)

	f := newFactory(t, Config{Endpoint: srv.URL, Timeouts: Timeouts{Frame: 250 * time.Millisecond}})
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	done := make(chan error, 1)
	go func() {
		// No deadline of its own: the frame clock is the only thing that can end
		// this, which is the whole point of the test.
		_, err := c.Initialize(context.Background())
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Initialize() succeeded against a stalling server")
		}
		if !strings.Contains(err.Error(), "stalled") {
			t.Errorf("error = %q, want it to name the stall", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Initialize() hung: a server that dribbles bytes without completing a frame is not bounded")
	}
}

func TestDefaultTransportIsTLSSafe(t *testing.T) {
	t.Parallel()

	f := newFactory(t, Config{Endpoint: "https://example.com/mcp"}).(*factory)
	cfg := f.base.TLSClientConfig
	if cfg == nil {
		t.Fatal("default transport has no TLSClientConfig")
	}
	if cfg.InsecureSkipVerify {
		t.Error("default transport has InsecureSkipVerify set")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("default transport MinVersion = 0x%04x, want 0x%04x (TLS 1.2)", cfg.MinVersion, tls.VersionTLS12)
	}
	if f.base.ResponseHeaderTimeout != DefaultResponseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", f.base.ResponseHeaderTimeout, DefaultResponseHeaderTimeout)
	}
	if f.base.IdleConnTimeout != DefaultIdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", f.base.IdleConnTimeout, DefaultIdleConnTimeout)
	}
}

// TestSuppliedClientIsVettedNotTrusted checks both halves of what New does to a
// caller's client: it raises the TLS floor on its own copy, and it leaves the
// caller's value alone.
func TestSuppliedClientIsVettedNotTrusted(t *testing.T) {
	t.Parallel()

	caller := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10}}
	f := newFactory(t, Config{
		Endpoint:   "https://example.com/mcp",
		HTTPClient: &http.Client{Transport: caller},
	}).(*factory)

	if got := f.base.TLSClientConfig.MinVersion; got != tls.VersionTLS12 {
		t.Errorf("vetted MinVersion = 0x%04x, want 0x%04x (TLS 1.2)", got, tls.VersionTLS12)
	}
	if got := caller.TLSClientConfig.MinVersion; got != tls.VersionTLS10 {
		t.Errorf("caller's MinVersion = 0x%04x, want it untouched (0x%04x)", got, tls.VersionTLS10)
	}
	if f.base == caller {
		t.Error("the caller's transport was used directly; it must be cloned")
	}
}

// TestAuthHeadersRefreshedPerRequest is the reason HeaderProvider is called from
// a RoundTripper rather than once at Connect. A provider backed by an expiring
// credential returns a different value over time, and every request must carry
// the current one.
func TestAuthHeadersRefreshedPerRequest(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var n atomic.Int64
	f := newFactory(t, Config{
		Endpoint: srv.URL,
		Auth: providerFunc(func(context.Context) ([]auth.Header, error) {
			return []auth.Header{auth.NewHeader("Authorization", fmt.Sprintf("Bearer token-%d", n.Add(1)))}, nil
		}),
	})

	// Two connections, one request each: the transport makes exactly one request
	// per failed initialize, so this is the cleanest way to observe two.
	initializeExpectingFailure(t, f)
	initializeExpectingFailure(t, f)

	mu.Lock()
	defer mu.Unlock()
	// Every request, not just the calls: the DELETE that releases a session
	// needs a live credential as much as the POST that opened it, and a
	// transport that cached the first token would send a stale one here too.
	if len(seen) < 2 {
		t.Fatalf("server saw %d requests, want at least 2: %q", len(seen), seen)
	}
	for i, got := range seen {
		if want := fmt.Sprintf("Bearer token-%d", i+1); got != want {
			t.Errorf("request %d carried %q, want %q: the provider must be consulted per request", i, got, want)
		}
	}
}

// TestStaticHeadersAreAttachedAndAuthWins pins the documented precedence: a
// static header is sent, and a provider naming the same field overrides it.
func TestStaticHeadersAreAttachedAndAuthWins(t *testing.T) {
	t.Parallel()

	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Clone())
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := newFactory(t, Config{
		Endpoint: srv.URL,
		Headers: []auth.Header{
			auth.NewHeader("X-Static", "static-value"),
			auth.NewHeader("Authorization", "Bearer configured"),
		},
		Auth: staticProvider{auth.NewHeader("Authorization", "Bearer live")},
	})
	initializeExpectingFailure(t, f)

	h := got.Load().(http.Header)
	if v := h.Get("X-Static"); v != "static-value" {
		t.Errorf("X-Static = %q, want %q", v, "static-value")
	}
	if v := h.Get("Authorization"); v != "Bearer live" {
		t.Errorf("Authorization = %q, want the provider's %q", v, "Bearer live")
	}
}

// TestProviderHeadersAreValidated checks that a provider — application code
// minting a value per request — cannot append headers of its own choosing by
// returning a value with a newline in it.
func TestProviderHeadersAreValidated(t *testing.T) {
	t.Parallel()

	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := newFactory(t, Config{
		Endpoint: srv.URL,
		Auth:     staticProvider{auth.NewHeader("Authorization", "Bearer x\r\nX-Evil: 1")},
	})
	err := initializeExpectingFailure(t, f)

	if reached.Load() {
		t.Error("the request reached the server; an invalid credential must not be sent")
	}
	assertClass(t, err, client.FailureInvalidConfig)
}

func TestAuthProviderFailuresAreClassified(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want client.FailureClass
	}{
		{name: "invalid config", err: auth.NewError(auth.ClassInvalidConfig, "load", "bad key", nil), want: client.FailureInvalidConfig},
		{name: "no token", err: auth.NewNoTokenError("load"), want: client.FailureAuthRequired},
		{name: "required", err: auth.NewError(auth.ClassRequired, "load", "login needed", nil), want: client.FailureAuthRequired},
		{name: "denied", err: auth.NewError(auth.ClassDenied, "authorize", "user refused", nil), want: client.FailureAuthDenied},
		{name: "expired", err: auth.NewError(auth.ClassExpired, "refresh", "past expiry", nil), want: client.FailureAuthExpired},
		{name: "failed", err: auth.NewError(auth.ClassFailed, "refresh", "broke", nil), want: client.FailureAuthFailed},
		{
			// A provider is application code and may return anything. It is still
			// an auth failure, classified as the one thing that is certainly true.
			name: "an error that is not an auth.Error",
			err:  errors.New("keyring is locked"),
			want: client.FailureAuthFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			f := newFactory(t, Config{
				Endpoint: srv.URL,
				Auth:     providerFunc(func(context.Context) ([]auth.Header, error) { return nil, tt.err }),
			})
			assertClass(t, initializeExpectingFailure(t, f), tt.want)
		})
	}
}

func TestHTTPStatusesAreClassified(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		want   client.FailureClass
	}{
		{name: "401 wants a credential", status: http.StatusUnauthorized, want: client.FailureAuthRequired},
		{name: "403 refuses the credential", status: http.StatusForbidden, want: client.FailureAuthDenied},
		{name: "404 no endpoint or no session", status: http.StatusNotFound, want: client.FailureRemoteHTTP},
		{name: "429 rate limited", status: http.StatusTooManyRequests, want: client.FailureRemoteHTTP},
		{name: "500 server broke", status: http.StatusInternalServerError, want: client.FailureRemoteHTTP},
		{name: "503 server unavailable", status: http.StatusServiceUnavailable, want: client.FailureRemoteHTTP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			f := newFactory(t, Config{Endpoint: srv.URL})
			err := initializeExpectingFailure(t, f)
			assertClass(t, err, tt.want)
			// The status is in the message, because "remote_http" alone does not
			// tell an operator whether to retry or to fix a config.
			if !strings.Contains(err.Error(), fmt.Sprint(tt.status)) {
				t.Errorf("error %q does not name the status %d", err, tt.status)
			}
		})
	}
}

// TestCallIsNeverRetried is the load-bearing test of the package comment. A
// server that fails every request is the case where a retrying client would show
// itself; exactly one request must arrive.
//
// It probes with initialize, which is a POST carrying a JSON-RPC call — the same
// shape, on the same code path, as a tool call. A tool call itself is probed
// end-to-end in the integration test, where there is a server that can serve one.
func TestCallIsNeverRetried(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
	}{
		// The transient set the SDK recognizes (500, 502, 503, 504, 429), plus
		// the two that reach its authorize-and-resend branch.
		// 401 and 403 first: they are the ONLY statuses that reach the SDK's
		// re-send branch, which fires when OAuthHandler is non-nil. They are
		// therefore the cases that would break the instant someone "adds OAuth
		// support" by setting that field — which is exactly the plausible future
		// change this test exists to stop.
		{name: "401", status: http.StatusUnauthorized},
		{name: "403", status: http.StatusForbidden},
		{name: "500", status: http.StatusInternalServerError},
		{name: "502", status: http.StatusBadGateway},
		{name: "503", status: http.StatusServiceUnavailable},
		{name: "504", status: http.StatusGatewayTimeout},
		{name: "429", status: http.StatusTooManyRequests},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var posts atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
				}
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			f := newFactory(t, Config{Endpoint: srv.URL})
			initializeExpectingFailure(t, f)

			// Give a retry that is going to happen time to happen. The SDK's
			// backoff starts at a jittered second, so a retry would land inside
			// this window; without the wait, this test would pass against a
			// retrying client by finishing first.
			time.Sleep(250 * time.Millisecond)

			if n := posts.Load(); n != 1 {
				t.Errorf("server received %d POSTs, want exactly 1: a call must never be re-sent", n)
			}
		})
	}
}

// TestOversizedBodyIsBounded is the hostile-server case: a body far larger than
// the limit, which a transport that read it whole would buffer whole.
func TestOversizedBodyIsBounded(t *testing.T) {
	t.Parallel()

	const limit = 4 << 10

	var written atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Far more than the bound, streamed rather than allocated, and never
		// terminated as valid JSON: the point is that the read stops, not that
		// the parse fails.
		chunk := strings.Repeat("x", 4<<10)
		for i := 0; i < 4096; i++ {
			n, err := w.Write([]byte(chunk))
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	f := newFactory(t, Config{Endpoint: srv.URL})
	cfg := testConnectConfig()
	cfg.Wire = protocol.WireLimits{MaxBodyBytes: limit, MaxFrameBytes: limit}

	c, err := f.Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = c.Initialize(ctx)
	if err == nil {
		t.Fatal("Initialize() succeeded against an oversized body, want a failure")
	}
	assertClass(t, err, client.FailureLimitExceeded)

	// The bound is on what is buffered, not on what the server sends: the server
	// may well get several chunks out before the connection collapses. What must
	// not happen is reading all 16 MiB of it.
	if n := written.Load(); n > 4<<20 {
		t.Errorf("server wrote %d bytes; the reader kept consuming past its %d byte bound", n, limit)
	}
}

func TestConnectRefusesADoneContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want client.FailureClass
	}{
		{
			name: "cancelled",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			want: client.FailureCancelled,
		},
		{
			name: "past its deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				return ctx, cancel
			},
			want: client.FailureStartupTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := tt.ctx()
			defer cancel()

			f := newFactory(t, Config{Endpoint: "https://example.com/mcp"})
			c, err := f.Connect(ctx, testConnectConfig())
			if err == nil {
				_ = c.Close(context.Background())
				t.Fatal("Connect() succeeded on a done context, want a failure")
			}
			assertClass(t, err, tt.want)
		})
	}
}

// TestInitializeHonorsCancellation checks the caller's context reaches the wire:
// a server that never answers must not outlast the caller who gave up.
func TestInitializeHonorsCancellation(t *testing.T) {
	t.Parallel()

	f := newFactory(t, Config{Endpoint: newHangingServer(t)})
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := c.Initialize(ctx)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Initialize() succeeded, want a cancellation")
		}
		assertClass(t, err, client.FailureCancelled)
	case <-time.After(10 * time.Second):
		t.Fatal("Initialize() did not return after its context was cancelled")
	}
}

// TestInitializeHonorsDeadline is the timeout half of the same claim.
func TestInitializeHonorsDeadline(t *testing.T) {
	t.Parallel()

	f := newFactory(t, Config{Endpoint: newHangingServer(t)})
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.Initialize(ctx); err == nil {
		t.Fatal("Initialize() succeeded, want a timeout")
	} else {
		assertClass(t, err, client.FailureStartupTimeout)
	}
}

// TestRequestTimeoutBoundsTheSessionRelease pins the bound documented on
// Timeouts.Request, against the server that makes it matter: one that accepts
// the DELETE and never answers.
//
// Without the bound this hangs forever. With it, a shutdown costs at most
// Timeouts.Request — which is also what a cancelled caller waits out, because
// the SDK releases the session from inside a failed handshake.
func TestRequestTimeoutBoundsTheSessionRelease(t *testing.T) {
	t.Parallel()

	const bound = 250 * time.Millisecond

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	f := newFactory(t, Config{Endpoint: srv.URL, Timeouts: Timeouts{Request: bound}})
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Initialize(ctx); err == nil {
		t.Fatal("Initialize() succeeded against a server that never answers")
	}

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		_ = c.Close(context.Background())
	}()

	select {
	case <-done:
		// The DELETE is bounded, so Close returns. It may return almost at once
		// (the release already timed out during Initialize) or after one more
		// bound; what must not happen is waiting forever on a silent server.
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("Close() took %v; Timeouts.Request (%v) did not bound the DELETE", elapsed, bound)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close() hung: the session-release DELETE is not bounded")
	}
}

// TestCloseIsIdempotent — the client promises to call Close once, but a
// transport that panicked or errored on a second call would be a trap for
// exactly the unwind paths that are hardest to test.
func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := newFactory(t, Config{Endpoint: srv.URL})
	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Close(context.Background()); err != nil {
			t.Fatalf("Close() #%d error = %v, want nil on a connection that never initialized", i+1, err)
		}
	}
}

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
			wantBody:  defaultMaxBodyBytes,
			wantFrame: defaultMaxFrameBytes,
		},
		{
			name:      "negative is not unbounded",
			in:        protocol.WireLimits{MaxBodyBytes: -1, MaxFrameBytes: -1},
			wantBody:  defaultMaxBodyBytes,
			wantFrame: defaultMaxFrameBytes,
		},
		{
			name:      "one set, one not",
			in:        protocol.WireLimits{MaxBodyBytes: 99},
			wantBody:  99,
			wantFrame: defaultMaxFrameBytes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := newWireLimits(tt.in)
			if got.maxBody != tt.wantBody {
				t.Errorf("maxBody = %d, want %d", got.maxBody, tt.wantBody)
			}
			if got.maxFrame != tt.wantFrame {
				t.Errorf("maxFrame = %d, want %d", got.maxFrame, tt.wantFrame)
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

	// A set field is never replaced.
	set := Timeouts{Dial: time.Second, TLSHandshake: 2 * time.Second, ResponseHeader: 3 * time.Second, Frame: 4 * time.Second, IdleConn: 5 * time.Second, Request: 6 * time.Second}
	if got := set.withDefaults(); got != set {
		t.Errorf("withDefaults() overwrote a set value: got %+v, want %+v", got, set)
	}
}

// --- helpers ---

// initializeExpectingFailure connects, initializes, and requires that it failed.
// It returns the error so the caller can assert on it.
//
// Most tests here point the transport at a server that cannot complete a
// handshake — that is how a status, a bound or a refused credential is observed
// — so "connect, fail, report" is the shape of nearly all of them.
func initializeExpectingFailure(t *testing.T, f client.TransportFactory) error {
	t.Helper()

	c, err := f.Connect(context.Background(), testConnectConfig())
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := c.Initialize(ctx)
	if err == nil {
		t.Fatalf("Initialize() succeeded (%+v), want a failure", res)
	}
	return err
}

// newHangingServer starts a server that never answers a POST or a GET, and
// returns its URL.
//
// It answers the DELETE immediately, and that detail is the difference between
// testing cancellation and testing something else. The SDK closes the session
// from inside a failed handshake, so a cancelled Initialize does not return
// until that DELETE resolves; a server that hung it too would make this test
// measure Timeouts.Request — which has its own test — while appearing to
// measure cancellation. A real server answers its DELETE.
func newHangingServer(t *testing.T) string {
	t.Helper()

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// LIFO: release the handlers, then shut the server down. srv.Close waits for
	// its handlers to return, so closing first would deadlock the cleanup.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv.URL
}

func assertClass(t *testing.T, err error, want client.FailureClass) {
	t.Helper()
	got, ok := client.ClassOf(err)
	if !ok {
		t.Fatalf("error %v (%T) is not a *client.Error", err, err)
	}
	if got != want {
		t.Errorf("class = %v, want %v (error: %v)", got, want, err)
	}
}

// staticProvider returns the same headers every time.
type staticProvider []auth.Header

func (p staticProvider) Headers(context.Context) ([]auth.Header, error) { return p, nil }

// providerFunc adapts a function to auth.HeaderProvider.
type providerFunc func(context.Context) ([]auth.Header, error)

func (f providerFunc) Headers(ctx context.Context) ([]auth.Header, error) { return f(ctx) }

// roundTripFunc is an http.RoundTripper that is not an *http.Transport, for the
// test that New refuses one.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestDeadlineClass pins the op-aware classification of a blown deadline.
//
// It is a direct unit test because deadlineClass is a pure function of the op
// and because the paths that reach it cannot cover the op set cheaply: the
// classification a caller acts on is decided here, so this is where every op is
// stated. The regression it exists to catch is the one this code started with —
// reporting every deadline as a startup timeout, which tells a caller that its
// healthy binding failed to start — and that mistake is invisible to a test
// that only ever blows one deadline.
func TestDeadlineClass(t *testing.T) {
	t.Parallel()

	// Every op this package defines, so that a new op has to be classified here
	// rather than defaulting in silence.
	tests := []struct {
		name string
		op   string
		want client.FailureClass
	}{
		// Startup: the binding never came up, and the caller may retry or drop it.
		{name: "connect", op: opConnect, want: client.FailureStartupTimeout},
		{name: "initialize", op: opInitialize, want: client.FailureStartupTimeout},

		// Everything else: the binding is fine and this operation ran out of time.
		{name: "new", op: opNew, want: client.FailureDeadline},
		{name: "close", op: opClose, want: client.FailureDeadline},
		{name: "list tools", op: opListTools, want: client.FailureDeadline},
		{name: "list prompts", op: opListPrompts, want: client.FailureDeadline},
		{name: "list resources", op: opListResources, want: client.FailureDeadline},
		{name: "list resource templates", op: opListResourceTemplates, want: client.FailureDeadline},
		{name: "call tool", op: opCallTool, want: client.FailureDeadline},
		{name: "get prompt", op: opGetPrompt, want: client.FailureDeadline},
		{name: "read resource", op: opReadResource, want: client.FailureDeadline},
		{name: "subscribe", op: opSubscribe, want: client.FailureDeadline},
		{name: "set log level", op: opSetLogLevel, want: client.FailureDeadline},

		// An op this package does not define is not a startup: defaulting the
		// unknown case to a startup timeout would misreport a caller's binding.
		{name: "unknown op", op: "no_such_op", want: client.FailureDeadline},
		{name: "empty op", op: "", want: client.FailureDeadline},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := deadlineClass(tt.op); got != tt.want {
				t.Errorf("deadlineClass(%q) = %v, want %v", tt.op, got, tt.want)
			}
		})
	}
}
