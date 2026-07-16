// This file tests the OAuth flow's exported surface: origin canonicalization,
// provider construction, and the posture a provider reports. The flow itself —
// discovery, registration, browser, exchange, refresh — needs a real
// authorization server and is tested in oauth_integration_test.go.

package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/looprig/mcp/pkg/auth"
)

func TestCanonicalOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		// The normalizations. Each is two spellings of one origin, and the
		// whole point is that they collapse to one store key.
		{name: "already canonical", in: "https://example.com", want: "https://example.com"},
		{name: "path is dropped", in: "https://example.com/mcp", want: "https://example.com"},
		{name: "root path is dropped", in: "https://example.com/", want: "https://example.com"},
		{name: "query is dropped", in: "https://example.com/mcp?x=1", want: "https://example.com"},
		{name: "fragment is dropped", in: "https://example.com/mcp#f", want: "https://example.com"},
		{name: "host is lowercased", in: "https://Example.COM", want: "https://example.com"},
		{name: "scheme is lowercased", in: "HTTPS://example.com", want: "https://example.com"},
		{name: "default https port is dropped", in: "https://example.com:443", want: "https://example.com"},
		{name: "default http port is dropped on loopback", in: "http://127.0.0.1:80", want: "http://127.0.0.1"},
		{name: "non-default port is kept", in: "https://example.com:8443", want: "https://example.com:8443"},
		{name: "leading zeros are stripped from the port", in: "https://example.com:08443", want: "https://example.com:8443"},
		{
			name: "a leading-zero default port is still the default port",
			// The hole that a string compare against "443" misses.
			in:   "https://example.com:0443",
			want: "https://example.com",
		},
		{name: "trailing root label is dropped", in: "https://example.com.", want: "https://example.com"},
		{name: "everything at once", in: "HTTPS://Example.COM.:0443/mcp?x=1#f", want: "https://example.com"},
		{name: "loopback http is allowed", in: "http://127.0.0.1:8080/mcp", want: "http://127.0.0.1:8080"},
		{name: "localhost http is allowed", in: "http://localhost:3000", want: "http://localhost:3000"},
		{name: "loopback name is lowercased", in: "http://LocalHost:3000", want: "http://localhost:3000"},
		{name: "ipv6 loopback", in: "http://[::1]:8080", want: "http://[::1]:8080"},
		{name: "ipv6 literal is compressed", in: "https://[2001:db8:0:0:0:0:0:1]", want: "https://[2001:db8::1]"},
		{name: "ipv6 literal hex is lowercased", in: "https://[2001:DB8::1]", want: "https://[2001:db8::1]"},
		{name: "ipv6 loopback long form", in: "http://[0:0:0:0:0:0:0:1]:9000", want: "http://[::1]:9000"},
		{name: "ipv4 host", in: "https://192.0.2.1:8443", want: "https://192.0.2.1:8443"},
		{name: "underscore in a label", in: "https://my_service.example.com", want: "https://my_service.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := auth.CanonicalOrigin(tt.in)
			if err != nil {
				t.Fatalf("CanonicalOrigin(%q) error = %v, want nil", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("CanonicalOrigin(%q) = %q, want %q", tt.in, got, tt.want)
			}

			// The invariant that ties this function to Key.Validate: anything
			// this returns is a key Validate accepts. Without it the two could
			// drift and the "canonical" contract would be a comment.
			if err := (auth.Key{ServerOrigin: got}).Validate(); err != nil {
				t.Errorf("Key{ServerOrigin: CanonicalOrigin(%q)}.Validate() error = %v, want nil", tt.in, err)
			}
			// And idempotence: canonicalizing a canonical origin changes
			// nothing. A canonicalizer without this is a normalizer that has
			// not finished.
			again, err := auth.CanonicalOrigin(got)
			if err != nil {
				t.Errorf("CanonicalOrigin(%q) on its own output error = %v", got, err)
			}
			if again != got {
				t.Errorf("CanonicalOrigin is not idempotent: %q -> %q -> %q", tt.in, got, again)
			}
		})
	}
}

func TestCanonicalOriginRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{name: "empty"},
		{name: "userinfo carries a credential we may not silently drop", in: "https://user:pw@example.com"},
		{name: "userinfo without a password", in: "https://user@example.com"},
		{name: "cleartext to a public host", in: "http://example.com"},
		{name: "cleartext to a public host with a port", in: "http://example.com:8080"},
		{name: "an unknown scheme", in: "ftp://example.com"},
		{name: "javascript", in: "javascript:alert(1)"},
		{name: "data", in: "data:text/html,x"},
		{name: "file", in: "file:///etc/passwd"},
		{name: "no scheme", in: "example.com"},
		{name: "scheme but no host", in: "https://"},
		{name: "an opaque URL", in: "https:example.com"},
		{name: "a non-ASCII host needs an A-label from the caller", in: "https://exämple.com"},
		{name: "a homograph host", in: "https://exaаmple.com"},
		{name: "an IPv6 zone is not an identity", in: "https://[fe80::1%25eth0]:8443"},
		{name: "port zero", in: "https://example.com:0"},
		{name: "port out of range", in: "https://example.com:99999"},
		{name: "a newline in the host is log forging", in: "https://example.com\n/x"},
		{name: "a control character", in: "https://exam\x00ple.com"},
		{name: "a space in the host", in: "https://exa mple.com"},
		{name: "an empty label", in: "https://a..b.example.com"},
		{name: "two trailing dots", in: "https://example.com.."},
		{name: "an over-long URL", in: "https://example.com/" + strings.Repeat("a", auth.MaxURLBytes)},
		{
			name: "an over-long origin",
			// The host alone exceeds MaxOriginBytes while the URL stays under
			// MaxURLBytes: the two bounds are separate and both must hold.
			in: "https://" + strings.Repeat("a", auth.MaxOriginBytes+10) + ".com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := auth.CanonicalOrigin(tt.in)
			if err == nil {
				t.Fatalf("CanonicalOrigin(%q) = %q, want an error", tt.in, got)
			}
			if class, ok := auth.ClassOf(err); !ok || class != auth.ClassInvalidConfig {
				t.Errorf("CanonicalOrigin(%q) error class = %v (found %v), want %v", tt.in, class, ok, auth.ClassInvalidConfig)
			}
			if got != "" {
				t.Errorf("CanonicalOrigin(%q) = %q on failure, want the empty string", tt.in, got)
			}
		})
	}
}

// A rejection message goes to a log. It must not quote a credential back, which
// is the one thing a URL can carry that a log must not.
func TestCanonicalOriginDoesNotLeakUserinfo(t *testing.T) {
	t.Parallel()

	_, err := auth.CanonicalOrigin("https://user:" + canary + "@example.com")
	if err == nil {
		t.Fatal("CanonicalOrigin() = nil error, want a rejection")
	}
	for _, verb := range verbs {
		if got := strings.ToLower(fmt.Sprintf(verb, err)); strings.Contains(got, strings.ToLower(canary)) {
			t.Errorf("fmt.Sprintf(%q, err) leaked the password from the URL: %s", verb, got)
		}
	}
}

// fixtureConfig is a minimal valid config for construction tests.
func fixtureConfig() auth.OAuthConfig {
	return auth.OAuthConfig{
		ServerURL: "https://mcp.example.com/mcp",
		Store:     auth.NewMemoryStore(),
		Browser:   refusingBrowser{},
	}
}

func TestNewOAuthProviderValidates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*auth.OAuthConfig)
		wantErr bool
	}{
		{name: "valid", mutate: func(*auth.OAuthConfig) {}},
		{
			name:   "a client ID makes it a registered client",
			mutate: func(c *auth.OAuthConfig) { c.Credentials = auth.NewClientCredentials("cid", "") },
		},
		{
			name:   "loopback http server",
			mutate: func(c *auth.OAuthConfig) { c.ServerURL = "http://127.0.0.1:8080/mcp" },
		},
		{name: "scopes", mutate: func(c *auth.OAuthConfig) { c.Scopes = []string{"read", "write"} }},
		{name: "no ServerURL", mutate: func(c *auth.OAuthConfig) { c.ServerURL = "" }, wantErr: true},
		{
			name:    "cleartext ServerURL",
			mutate:  func(c *auth.OAuthConfig) { c.ServerURL = "http://mcp.example.com" },
			wantErr: true,
		},
		{name: "no Store", mutate: func(c *auth.OAuthConfig) { c.Store = nil }, wantErr: true},
		{name: "no Browser", mutate: func(c *auth.OAuthConfig) { c.Browser = nil }, wantErr: true},
		{
			name: "a scope containing a space is two scopes wearing a trench coat",
			// Space is the scope-list separator (RFC 6749 §3.3).
			mutate:  func(c *auth.OAuthConfig) { c.Scopes = []string{"read write"} },
			wantErr: true,
		},
		{name: "an empty scope", mutate: func(c *auth.OAuthConfig) { c.Scopes = []string{""} }, wantErr: true},
		{
			name:    "a newline in a scope",
			mutate:  func(c *auth.OAuthConfig) { c.Scopes = []string{"read\nwrite"} },
			wantErr: true,
		},
		{
			name:    "a control character in ClientName",
			mutate:  func(c *auth.OAuthConfig) { c.ClientName = "bad\nname" },
			wantErr: true,
		},
		{
			name:    "a negative AuthorizationTimeout",
			mutate:  func(c *auth.OAuthConfig) { c.AuthorizationTimeout = -time.Second },
			wantErr: true,
		},
		{
			name: "an over-long client ID cannot key the store",
			mutate: func(c *auth.OAuthConfig) {
				c.Credentials = auth.NewClientCredentials(strings.Repeat("c", auth.MaxClientIDBytes+1), "")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := fixtureConfig()
			tt.mutate(&cfg)

			provider, err := auth.NewOAuthProvider(cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewOAuthProvider() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if provider != nil {
					t.Error("NewOAuthProvider() returned a provider alongside an error")
				}
				// Nothing has been attempted yet, so a construction failure is
				// always the caller's configuration, never an auth outcome.
				if class, ok := auth.ClassOf(err); !ok || class != auth.ClassInvalidConfig {
					t.Errorf("error class = %v (found %v), want %v", class, ok, auth.ClassInvalidConfig)
				}
				return
			}
			if provider == nil {
				t.Fatal("NewOAuthProvider() = nil, want a provider")
			}
		})
	}
}

// Construction does no I/O. A provider pointed at a black hole must still
// build: nothing is discovered until Token is called.
func TestNewOAuthProviderDoesNoIO(t *testing.T) {
	t.Parallel()

	cfg := fixtureConfig()
	// A host that does not resolve. If construction touched the network this
	// would fail or hang.
	cfg.ServerURL = "https://this-host-does-not-exist.invalid/mcp"
	cfg.HTTPClient = &http.Client{Timeout: time.Millisecond}

	if _, err := auth.NewOAuthProvider(cfg); err != nil {
		t.Errorf("NewOAuthProvider() error = %v; construction must not do I/O", err)
	}
}

// A fresh provider needs credentials and says so. StateRequired is the state
// that warrants an interactive login, and it is what a UI branches on.
func TestNewProviderStatusIsRequired(t *testing.T) {
	t.Parallel()

	provider, err := auth.NewOAuthProvider(fixtureConfig())
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}
	status := provider.Status()
	if status.State != auth.StateRequired {
		t.Errorf("Status().State = %v, want %v", status.State, auth.StateRequired)
	}
	if status.Failure != "" {
		t.Errorf("Status().Failure = %q, want empty before anything has been attempted", status.Failure)
	}
}

// The contract the HTTP transport in 3.3 depends on. Asserted as a value rather
// than only as the compile-time var in oauth.go, so the failure names the
// interface.
func TestOAuthProviderIsAHeaderProvider(t *testing.T) {
	t.Parallel()

	provider, err := auth.NewOAuthProvider(fixtureConfig())
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}
	var _ auth.HeaderProvider = provider
}

// A stored, valid token is returned without any I/O and without a browser —
// the top rung of the ladder. The refusing browser is the assertion: if the
// flow tried to authorize, this test fails.
func TestTokenReturnsAStoredValidToken(t *testing.T) {
	t.Parallel()

	store := auth.NewMemoryStore()
	cfg := fixtureConfig()
	cfg.Store = store
	cfg.Credentials = auth.NewClientCredentials("cid", "")
	// A client that would fail loudly if the flow tried to reach the network.
	cfg.HTTPClient = &http.Client{Timeout: time.Millisecond}

	provider, err := auth.NewOAuthProvider(cfg)
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}

	want := auth.NewTokenSet("stored-access", "stored-refresh", time.Now().Add(time.Hour), []string{"read"})
	key := auth.Key{ServerOrigin: "https://mcp.example.com", ClientID: "cid"}
	if err := store.Store(context.Background(), key, want); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	got, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if got.Access() != "stored-access" {
		t.Errorf("Token().Access() = %q, want the stored token", got.Access())
	}
	if status := provider.Status(); status.State != auth.StateAuthenticated {
		t.Errorf("Status().State = %v, want %v", status.State, auth.StateAuthenticated)
	}

	// And through the HeaderProvider seam the transport uses.
	headers, err := provider.Headers(context.Background())
	if err != nil {
		t.Fatalf("Headers() error = %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("Headers() returned %d headers, want 1", len(headers))
	}
	if headers[0].Name() != "Authorization" {
		t.Errorf("Headers()[0].Name() = %q, want Authorization", headers[0].Name())
	}
	if headers[0].Value() != "Bearer stored-access" {
		t.Errorf("Headers()[0].Value() = %q, want the bearer token", headers[0].Value())
	}
	if err := headers[0].Validate(); err != nil {
		t.Errorf("Headers()[0].Validate() error = %v", err)
	}
}

// A store that is broken is not a store that is empty: a keyring failure must
// not be papered over with a browser window.
func TestTokenPropagatesAStoreFailure(t *testing.T) {
	t.Parallel()

	cfg := fixtureConfig()
	cfg.Store = brokenStore{}
	cfg.Credentials = auth.NewClientCredentials("cid", "")

	provider, err := auth.NewOAuthProvider(cfg)
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}

	// The refusing browser in fixtureConfig is the real assertion here: if the
	// ladder fell through to the flow, the error would be the browser's.
	_, err = provider.Token(context.Background())
	if err == nil {
		t.Fatal("Token() = nil error, want the store's failure")
	}
	if !errors.Is(err, errBrokenStore) {
		t.Errorf("Token() error = %v, want it to wrap the store's failure", err)
	}
	if status := provider.Status(); status.State != auth.StateFailed {
		t.Errorf("Status().State = %v, want %v", status.State, auth.StateFailed)
	}
}

// A cancelled context is refused before any work is done.
func TestTokenHonorsACancelledContext(t *testing.T) {
	t.Parallel()

	provider, err := auth.NewOAuthProvider(fixtureConfig())
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := provider.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Token(cancelled) error = %v, want it to wrap context.Canceled", err)
	}
}

// A provider's own failure text is published into its Status, which is designed
// to be logged as-is. Nothing secret may reach it.
func TestStatusFailureCarriesNoSecret(t *testing.T) {
	t.Parallel()

	cfg := fixtureConfig()
	cfg.Store = brokenStore{}
	cfg.Credentials = auth.NewClientCredentials("cid", canary)

	provider, err := auth.NewOAuthProvider(cfg)
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}
	if _, err := provider.Token(context.Background()); err == nil {
		t.Fatal("Token() = nil error, want a failure")
	}
	if got := provider.Status().Failure; strings.Contains(got, canary) {
		t.Errorf("Status().Failure leaked the client secret: %q", got)
	}
}

// Credentials round-trip so a caller can persist a registration.
func TestCredentialsAreReadable(t *testing.T) {
	t.Parallel()

	cfg := fixtureConfig()
	cfg.Credentials = auth.NewClientCredentials("cid", "shh")

	provider, err := auth.NewOAuthProvider(cfg)
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}
	creds := provider.Credentials()
	if creds.ID() != "cid" {
		t.Errorf("Credentials().ID() = %q, want cid", creds.ID())
	}
	if creds.Secret() != "shh" {
		t.Errorf("Credentials().Secret() = %q, want the secret back verbatim", creds.Secret())
	}
	if !creds.Valid() || !creds.Confidential() {
		t.Errorf("Credentials() = %v, want a valid confidential client", creds)
	}

	public := auth.NewClientCredentials("cid", "")
	if !public.Valid() || public.Confidential() {
		t.Errorf("a client with no secret = %v, want valid but not confidential", public)
	}
	var zero auth.ClientCredentials
	if zero.Valid() {
		t.Error("the zero ClientCredentials reports Valid() = true; it is an unregistered client")
	}
}

var errBrokenStore = errors.New("the keyring is on fire")

// brokenStore fails every operation with something that is emphatically not
// ErrNoToken.
type brokenStore struct{}

func (brokenStore) Load(context.Context, auth.Key) (auth.TokenSet, error) {
	return auth.TokenSet{}, auth.NewError(auth.ClassFailed, "load", "the store is broken", errBrokenStore)
}

func (brokenStore) Store(context.Context, auth.Key, auth.TokenSet) error {
	return auth.NewError(auth.ClassFailed, "store", "the store is broken", errBrokenStore)
}

func (brokenStore) Delete(context.Context, auth.Key) error {
	return auth.NewError(auth.ClassFailed, "delete", "the store is broken", errBrokenStore)
}
