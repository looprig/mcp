//go:build integration

// This file drives the whole OAuth flow against a real authorization server:
// real TLS, real HTTP, real redirects, a real browser round trip, and real PKCE
// verification. It is tagged integration because it stands up servers and
// listens on loopback ports; the unit tests next door cover the pieces.
//
// The fixture server is not a stub that says yes. It verifies the PKCE
// challenge the way a conforming server does — recomputing S256 over the
// verifier we send and comparing it to the challenge we sent earlier — so a
// mistake in our S256 transformation fails here as "PKCE verification failed"
// rather than passing quietly. It rotates refresh tokens and invalidates the
// old one, so the rotation rule is tested against a server that actually
// enforces it. And it counts requests, so "never retry a token exchange" is an
// assertion about observed behavior rather than about the shape of the code.

package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/pkg/auth"
)

// authServer is a conforming-enough OAuth 2.0 authorization server, with knobs
// for the ways a server can be hostile or broken.
type authServer struct {
	server *httptest.Server

	mu sync.Mutex
	// codes maps an issued authorization code to the PKCE challenge it is bound
	// to. A conforming server binds them; that binding is what PKCE is.
	codes map[string]string
	// refreshTokens holds the refresh tokens currently valid. Rotation removes
	// the old one, which is what makes reuse detectable.
	refreshTokens map[string]bool
	// tokenRequests counts requests to /token, so "never retry" is measurable.
	tokenRequests int
	// registrations counts dynamic client registrations.
	registrations int
	nextToken     int

	// Knobs.
	challengeMethods []string // what the server advertises for PKCE
	issuerOverride   string   // a lying issuer, for the mix-up attack
	noRegistration   bool     // a server without dynamic registration
	tokenStatus      int      // a forced token-endpoint status, for no-retry
}

func newAuthServer(t *testing.T) *authServer {
	t.Helper()

	as := &authServer{
		codes:            make(map[string]string),
		refreshTokens:    make(map[string]bool),
		challengeMethods: []string{"S256"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", as.handleProtectedResource)
	mux.HandleFunc("/.well-known/oauth-authorization-server", as.handleAuthServerMeta)
	mux.HandleFunc("/register", as.handleRegister)
	mux.HandleFunc("/authorize", as.handleAuthorize)
	mux.HandleFunc("/token", as.handleToken)

	as.server = httptest.NewTLSServer(mux)
	t.Cleanup(as.server.Close)
	return as
}

// URL is the authorization server's (and the protected resource's) origin.
func (a *authServer) URL() string { return a.server.URL }

// serverURL is the MCP server URL the provider is pointed at.
func (a *authServer) serverURL() string { return a.server.URL + "/mcp" }

// client returns an HTTP client that trusts the fixture's TLS certificate.
//
// This is why the test can use real TLS without InsecureSkipVerify anywhere:
// httptest hands out a client with its own certificate in the pool, which is
// certificate verification working, not being skipped.
func (a *authServer) client() *http.Client { return a.server.Client() }

func (a *authServer) issuer() string {
	if a.issuerOverride != "" {
		return a.issuerOverride
	}
	return a.server.URL
}

// writeJSON writes a JSON response with an explicit status.
//
// The status is a parameter rather than a separate WriteHeader call because the
// order matters and getting it wrong is silent: WriteHeader flushes the header
// block, so any Header().Set after it is discarded and the response goes out as
// text/plain. That is a real bug this fixture had, and the client caught it by
// refusing a discovery document that did not claim to be JSON — which is the
// content-type check doing exactly its job.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (a *authServer) handleProtectedResource(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":              a.server.URL,
		"authorization_servers": []string{a.server.URL},
		"scopes_supported":      []string{"mcp:read", "mcp:write"},
	})
}

func (a *authServer) handleAuthServerMeta(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{
		"issuer":                                a.issuer(),
		"authorization_endpoint":                a.server.URL + "/authorize",
		"token_endpoint":                        a.server.URL + "/token",
		"code_challenge_methods_supported":      a.challengeMethods,
		"scopes_supported":                      []string{"mcp:read", "mcp:write"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"response_types_supported":              []string{"code"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	}
	if !a.noRegistration {
		body["registration_endpoint"] = a.server.URL + "/register"
	}
	writeJSON(w, http.StatusOK, body)
}

func (a *authServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.registrations++
	id := fmt.Sprintf("registered-client-%d", a.registrations)
	a.mu.Unlock()

	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// A conforming server records the redirect URIs. The flow must have sent
	// the real, already-bound loopback port here — see newRedirectServer.
	uris, _ := req["redirect_uris"].([]any)
	if len(uris) != 1 {
		http.Error(w, "want exactly one redirect_uri", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":           id,
		"client_id_issued_at": time.Now().Unix(),
	})
}

// handleAuthorize is the authorization endpoint. It validates the request the
// way a conforming server does and redirects the browser back with a code.
func (a *authServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	if got := query.Get("response_type"); got != "code" {
		http.Error(w, "unsupported response_type "+got, http.StatusBadRequest)
		return
	}
	// PKCE is mandatory at this fixture: a client that sends no challenge, or
	// sends "plain", is refused. That makes "we never downgrade" testable from
	// the server's side too.
	challenge := query.Get("code_challenge")
	if challenge == "" {
		http.Error(w, "missing code_challenge", http.StatusBadRequest)
		return
	}
	if got := query.Get("code_challenge_method"); got != "S256" {
		http.Error(w, "refusing code_challenge_method "+got, http.StatusBadRequest)
		return
	}
	redirectURI := query.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	a.nextToken++
	code := fmt.Sprintf("auth-code-%d", a.nextToken)
	a.codes[code] = challenge
	a.mu.Unlock()

	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	q := target.Query()
	q.Set("code", code)
	q.Set("state", query.Get("state"))
	target.RawQuery = q.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

// handleToken is the token endpoint. It performs real PKCE verification and
// real refresh-token rotation.
func (a *authServer) handleToken(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.tokenRequests++
	forced := a.tokenStatus
	a.mu.Unlock()

	if forced != 0 {
		writeJSON(w, forced, map[string]any{"error": "server_error"})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	switch r.Form.Get("grant_type") {
	case "authorization_code":
		a.handleCodeGrant(w, r)
	case "refresh_token":
		a.handleRefreshGrant(w, r)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
	}
}

func (a *authServer) handleCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	verifier := r.Form.Get("code_verifier")

	a.mu.Lock()
	challenge, ok := a.codes[code]
	// A code is single-use, by specification. Deleting it here is what makes a
	// retried exchange fail — and therefore what makes "never retry" matter.
	delete(a.codes, code)
	a.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "unknown or used code"})
		return
	}
	// The actual PKCE check, done the way RFC 7636 §4.6 specifies. If our S256
	// is wrong in any way, the flow dies here.
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}
	a.issueTokens(w, "")
}

func (a *authServer) handleRefreshGrant(w http.ResponseWriter, r *http.Request) {
	presented := r.Form.Get("refresh_token")

	a.mu.Lock()
	valid := a.refreshTokens[presented]
	if valid {
		// Rotation: the presented token dies here. Reusing it afterwards is
		// invalid_grant, which is what lets the test prove rotation happened.
		delete(a.refreshTokens, presented)
	}
	a.mu.Unlock()

	if !valid {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "unknown or rotated refresh token"})
		return
	}
	a.issueTokens(w, "")
}

// issueTokens mints a fresh access/refresh pair and records the refresh token
// as valid.
func (a *authServer) issueTokens(w http.ResponseWriter, _ string) {
	a.mu.Lock()
	a.nextToken++
	n := a.nextToken
	access := fmt.Sprintf("access-token-%d", n)
	refresh := fmt.Sprintf("refresh-token-%d", n)
	a.refreshTokens[refresh] = true
	a.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refresh,
		"scope":         "mcp:read mcp:write",
	})
}

func (a *authServer) counts() (tokenRequests, registrations int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokenRequests, a.registrations
}

// fakeBrowser is the user: it fetches the authorization URL and follows the
// redirect back to the loopback listener, which is exactly what a real browser
// does.
//
// It runs the round trip on its own goroutine because BrowserOpener's contract
// says OpenURL hands the URL off and returns promptly — it never waits for the
// user to finish. Blocking here would deadlock against the flow, which is
// already waiting on the listener.
type fakeBrowser struct {
	client *http.Client
	// rewrite lets a test tamper with the authorization URL before it is
	// fetched, which is how the CSRF attack is staged.
	rewrite func(string) string

	mu     sync.Mutex
	opened []string
	err    error
}

func (b *fakeBrowser) OpenURL(ctx context.Context, raw string) error {
	b.mu.Lock()
	b.opened = append(b.opened, raw)
	b.mu.Unlock()

	target := raw
	if b.rewrite != nil {
		target = b.rewrite(raw)
	}
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			b.fail(err)
			return
		}
		resp, err := b.client.Do(req)
		if err != nil {
			b.fail(err)
			return
		}
		_ = resp.Body.Close()
	}()
	return nil
}

func (b *fakeBrowser) fail(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err == nil {
		b.err = err
	}
}

func (b *fakeBrowser) openedURLs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.opened...)
}

// newProvider wires a provider to the fixture, with a fake browser.
func newProvider(t *testing.T, as *authServer, browser auth.BrowserOpener, store auth.TokenStore) *auth.OAuthProvider {
	t.Helper()

	provider, err := auth.NewOAuthProvider(auth.OAuthConfig{
		ServerURL:  as.serverURL(),
		Store:      store,
		Browser:    browser,
		HTTPClient: as.client(),
		// Short: no test here waits for a real human, and a hung flow should
		// fail the test rather than the whole run.
		AuthorizationTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}
	return provider
}

// The whole thing: discovery, dynamic registration, the browser round trip,
// PKCE verification, the exchange, persistence, refresh, and rotation.
func TestOAuthFlowEndToEnd(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	browser := &fakeBrowser{client: as.client()}
	store := auth.NewMemoryStore()
	provider := newProvider(t, as, browser, store)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// --- The full flow, from nothing.
	set, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if set.Access() != "access-token-2" {
		t.Errorf("Token().Access() = %q, want the issued access token", set.Access())
	}
	if set.Refresh() == "" {
		t.Error("Token().Refresh() is empty, want the issued refresh token")
	}
	if set.Expiry().IsZero() {
		t.Error("Token().Expiry() is zero, want expires_in to have been honored")
	}
	if got, want := set.Scopes(), []string{"mcp:read", "mcp:write"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Token().Scopes() = %v, want %v", got, want)
	}
	if status := provider.Status(); status.State != auth.StateAuthenticated {
		t.Errorf("Status().State = %v, want %v", status.State, auth.StateAuthenticated)
	}

	// The browser was actually used, and the URL it got was an authorization
	// request carrying an S256 challenge.
	opened := browser.openedURLs()
	if len(opened) != 1 {
		t.Fatalf("the browser was opened %d times, want once", len(opened))
	}
	authURL, err := url.Parse(opened[0])
	if err != nil {
		t.Fatalf("the browser was given an unparseable URL: %v", err)
	}
	if got := authURL.Query().Get("code_challenge_method"); got != "S256" {
		t.Errorf("authorization URL code_challenge_method = %q, want S256", got)
	}
	if authURL.Query().Get("code_challenge") == "" {
		t.Error("authorization URL carries no code_challenge")
	}
	// RFC 8707: the token is bound to this resource.
	if got := authURL.Query().Get("resource"); got != as.serverURL() {
		t.Errorf("authorization URL resource = %q, want %q", got, as.serverURL())
	}
	// The verifier must never appear in the URL the browser (and the
	// authorization server, and any URL logger between them) sees. Only its
	// hash may.
	if strings.Contains(opened[0], "code_verifier") {
		t.Error("the authorization URL carries the code_verifier; only the challenge may be sent")
	}

	// --- Registration happened, and is readable so the caller can persist it.
	creds := provider.Credentials()
	if creds.ID() != "registered-client-1" {
		t.Errorf("Credentials().ID() = %q, want the dynamically registered client", creds.ID())
	}
	if _, registrations := as.counts(); registrations != 1 {
		t.Errorf("the server saw %d registrations, want 1", registrations)
	}

	// --- The token was persisted, under the registered client's key.
	key := auth.Key{ServerOrigin: mustCanonical(t, as.URL()), ClientID: creds.ID()}
	stored, err := store.Load(ctx, key)
	if err != nil {
		t.Fatalf("the token was not persisted: %v", err)
	}
	if stored.Access() != set.Access() {
		t.Errorf("stored access token = %q, want %q", stored.Access(), set.Access())
	}

	// --- A second call uses the stored token: no browser, no token request.
	tokenRequestsBefore, _ := as.counts()
	again, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("Token() (cached) error = %v", err)
	}
	if again.Access() != set.Access() {
		t.Errorf("Token() (cached) = %q, want the same token back", again.Access())
	}
	if tokenRequests, _ := as.counts(); tokenRequests != tokenRequestsBefore {
		t.Errorf("a cached Token() made %d token requests, want 0", tokenRequests-tokenRequestsBefore)
	}
	if opened := browser.openedURLs(); len(opened) != 1 {
		t.Errorf("a cached Token() opened the browser again (%d total)", len(opened))
	}

	// --- Refresh: expire the stored token, and the next call refreshes it
	// silently rather than opening a browser.
	oldRefresh := set.Refresh()
	expired := auth.NewTokenSet(set.Access(), oldRefresh, time.Now().Add(-time.Hour), set.Scopes())
	if err := store.Store(ctx, key, expired); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	refreshed, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("Token() (refresh) error = %v", err)
	}
	if refreshed.Access() == set.Access() {
		t.Error("Token() (refresh) returned the old access token; want a newly minted one")
	}
	if refreshed.Expired(time.Now()) {
		t.Error("the refreshed token is already expired")
	}
	if opened := browser.openedURLs(); len(opened) != 1 {
		t.Errorf("a refresh opened the browser (%d total); a refresh must not need a human", len(opened))
	}

	// --- Rotation: the server rotated, so the new refresh token must have
	// replaced the old one, and the old one must be gone.
	if refreshed.Refresh() == oldRefresh {
		t.Error("the refresh token was not rotated; the server issued a new one and it was discarded")
	}
	if refreshed.Refresh() == "" {
		t.Fatal("the refreshed token set carries no refresh token")
	}
	rotatedStored, err := store.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load() after refresh error = %v", err)
	}
	if rotatedStored.Refresh() != refreshed.Refresh() {
		t.Errorf("the store holds refresh token %q, want the rotated one %q",
			rotatedStored.Refresh(), refreshed.Refresh())
	}
	if rotatedStored.Access() != refreshed.Access() {
		t.Error("the store was not updated with the refreshed access token")
	}
}

// Persistence across a restart: a second, independently constructed provider
// — standing in for the process starting over, pointed at the credentials and
// store the first process persisted — must reuse the token without a browser
// or another registration. This is the property that lets an application
// carry OAuth state across restarts using nothing but a persistent TokenStore
// and its own persisted client registration; the SDK's token-source hooks are
// not involved because this provider never uses them.
func TestOAuthFlowPersistsTokensAcrossProviderRestarts(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	store := auth.NewMemoryStore()

	// --- Process 1: the full flow, from nothing.
	browserA := &fakeBrowser{client: as.client()}
	providerA := newProvider(t, as, browserA, store)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	setA, err := providerA.Token(ctx)
	if err != nil {
		t.Fatalf("provider A: Token() error = %v", err)
	}
	credsA := providerA.Credentials()

	tokenRequestsBefore, registrationsBefore := as.counts()

	// --- Process 2: a fresh provider, configured with the client ID process 1
	// registered (exactly what a real application persists alongside the
	// token) and pointed at the same store. Its browser refuses outright: if
	// this provider so much as attempted to authorize, the test fails on that
	// refusal rather than silently opening a window.
	providerB, err := auth.NewOAuthProvider(auth.OAuthConfig{
		ServerURL:            as.serverURL(),
		Credentials:          credsA,
		Store:                store,
		Browser:              refusingBrowser{},
		HTTPClient:           as.client(),
		AuthorizationTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("provider B: NewOAuthProvider() error = %v", err)
	}

	headers, err := providerB.Headers(ctx)
	if err != nil {
		t.Fatalf("provider B: Headers() error = %v, want the stored token reused without authorization", err)
	}
	if len(headers) != 1 || headers[0].Value() != "Bearer "+setA.Access() {
		t.Errorf("provider B: Headers() = %v, want the bearer token issued to provider A", headers)
	}

	tokenRequestsAfter, registrationsAfter := as.counts()
	if tokenRequestsAfter != tokenRequestsBefore {
		t.Errorf("provider B made %d token requests, want 0: a restarted provider must not re-authorize",
			tokenRequestsAfter-tokenRequestsBefore)
	}
	if registrationsAfter != registrationsBefore {
		t.Errorf("provider B registered %d times, want 0: a restarted provider must not re-register",
			registrationsAfter-registrationsBefore)
	}
}

// The CSRF defense. An attacker who can reach the loopback listener feeds it a
// code of their own; if the client exchanges it, the user silently ends up
// operating as the attacker.
//
// The attack is staged by tampering with the state in the authorization URL, so
// the code that comes back is bound to a state the flow never issued — which is
// exactly what an injected callback looks like from the listener's side.
func TestOAuthFlowRejectsAStateMismatch(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	browser := &fakeBrowser{
		client: as.client(),
		rewrite: func(raw string) string {
			u, err := url.Parse(raw)
			if err != nil {
				return raw
			}
			q := u.Query()
			q.Set("state", "attacker-supplied-state")
			u.RawQuery = q.Encode()
			return u.String()
		},
	}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	// The flow will never complete, so the timeout is what ends it. Short,
	// because waiting is the expected outcome.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	set, err := provider.Token(ctx)
	if err == nil {
		t.Fatalf("Token() = %v, want a failure: the callback carried a forged state", set)
	}

	// The assertion that matters: no token was ever exchanged. A client that
	// rejects the state but exchanges the code first has no defense at all.
	if tokenRequests, _ := as.counts(); tokenRequests != 0 {
		t.Errorf("the client made %d token requests after a state mismatch, want 0", tokenRequests)
	}
	if _, err := provider.Token(ctx); err == nil {
		t.Error("a second Token() succeeded after a state mismatch")
	}
}

// The downgrade refusal, end to end: a server advertising only "plain" gets no
// flow at all.
//
// Note what is asserted beyond the error: the browser is never opened. Refusing
// after sending the user to a login page would be a poor refusal — the user
// would have authorized, and the client would then throw it away.
func TestOAuthFlowRejectsAPlainOnlyServer(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	as.challengeMethods = []string{"plain"}
	browser := &fakeBrowser{client: as.client()}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := provider.Token(ctx); err == nil {
		t.Fatal("Token() = nil error, want a refusal: the server offers only plain PKCE")
	} else if !strings.Contains(err.Error(), "S256") {
		t.Errorf("Token() error = %v, want it to name the missing S256 support", err)
	}
	if opened := browser.openedURLs(); len(opened) != 0 {
		t.Errorf("the browser was opened %d times against a plain-only server; refuse before involving the user", len(opened))
	}
	if tokenRequests, _ := as.counts(); tokenRequests != 0 {
		t.Errorf("the client made %d token requests against a plain-only server, want 0", tokenRequests)
	}
}

// Issuer validation (RFC 8414 §3.3), end to end: the mix-up attack.
//
// The server returns metadata claiming to be a different issuer than the one we
// fetched it from. A client that accepts it can be steered to redeem codes at
// an endpoint of the document's choosing.
func TestOAuthFlowRejectsAnIssuerMismatch(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	as.issuerOverride = "https://attacker.example.com"
	browser := &fakeBrowser{client: as.client()}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := provider.Token(ctx); err == nil {
		t.Fatal("Token() = nil error, want a refusal: the metadata issuer does not match")
	} else if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("Token() error = %v, want it to name the issuer mismatch", err)
	}
	if opened := browser.openedURLs(); len(opened) != 0 {
		t.Errorf("the browser was opened %d times against a lying issuer, want 0", len(opened))
	}
	if tokenRequests, _ := as.counts(); tokenRequests != 0 {
		t.Errorf("the client made %d token requests against a lying issuer, want 0", tokenRequests)
	}
}

// A token exchange is never retried, because it is not idempotent: the code is
// single-use and a rotated refresh token dies on use. A retry after an
// unseen response is a second, different request whose predecessor may have
// succeeded.
//
// The server fails every token request with a 500 — the most retry-tempting
// response there is. Exactly one request must arrive.
func TestOAuthFlowNeverRetriesATokenExchange(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	as.tokenStatus = http.StatusInternalServerError
	browser := &fakeBrowser{client: as.client()}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := provider.Token(ctx); err == nil {
		t.Fatal("Token() = nil error, want the token endpoint's failure")
	}
	if tokenRequests, _ := as.counts(); tokenRequests != 1 {
		t.Errorf("the client made %d token requests, want exactly 1: a token exchange is not idempotent", tokenRequests)
	}
}

// A server without dynamic registration and a client without an ID is a dead
// end, and must say so rather than starting a flow it cannot finish.
func TestOAuthFlowRequiresAClientIDWhenRegistrationIsUnsupported(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	as.noRegistration = true
	browser := &fakeBrowser{client: as.client()}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := provider.Token(ctx)
	if err == nil {
		t.Fatal("Token() = nil error, want a refusal")
	}
	if class, ok := auth.ClassOf(err); !ok || class != auth.ClassInvalidConfig {
		t.Errorf("Token() error class = %v (found %v), want %v", class, ok, auth.ClassInvalidConfig)
	}
	if opened := browser.openedURLs(); len(opened) != 0 {
		t.Errorf("the browser was opened %d times with no way to finish, want 0", len(opened))
	}
}

// A pre-registered client skips registration entirely — the path an application
// takes once it has persisted its credentials.
func TestOAuthFlowUsesAConfiguredClientID(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	browser := &fakeBrowser{client: as.client()}
	store := auth.NewMemoryStore()

	provider, err := auth.NewOAuthProvider(auth.OAuthConfig{
		ServerURL:            as.serverURL(),
		Credentials:          auth.NewClientCredentials("preregistered", ""),
		Scopes:               []string{"mcp:read"},
		Store:                store,
		Browser:              browser,
		HTTPClient:           as.client(),
		AuthorizationTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := provider.Token(ctx); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if _, registrations := as.counts(); registrations != 0 {
		t.Errorf("a pre-registered client registered %d times, want 0", registrations)
	}

	opened := browser.openedURLs()
	if len(opened) != 1 {
		t.Fatalf("the browser was opened %d times, want once", len(opened))
	}
	authURL, err := url.Parse(opened[0])
	if err != nil {
		t.Fatalf("unparseable authorization URL: %v", err)
	}
	if got := authURL.Query().Get("client_id"); got != "preregistered" {
		t.Errorf("authorization URL client_id = %q, want the configured one", got)
	}
	// The configured scope was requested, rather than the resource's advertised
	// default.
	if got := authURL.Query().Get("scope"); got != "mcp:read" {
		t.Errorf("authorization URL scope = %q, want mcp:read", got)
	}
}

// A dead refresh token falls through to a browser flow rather than failing:
// invalid_grant means the grant is over, and re-authorizing is the remedy.
func TestOAuthFlowReauthorizesWhenTheRefreshTokenIsDead(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	browser := &fakeBrowser{client: as.client()}
	store := auth.NewMemoryStore()

	provider, err := auth.NewOAuthProvider(auth.OAuthConfig{
		ServerURL:            as.serverURL(),
		Credentials:          auth.NewClientCredentials("preregistered", ""),
		Store:                store,
		Browser:              browser,
		HTTPClient:           as.client(),
		AuthorizationTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// An expired access token with a refresh token the server has never heard
	// of: the shape of a grant that was revoked while we were away.
	key := auth.Key{ServerOrigin: mustCanonical(t, as.URL()), ClientID: "preregistered"}
	dead := auth.NewTokenSet("stale", "never-issued-refresh-token", time.Now().Add(-time.Hour), nil)
	if err := store.Store(ctx, key, dead); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	set, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error = %v, want a fresh browser flow after a dead refresh token", err)
	}
	if set.Access() == "stale" {
		t.Error("Token() returned the stale token")
	}
	if opened := browser.openedURLs(); len(opened) != 1 {
		t.Errorf("the browser was opened %d times, want once: a dead grant needs a human", len(opened))
	}
}

// Concurrent callers cooperate: the first runs the flow and the rest wait for
// its result. Ten browser windows for one connection would be a bug the user
// experiences directly.
func TestOAuthFlowIsSingleFlight(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	browser := &fakeBrowser{client: as.client()}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callers = 10
	var wg sync.WaitGroup
	tokens := make([]string, callers)
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			set, err := provider.Token(ctx)
			tokens[i], errs[i] = set.Access(), err
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: Token() error = %v", i, err)
		}
		if tokens[i] != tokens[0] {
			t.Errorf("caller %d got token %q, caller 0 got %q; want one flow shared by all", i, tokens[i], tokens[0])
		}
	}
	if opened := browser.openedURLs(); len(opened) != 1 {
		t.Errorf("%d concurrent callers opened %d browser windows, want 1", callers, len(opened))
	}
}

// instantBrowser completes the whole callback synchronously, before OpenURL
// returns — the fastest a browser can possibly be.
//
// This is a regression test for a real race. The listener's expected state used
// to be published inside wait(), which runs after OpenURL: a callback arriving
// in between was matched against the zero state, rejected at the door, and the
// flow then blocked until it timed out. The ordinary fakeBrowser never caught
// it, because a goroutine plus a network round trip always lost the race to the
// next statement. This browser always wins it.
type instantBrowser struct {
	client *http.Client
	mu     sync.Mutex
	opened int
}

func (b *instantBrowser) OpenURL(ctx context.Context, raw string) error {
	b.mu.Lock()
	b.opened++
	b.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// The listener must be armed before the browser is opened, so a callback that
// lands the instant the URL is handed over is still accepted.
func TestOAuthFlowAcceptsAnInstantCallback(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	browser := &instantBrowser{client: as.client()}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	// Deliberately shorter than the flow's authorization timeout: if the
	// listener is armed too late the callback is rejected and the flow blocks,
	// so this deadline is what turns that race into a failure rather than a
	// 15-second pause.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	set, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error = %v; the callback arrived before OpenURL returned and must still be accepted", err)
	}
	if !set.Valid() {
		t.Error("Token() returned an invalid token set")
	}
}

// The redirect listener binds loopback only. A listener reachable from the
// network is an authorization-code interceptor for anyone on it.
func TestRedirectListenerIsLoopbackOnly(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	var redirectURI string
	browser := &fakeBrowser{
		client: as.client(),
		rewrite: func(raw string) string {
			if u, err := url.Parse(raw); err == nil {
				redirectURI = u.Query().Get("redirect_uri")
			}
			return raw
		},
	}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := provider.Token(ctx); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if redirectURI == "" {
		t.Fatal("no redirect_uri was sent")
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("unparseable redirect_uri %q: %v", redirectURI, err)
	}
	if u.Hostname() != "127.0.0.1" {
		t.Errorf("redirect_uri host = %q, want 127.0.0.1: the listener must not be reachable off-host", u.Hostname())
	}
	if u.Scheme != "http" {
		t.Errorf("redirect_uri scheme = %q, want http (loopback)", u.Scheme)
	}
}

// The listener is closed when the flow ends, and the port released. A flow that
// leaks its listener holds a port for the process's lifetime, and a cancelled
// one is the case that leaks.
func TestRedirectListenerClosesAfterACancelledFlow(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	var redirectURI string
	var mu sync.Mutex
	browser := &fakeBrowser{
		client: as.client(),
		rewrite: func(raw string) string {
			mu.Lock()
			if u, err := url.Parse(raw); err == nil {
				redirectURI = u.Query().Get("redirect_uri")
			}
			mu.Unlock()
			// Never complete the callback: the flow will time out, which is the
			// case under test.
			return ""
		},
	}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := provider.Token(ctx); err == nil {
		t.Fatal("Token() = nil error, want a timeout")
	}

	mu.Lock()
	uri := redirectURI
	mu.Unlock()
	if uri == "" {
		t.Fatal("no redirect_uri was observed")
	}

	// The port must be dead. A connection to a closed listener is refused
	// promptly; a leaked one would answer.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer probeCancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, uri, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Error("the redirect listener is still answering after the flow ended; the port was leaked")
	}
}

// A refusing BrowserOpener — a headless service, an SSH session — is a
// legitimate implementation, and refusing must read as "credentials are
// required", not as a crash.
func TestOAuthFlowSurfacesABrowserRefusal(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	provider := newProvider(t, as, refusingBrowser{}, auth.NewMemoryStore())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := provider.Token(ctx)
	if err == nil {
		t.Fatal("Token() = nil error, want the browser's refusal")
	}
	if class, ok := auth.ClassOf(err); !ok || class != auth.ClassRequired {
		t.Errorf("Token() error class = %v (found %v), want %v", class, ok, auth.ClassRequired)
	}
	if status := provider.Status(); status.State != auth.StateRequired {
		t.Errorf("Status().State = %v, want %v", status.State, auth.StateRequired)
	}
	if tokenRequests, _ := as.counts(); tokenRequests != 0 {
		t.Errorf("the client made %d token requests without a browser, want 0", tokenRequests)
	}
}

// No secret from a real flow may reach an error, a Status, or a log line. This
// is the promise, tested against real server-issued material rather than
// against a planted canary.
func TestOAuthFlowKeepsRealTokensOutOfRenderings(t *testing.T) {
	t.Parallel()

	as := newAuthServer(t)
	browser := &fakeBrowser{client: as.client()}
	provider := newProvider(t, as, browser, auth.NewMemoryStore())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	set, err := provider.Token(ctx)
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	access, refresh := set.Access(), set.Refresh()
	if access == "" || refresh == "" {
		t.Fatal("the flow produced no tokens to check")
	}

	for _, verb := range verbs {
		rendered := fmt.Sprintf(verb, set)
		for _, secret := range []string{access, refresh} {
			if strings.Contains(rendered, secret) {
				t.Errorf("fmt.Sprintf(%q, TokenSet) leaked a real token: %s", verb, rendered)
			}
		}
	}
	status := fmt.Sprint(provider.Status())
	for _, secret := range []string{access, refresh} {
		if strings.Contains(status, secret) {
			t.Errorf("Status() leaked a real token: %s", status)
		}
	}
	if _, err := json.Marshal(set); !errors.Is(err, auth.ErrMarshalRefused) {
		t.Errorf("json.Marshal(TokenSet) error = %v, want ErrMarshalRefused", err)
	}
}

func mustCanonical(t *testing.T, raw string) string {
	t.Helper()
	origin, err := auth.CanonicalOrigin(raw)
	if err != nil {
		t.Fatalf("CanonicalOrigin(%q) error = %v", raw, err)
	}
	return origin
}
