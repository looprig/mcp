// This file tests the parts of the OAuth flow that have no exported surface:
// the PKCE verifier, the CSRF state, the authorization code, the discovery
// document parsing, and the wire-error classification. They are unexported
// because they are flow mechanics rather than contracts, and they are tested
// here rather than through the flow because a bug in the S256 transformation
// should fail as "S256 is wrong", not as "the integration test hangs".

package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/secrettest"
)

// internalCanary is the secret planted in the unexported types. It mirrors the
// canary in redaction_test.go, which is in the external test package and
// therefore cannot be shared.
const internalCanary = "CANARY-9f2b6d41-INTERNAL-SECRET"

// The RFC 7636 §B.1 test vector. This is the one assertion in the package that
// is not a matter of our judgment: the RFC publishes a verifier and the
// challenge it must produce, and a client that disagrees with it will be
// rejected by every conforming authorization server.
//
// It is worth understanding what this catches, because "SHA-256 then base64"
// sounds too simple to get wrong. The two real mistakes are hashing the
// base64-decoded verifier rather than its ASCII characters, and using standard
// base64 or padded base64url instead of unpadded base64url — both produce a
// plausible-looking challenge that is simply not the right one.
func TestS256ChallengeMatchesRFC7636Vector(t *testing.T) {
	t.Parallel()

	const (
		vectorVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		vectorChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := s256Challenge(vectorVerifier); got != vectorChallenge {
		t.Errorf("s256Challenge(RFC 7636 B.1 verifier) = %q, want %q", got, vectorChallenge)
	}
}

// A generated verifier must satisfy RFC 7636 §4.1: 43-128 characters from the
// unreserved set. The charset holds by construction (base64url's alphabet is a
// subset of unreserved), so this test is really pinning that construction
// against a future "improvement" that adds padding or switches encoding.
func TestNewPKCEProducesAConformingVerifier(t *testing.T) {
	t.Parallel()

	// RFC 3986 §2.3 unreserved. Notably this is what base64url yields, minus
	// the '=' padding that RawURLEncoding does not emit.
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

	seen := make(map[string]bool)
	for range 100 {
		p, err := newPKCE()
		if err != nil {
			t.Fatalf("newPKCE() error = %v", err)
		}
		verifier := p.Verifier()

		if len(verifier) < minVerifierLen || len(verifier) > maxVerifierLen {
			t.Fatalf("verifier length = %d, want between %d and %d", len(verifier), minVerifierLen, maxVerifierLen)
		}
		for i := range len(verifier) {
			if !strings.ContainsRune(unreserved, rune(verifier[i])) {
				t.Fatalf("verifier byte at %d is %q, which is outside the RFC 7636 unreserved charset", i, verifier[i])
			}
		}
		// The challenge must actually be the verifier's challenge, not some
		// other value: a flow that sends a mismatched pair fails at the token
		// endpoint with an opaque error.
		if got, want := p.Challenge(), s256Challenge(verifier); got != want {
			t.Fatalf("Challenge() = %q, want %q", got, want)
		}
		// Every verifier must be new. A repeat inside 100 draws of a 256-bit
		// space is not luck, it is a broken entropy source — this is the shape
		// of the bug where a package-level rand is seeded once.
		if seen[verifier] {
			t.Fatalf("newPKCE() produced a duplicate verifier %q; the entropy source is broken", verifier)
		}
		seen[verifier] = true
	}
}

// The same for state: unique every time, and long enough to be unguessable.
func TestNewStateIsUniqueAndLong(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for range 100 {
		st, err := newState()
		if err != nil {
			t.Fatalf("newState() error = %v", err)
		}
		value := st.Value()

		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			t.Fatalf("state %q is not unpadded base64url: %v", value, err)
		}
		if len(raw) != stateBytes {
			t.Fatalf("state carries %d bytes of entropy, want %d", len(raw), stateBytes)
		}
		if seen[value] {
			t.Fatalf("newState() produced a duplicate state; the entropy source is broken")
		}
		seen[value] = true
	}
}

// The entropy has to come from crypto/rand, and no test of the output can prove
// that: math/rand seeded from the clock produces values that are unique and
// well-distributed and pass every statistical check a unit test could run, while
// being completely predictable to anyone who knows roughly when the process
// started. Predictable state is CSRF; a predictable verifier is no PKCE at all.
//
// So the source is checked at the source. This asserts the module rule
// ("crypto/rand for anything security-sensitive, never math/rand") against the
// files that generate secrets, which is the only place the question can be
// settled.
func TestSecretGeneratingFilesDoNotImportMathRand(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"pkce.go", "oauth.go", "register.go", "redirect.go", "discovery.go"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			source, err := os.ReadFile(filepath.Clean(name))
			if err != nil {
				t.Fatalf("could not read %s: %v", name, err)
			}
			if strings.Contains(string(source), `"math/rand"`) || strings.Contains(string(source), `"math/rand/v2"`) {
				t.Errorf("%s imports math/rand; security-sensitive randomness must come from crypto/rand", name)
			}
		})
	}
	// And the positive half: the file that generates them says so.
	source, err := os.ReadFile(filepath.Clean("pkce.go"))
	if err != nil {
		t.Fatalf("could not read pkce.go: %v", err)
	}
	if !strings.Contains(string(source), `"crypto/rand"`) {
		t.Error("pkce.go does not import crypto/rand; the verifier and state must come from it")
	}
}

// The state comparison is the CSRF check. It must reject everything but the
// exact value, and a zero state must reject everything — fail closed.
func TestStateMatches(t *testing.T) {
	t.Parallel()

	st, err := newState()
	if err != nil {
		t.Fatalf("newState() error = %v", err)
	}
	value := st.Value()

	tests := []struct {
		name string
		got  string
		want bool
	}{
		{name: "exact match", got: value, want: true},
		{name: "empty", got: "", want: false},
		{name: "different", got: "not-the-state", want: false},
		{name: "prefix of the real state", got: value[:len(value)-1], want: false},
		{name: "real state with a suffix", got: value + "x", want: false},
		{name: "case flipped", got: strings.ToUpper(value), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := st.Matches(tt.got); got != tt.want {
				t.Errorf("Matches(%q) = %v, want %v", tt.got, got, tt.want)
			}
		})
	}

	// A zero state matches nothing, including the empty string it holds.
	var zero state
	for _, got := range []string{"", "anything", value} {
		if zero.Matches(got) {
			t.Errorf("zero state matched %q; it must fail closed", got)
		}
	}
}

// The downgrade refusal. A server that offers only "plain" gets no flow: this
// is the test that stops someone adding a "fall back to plain for
// compatibility" branch, which is the shape the vulnerability takes in the wild.
func TestSelectChallengeMethodRefusesDowngrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		supported []string
		want      string
		wantErr   bool
	}{
		{name: "S256 only", supported: []string{"S256"}, want: "S256"},
		{name: "S256 among others", supported: []string{"plain", "S256"}, want: "S256"},
		{
			name: "unadvertised is assumed capable",
			// RFC 8414 makes the field RECOMMENDED, not REQUIRED; an absent
			// field says nothing, and sending S256 to a server that ignores
			// PKCE costs nothing.
			supported: nil,
			want:      "S256",
		},
		{name: "plain only is refused", supported: []string{"plain"}, wantErr: true},
		{name: "unknown method only is refused", supported: []string{"S512"}, wantErr: true},
		{name: "empty string method is refused", supported: []string{""}, wantErr: true},
		{name: "case must match: s256 is not S256", supported: []string{"s256"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := selectChallengeMethod(tt.supported)
			if (err != nil) != tt.wantErr {
				t.Fatalf("selectChallengeMethod(%v) error = %v, wantErr %v", tt.supported, err, tt.wantErr)
			}
			if tt.wantErr {
				if class, ok := ClassOf(err); !ok || class != ClassFailed {
					t.Errorf("selectChallengeMethod() error class = %v (found %v), want %v", class, ok, ClassFailed)
				}
				return
			}
			if got != tt.want {
				t.Errorf("selectChallengeMethod(%v) = %q, want %q", tt.supported, got, tt.want)
			}
		})
	}
}

// Issuer validation (RFC 8414 §3.3) is the check that stops a mix-up attack, so
// it must be exact: every near-miss below is a distinct issuer.
func TestAuthServerMetadataValidate(t *testing.T) {
	t.Parallel()

	const issuer = "https://as.example.com"
	valid := func() authServerMetadata {
		return authServerMetadata{
			Issuer:                issuer,
			AuthorizationEndpoint: "https://as.example.com/authorize",
			TokenEndpoint:         "https://as.example.com/token",
		}
	}

	tests := []struct {
		name    string
		mutate  func(*authServerMetadata)
		wantErr bool
	}{
		{name: "valid", mutate: func(*authServerMetadata) {}},
		{
			name:    "issuer mismatch",
			mutate:  func(m *authServerMetadata) { m.Issuer = "https://attacker.example.com" },
			wantErr: true,
		},
		{
			name: "issuer differing only by a trailing slash",
			// Not a nitpick: accepting "close enough" is exactly the latitude a
			// mix-up attack needs.
			mutate:  func(m *authServerMetadata) { m.Issuer = issuer + "/" },
			wantErr: true,
		},
		{
			name:    "issuer differing only by case",
			mutate:  func(m *authServerMetadata) { m.Issuer = "https://AS.example.com" },
			wantErr: true,
		},
		{name: "issuer empty", mutate: func(m *authServerMetadata) { m.Issuer = "" }, wantErr: true},
		{
			name:    "authorization endpoint missing",
			mutate:  func(m *authServerMetadata) { m.AuthorizationEndpoint = "" },
			wantErr: true,
		},
		{name: "token endpoint missing", mutate: func(m *authServerMetadata) { m.TokenEndpoint = "" }, wantErr: true},
		{
			name: "javascript authorization endpoint",
			// This one goes to a BrowserOpener. A javascript: URL there is
			// script execution in the user's browser.
			mutate:  func(m *authServerMetadata) { m.AuthorizationEndpoint = "javascript:alert(1)" },
			wantErr: true,
		},
		{
			name:    "data authorization endpoint",
			mutate:  func(m *authServerMetadata) { m.AuthorizationEndpoint = "data:text/html,<script>x</script>" },
			wantErr: true,
		},
		{
			name: "cleartext token endpoint",
			// This one receives the code and the verifier.
			mutate:  func(m *authServerMetadata) { m.TokenEndpoint = "http://as.example.com/token" },
			wantErr: true,
		},
		{
			name:    "cleartext loopback token endpoint is allowed",
			mutate:  func(m *authServerMetadata) { m.TokenEndpoint = "http://127.0.0.1:9000/token" },
			wantErr: false,
		},
		{
			name:    "cleartext registration endpoint",
			mutate:  func(m *authServerMetadata) { m.RegistrationEndpoint = "http://as.example.com/register" },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			meta := valid()
			tt.mutate(&meta)
			err := meta.validate(issuer)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				if class, ok := ClassOf(err); !ok || class != ClassFailed {
					t.Errorf("validate() error class = %v (found %v), want %v", class, ok, ClassFailed)
				}
			}
		})
	}
}

// The well-known path rules are the fiddly part of RFC 8414 §3.1 and RFC 9728
// §3.1, and the mistake — appending instead of inserting — produces URLs that
// work fine against single-tenant servers and fail against every multi-tenant
// one. Pinning the exact strings is the only way to keep it right.
func TestWellKnownCandidates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		base      string
		wellKnown string
		want      []string
	}{
		{
			name:      "no path",
			base:      "https://h.example.com",
			wellKnown: wellKnownAuthServer,
			want:      []string{"https://h.example.com/.well-known/oauth-authorization-server"},
		},
		{
			name:      "root path",
			base:      "https://h.example.com/",
			wellKnown: wellKnownAuthServer,
			want:      []string{"https://h.example.com/.well-known/oauth-authorization-server"},
		},
		{
			name:      "one path segment inserts, then falls back to root",
			base:      "https://h.example.com/tenant",
			wellKnown: wellKnownAuthServer,
			want: []string{
				"https://h.example.com/.well-known/oauth-authorization-server/tenant",
				"https://h.example.com/.well-known/oauth-authorization-server",
			},
		},
		{
			name:      "several path segments",
			base:      "https://h.example.com/a/b",
			wellKnown: wellKnownProtectedResource,
			want: []string{
				"https://h.example.com/.well-known/oauth-protected-resource/a/b",
				"https://h.example.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:      "query and port are handled",
			base:      "https://h.example.com:8443/mcp?x=1",
			wellKnown: wellKnownProtectedResource,
			want: []string{
				"https://h.example.com:8443/.well-known/oauth-protected-resource/mcp",
				"https://h.example.com:8443/.well-known/oauth-protected-resource",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := wellKnownCandidates(tt.base, tt.wellKnown)
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("wellKnownCandidates(%q) = %v, want %v", tt.base, got, tt.want)
			}
		})
	}
}

// OpenID Connect discovery suffixes where RFC 8414 inserts. Both forms exist in
// the wild, and the suffixed one must come first: it is what OIDC specifies, so
// it is what an OIDC server serves.
func TestOpenIDCandidates(t *testing.T) {
	t.Parallel()

	got := openIDCandidates("https://h.example.com/tenant")
	want := []string{
		"https://h.example.com/tenant/.well-known/openid-configuration",
		"https://h.example.com/.well-known/openid-configuration/tenant",
		"https://h.example.com/.well-known/openid-configuration",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("openIDCandidates() = %v, want %v", got, want)
	}
}

// A discovery document is the least trustworthy input in the module. These are
// the shapes a hostile or broken server actually sends.
func TestDecodeBoundedJSONRejectsHostileDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "valid", body: `{"issuer":"https://h"}`},
		{name: "malformed", body: `{"issuer":`, wantErr: "not valid JSON"},
		{name: "not an object", body: `"a string"`, wantErr: "not valid JSON"},
		{name: "empty", body: ``, wantErr: "not valid JSON"},
		{
			name: "oversized",
			// The 1GB-discovery-document case, scaled to something a test can
			// build: what matters is that the bound is enforced by the reader,
			// so the process never holds the whole body.
			body:    `{"issuer":"` + strings.Repeat("A", maxDocumentBytes+1) + `"}`,
			wantErr: "exceeds the",
		},
		{
			name:    "deeply nested",
			body:    strings.Repeat(`{"a":`, 500) + `1` + strings.Repeat(`}`, 500),
			wantErr: "nesting exceeds",
		},
		{
			name:    "deeply nested arrays",
			body:    strings.Repeat(`[`, 5000) + strings.Repeat(`]`, 5000),
			wantErr: "nesting exceeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var meta authServerMetadata
			err := decodeBoundedJSON(strings.NewReader(tt.body), &meta)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("decodeBoundedJSON() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("decodeBoundedJSON() = nil, want an error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("decodeBoundedJSON() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// A parse failure must not quote the input back: the input is attacker
// controlled and the error goes to a log.
func TestDecodeBoundedJSONDoesNotEchoInput(t *testing.T) {
	t.Parallel()

	var meta authServerMetadata
	err := decodeBoundedJSON(strings.NewReader(`{"issuer": `+internalCanary), &meta)
	if err == nil {
		t.Fatal("decodeBoundedJSON() = nil, want an error")
	}
	if strings.Contains(err.Error(), internalCanary) {
		t.Errorf("decodeBoundedJSON() error echoed the document back: %v", err)
	}
}

// A 1GB document must not be buffered. The bound is on the reader, so the proof
// is that decoding an endless stream returns rather than growing until the
// process dies.
func TestDecodeBoundedJSONStopsAnEndlessDocument(t *testing.T) {
	t.Parallel()

	var meta authServerMetadata
	err := decodeBoundedJSON(endlessReader{}, &meta)
	if err == nil {
		t.Fatal("decodeBoundedJSON(endless) = nil, want an over-limit error")
	}
	if !strings.Contains(err.Error(), "exceeds the") {
		t.Errorf("decodeBoundedJSON(endless) error = %q, want an over-limit error", err)
	}
}

// endlessReader is a document that never ends: the hostile server, reduced to
// its essence.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

func TestCheckJSONContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{name: "json", header: "application/json"},
		{name: "json with charset", header: "application/json; charset=utf-8"},
		{name: "uppercase", header: "APPLICATION/JSON"},
		{name: "empty", header: "", wantErr: true},
		{name: "html: a login page or captive portal", header: "text/html", wantErr: true},
		{name: "unparseable", header: "application/", wantErr: true},
		{name: "text", header: "text/plain", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := checkJSONContentType(tt.header); (err != nil) != tt.wantErr {
				t.Errorf("checkJSONContentType(%q) error = %v, wantErr %v", tt.header, err, tt.wantErr)
			}
		})
	}
}

// Error classification is what callers branch on, and the distinction that
// matters most is denied (do not open a browser) versus expired (do).
func TestTokenErrorClass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		code   string
		status int
		want   Class
	}{
		{name: "invalid_grant is recoverable by re-authorizing", code: "invalid_grant", status: 400, want: ClassExpired},
		{name: "access_denied", code: "access_denied", status: 400, want: ClassDenied},
		{name: "invalid_client", code: "invalid_client", status: 401, want: ClassDenied},
		{name: "unauthorized_client", code: "unauthorized_client", status: 400, want: ClassDenied},
		{name: "invalid_request", code: "invalid_request", status: 400, want: ClassFailed},
		{name: "invalid_scope", code: "invalid_scope", status: 400, want: ClassFailed},
		{name: "server_error", code: "server_error", status: 500, want: ClassFailed},
		{name: "temporarily_unavailable", code: "temporarily_unavailable", status: 503, want: ClassFailed},
		{
			name: "an unknown code falls back to the status",
			// Never interpreted as consent: an error we do not understand is
			// not one we may treat as a refusal or as a retry signal.
			code: "wat", status: 401, want: ClassDenied,
		},
		{name: "an unknown code with an unknown status is failed", code: "wat", status: 400, want: ClassFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tokenErrorClass(tt.code, tt.status); got != tt.want {
				t.Errorf("tokenErrorClass(%q, %d) = %v, want %v", tt.code, tt.status, got, tt.want)
			}
		})
	}
}

// Refresh-token rotation, which is the rule most easily got wrong in both
// directions: dropping a still-valid refresh token logs the user out, and
// keeping a rotated one uses a token the server has already invalidated.
func TestNewTokenSetFromResolvesRotation(t *testing.T) {
	t.Parallel()

	previous := NewTokenSet("old-access", "old-refresh", time.Time{}, []string{"read"})

	tests := []struct {
		name        string
		body        tokenResponse
		previous    TokenSet
		wantRefresh string
		wantScopes  []string
	}{
		{
			name:        "a new refresh token replaces the old one",
			body:        tokenResponse{AccessToken: "a", RefreshToken: "new-refresh"},
			previous:    previous,
			wantRefresh: "new-refresh",
			wantScopes:  []string{"read"},
		},
		{
			name:        "no refresh token leaves the old one in force",
			body:        tokenResponse{AccessToken: "a"},
			previous:    previous,
			wantRefresh: "old-refresh",
			wantScopes:  []string{"read"},
		},
		{
			name:        "a first exchange has no previous token",
			body:        tokenResponse{AccessToken: "a", RefreshToken: "r"},
			previous:    TokenSet{},
			wantRefresh: "r",
			wantScopes:  []string{"read"},
		},
		{
			name:        "the granted scope wins over the requested one",
			body:        tokenResponse{AccessToken: "a", Scope: "read write"},
			previous:    previous,
			wantRefresh: "old-refresh",
			wantScopes:  []string{"read", "write"},
		},
		{
			name:        "a narrowed grant is reported as granted, not as requested",
			body:        tokenResponse{AccessToken: "a", Scope: "read"},
			previous:    previous,
			wantRefresh: "old-refresh",
			wantScopes:  []string{"read"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := newTokenSetFrom(tt.body, []string{"read"}, tt.previous, time.Now())
			if err != nil {
				t.Fatalf("newTokenSetFrom() error = %v", err)
			}
			if got.Refresh() != tt.wantRefresh {
				t.Errorf("Refresh() = %q, want %q", got.Refresh(), tt.wantRefresh)
			}
			if fmt.Sprint(got.Scopes()) != fmt.Sprint(tt.wantScopes) {
				t.Errorf("Scopes() = %v, want %v", got.Scopes(), tt.wantScopes)
			}
		})
	}
}

// seconds returns a pointer to n, for building an expires_in.
func seconds(n int64) *int64 { return &n }

// expires_in is four cases, not two, and the pairs that look alike mean
// opposite things:
//
//   - absent vs zero: "no stated expiry" (never expires) vs "already dead".
//     A plain int64 cannot tell these apart, which is why the field is a
//     pointer. Conflating them yields a token that is never proactively
//     refreshed and degrades into 401s from the resource instead.
//   - huge vs normal: time.Duration is nanoseconds in an int64, so the naive
//     multiply WRAPS past ~292 years. The wrapped values happen to land in the
//     past — safe, but by arithmetic accident. The clamp makes it a decision.
func TestExpiryFrom(t *testing.T) {
	t.Parallel()

	// A fixed instant: expiry arithmetic against time.Now() is a test that
	// asserts on a moving target.
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		expiresIn  *int64
		wantErr    bool
		wantZero   bool
		wantExpiry time.Time
		// wantExpiredNow is the property that actually matters to the ladder in
		// Token: does this token get used, or refreshed?
		wantExpiredNow bool
	}{
		{
			name:      "absent means the server stated no expiry",
			expiresIn: nil,
			wantZero:  true,
			// A token with no stated expiry never expires; treating it as dead
			// would throw away a perfectly good credential.
			wantExpiredNow: false,
		},
		{
			name:           "normal",
			expiresIn:      seconds(3600),
			wantExpiry:     now.Add(time.Hour),
			wantExpiredNow: false,
		},
		{
			name:           "one second is inside the skew, so already unusable",
			expiresIn:      seconds(1),
			wantExpiry:     now.Add(time.Second),
			wantExpiredNow: true,
		},
		{
			name: "zero means already dead, and is NOT absent",
			// The case the old `> 0` guard silently turned into "never
			// expires".
			expiresIn:      seconds(0),
			wantExpiry:     now,
			wantExpiredNow: true,
		},
		{
			name:      "negative is a malformed response",
			expiresIn: seconds(-1),
			wantErr:   true,
		},
		{
			name:      "large negative is a malformed response",
			expiresIn: seconds(-3600),
			wantErr:   true,
		},
		{
			name:           "a year is at the ceiling and is not clamped",
			expiresIn:      seconds(maxExpiresIn),
			wantExpiry:     now.Add(maxExpiresIn * time.Second),
			wantExpiredNow: false,
		},
		{
			name: "beyond the ceiling is clamped, not wrapped",
			// Without the clamp this wrapped to 1795.
			expiresIn:      seconds(1099511627776),
			wantExpiry:     now.Add(maxExpiresIn * time.Second),
			wantExpiredNow: false,
		},
		{
			name: "MaxInt64 is clamped, not wrapped",
			// Without the clamp this wrapped to approximately now.
			expiresIn:      seconds(math.MaxInt64),
			wantExpiry:     now.Add(maxExpiresIn * time.Second),
			wantExpiredNow: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := expiryFrom(tt.expiresIn, now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expiryFrom() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if class, ok := ClassOf(err); !ok || class != ClassFailed {
					t.Errorf("expiryFrom() error class = %v (found %v), want %v", class, ok, ClassFailed)
				}
				return
			}
			if tt.wantZero {
				if !got.IsZero() {
					t.Fatalf("expiryFrom() = %v, want the zero time", got)
				}
			} else if !got.Equal(tt.wantExpiry) {
				t.Fatalf("expiryFrom() = %v, want %v", got, tt.wantExpiry)
			}

			// The behavior the value exists for: a TokenSet built from it is
			// either usable or refreshed. This is what the Minor was actually
			// about — the arithmetic is only the mechanism.
			set := NewTokenSet("access", "refresh", got, nil)
			if set.Expired(now) != tt.wantExpiredNow {
				t.Errorf("NewTokenSet(expiry=%v).Expired(now) = %v, want %v", got, set.Expired(now), tt.wantExpiredNow)
			}
		})
	}
}

// The same four cases through the conversion a token response actually takes.
func TestNewTokenSetFromExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	withExpiry, err := newTokenSetFrom(tokenResponse{AccessToken: "a", ExpiresIn: seconds(3600)}, nil, TokenSet{}, now)
	if err != nil {
		t.Fatalf("newTokenSetFrom() error = %v", err)
	}
	if !withExpiry.Expiry().Equal(now.Add(time.Hour)) {
		t.Errorf("Expiry() = %v, want an hour after now", withExpiry.Expiry())
	}
	if withExpiry.Expired(now) {
		t.Error("Expired() = true for a token that expires in an hour")
	}

	without, err := newTokenSetFrom(tokenResponse{AccessToken: "a"}, nil, TokenSet{}, now)
	if err != nil {
		t.Fatalf("newTokenSetFrom() error = %v", err)
	}
	if !without.Expiry().IsZero() {
		t.Errorf("Expiry() = %v, want zero when the server stated no expiry", without.Expiry())
	}
	if without.Expired(now) {
		t.Error("Expired() = true for a token with no stated expiry; it must be treated as never expiring")
	}

	dead, err := newTokenSetFrom(tokenResponse{AccessToken: "a", ExpiresIn: seconds(0)}, nil, TokenSet{}, now)
	if err != nil {
		t.Fatalf("newTokenSetFrom() error = %v", err)
	}
	if !dead.Expired(now) {
		t.Error("Expired() = false for expires_in=0; the server said the token is already dead")
	}

	if _, err := newTokenSetFrom(tokenResponse{AccessToken: "a", ExpiresIn: seconds(-1)}, nil, TokenSet{}, now); err == nil {
		t.Error("newTokenSetFrom() = nil error for a negative expires_in, want a malformed-response failure")
	}
}

// expires_in is decoded from real JSON, because the absent-vs-zero distinction
// is a property of the decoding and a unit test that builds the struct by hand
// cannot see it. This is the test that fails if the field goes back to int64.
func TestTokenResponseDistinguishesAbsentFromZeroExpiresIn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		wantNil  bool
		wantSecs int64
	}{
		{name: "absent", body: `{"access_token":"a"}`, wantNil: true},
		{name: "zero", body: `{"access_token":"a","expires_in":0}`, wantSecs: 0},
		{name: "normal", body: `{"access_token":"a","expires_in":3600}`, wantSecs: 3600},
		{name: "negative", body: `{"access_token":"a","expires_in":-1}`, wantSecs: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var body tokenResponse
			if err := decodeBoundedJSON(strings.NewReader(tt.body), &body); err != nil {
				t.Fatalf("decodeBoundedJSON() error = %v", err)
			}
			if tt.wantNil {
				if body.ExpiresIn != nil {
					t.Fatalf("ExpiresIn = %d, want nil: an absent expires_in must be distinguishable from zero", *body.ExpiresIn)
				}
				return
			}
			if body.ExpiresIn == nil {
				t.Fatalf("ExpiresIn = nil, want %d", tt.wantSecs)
			}
			if *body.ExpiresIn != tt.wantSecs {
				t.Errorf("ExpiresIn = %d, want %d", *body.ExpiresIn, tt.wantSecs)
			}
		})
	}
}

// The unexported secret-bearing types get the same guarantee as the exported
// ones, measured with the same adversary. This is the internal half of
// TestSecretsSurviveUnsafeReflection.
func TestUnexportedSecretsSurviveUnsafeReflection(t *testing.T) {
	t.Parallel()

	subjects := map[string]any{
		"pkce":     pkce{verifier: newSecret(internalCanary), challenge: "not-secret"},
		"state":    state{value: newSecret(internalCanary)},
		"authCode": newAuthCode(internalCanary),
	}
	for name, subject := range subjects {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := secrettest.Dump(subject)
			if strings.Contains(got, internalCanary) {
				t.Errorf("an unsafe reflection walker recovered the secret from %s: %s", name, got)
			}
			if !secrettest.ReachedSecret(got) {
				t.Errorf("walker never reached a secret in %s; the test proves nothing: %s", name, got)
			}
		})
	}
}

// And the fmt half: every verb, over the unexported types, redacted.
func TestUnexportedSecretsRedactUnderEveryVerb(t *testing.T) {
	t.Parallel()

	// Every ASCII letter as a verb, with the flags that change fmt's dispatch.
	// See redaction_test.go for why sweeping only the Stringer verbs proves
	// nothing.
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var allVerbs []string
	for _, flag := range []string{"", "+", "#", " ", "-", "0"} {
		for _, letter := range letters {
			allVerbs = append(allVerbs, "%"+flag+string(letter))
		}
	}
	allVerbs = append(allVerbs, "%!", "%9.3v")

	p := pkce{verifier: newSecret(internalCanary), challenge: "not-secret"}
	st := state{value: newSecret(internalCanary)}
	code := newAuthCode(internalCanary)

	// The wrapping struct is the case methods cannot defend — fmt reaches a
	// value in an unexported field by reflection and cannot call a method on
	// it — so it is the one that proves the layout, not the methods.
	type flow struct {
		p    pkce
		st   state
		code authCode
	}

	subjects := map[string]any{
		"pkce":            p,
		"state":           st,
		"authCode":        code,
		"private wrapper": flow{p: p, st: st, code: code},
	}
	for name, subject := range subjects {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, verb := range allVerbs {
				if got := fmt.Sprintf(verb, subject); strings.Contains(got, internalCanary) {
					t.Errorf("fmt.Sprintf(%q, %s) leaked: %s", verb, name, got)
				}
			}
		})
	}
}

// The accessors are the deliberate escape hatch; without them the flow cannot
// send the verifier, and the design is wrong in the other direction.
func TestUnexportedAccessorsExposeSecretsDeliberately(t *testing.T) {
	t.Parallel()

	if got := (pkce{verifier: newSecret(internalCanary)}).Verifier(); got != internalCanary {
		t.Errorf("Verifier() = %q, want the verifier back verbatim", got)
	}
	if got := (state{value: newSecret(internalCanary)}).Value(); got != internalCanary {
		t.Errorf("state.Value() = %q, want the state back verbatim", got)
	}
	if got := newAuthCode(internalCanary).Value(); got != internalCanary {
		t.Errorf("authCode.Value() = %q, want the code back verbatim", got)
	}
	if newAuthCode("").Valid() {
		t.Error("an empty authCode reports Valid() = true; absence must be distinguishable")
	}
}

// A metadata endpoint answering with a redirect to a cleartext or hostile
// scheme must not be followed. The default client's CheckRedirect is what
// enforces it, and it is easy to lose in a refactor.
func TestDefaultHTTPClientRefusesADowngradingRedirect(t *testing.T) {
	t.Parallel()

	// A server that redirects to cleartext, which is what a downgrade attack
	// looks like from the client's side.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.example.com/token", http.StatusFound)
	}))
	defer server.Close()

	client := defaultHTTPClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("Do() followed a redirect to a non-loopback http URL; want it refused")
	}
}
