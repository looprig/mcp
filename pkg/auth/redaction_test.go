// This file is the package's load-bearing test. Every other test here checks a
// contract; this one checks the promise the design makes to the operator:
// "Token values, client secrets, authorization codes, verifiers, and bearer
// headers never enter events, catalogs, fingerprints, or logs."
//
// The mechanism under test is layered:
//
//   - secret fields are unexported, so no reflection-driven encoder or logger
//     can reach them and no caller can name one by accident;
//   - String/GoString render redacted text, so every fmt verb that can reach a
//     value goes through them rather than through reflection;
//   - MarshalJSON refuses, so a struct that ends up in a JSON log line fails
//     loudly instead of leaking or silently emitting a useless token.
//
// The matrix below sweeps the formatting verbs that reach a value's own
// methods (%v %s %q %+v %#v) plus json.Marshal, over every secret-bearing type
// and over the containers those types realistically end up inside — a slice, a
// map, a wrapping struct, and the MemoryStore itself. A canary string is
// planted as the secret; the assertion is simply that it never appears in the
// output.

package auth_test

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/secrettest"
	"github.com/looprig/mcp/pkg/auth"
)

// canary is the secret planted in every value under test. It is deliberately
// unlike any legitimate output of this package, so a substring hit is proof of
// a leak rather than a coincidence.
const canary = "CANARY-c7f3a1e9-SECRET-TOKEN-VALUE"

// verbs is every fmt verb, not a chosen few.
//
// The list is generated rather than hand-picked, and that is a deliberate
// correction: an earlier version of this test swept only {%v %s %q %+v %#v} —
// exactly the verbs fmt routes through Stringer, and therefore exactly the
// verbs that could not fail. It passed while `fmt.Sprintf("%d", set)` printed
// the token in full, because %d falls through to reflection and reflection
// reads unexported fields. A redaction test that only tries the safe verbs is
// not evidence of anything.
//
// So: every ASCII letter as a verb, each with the flags that change fmt's
// dispatch (%#v reaches GoStringer, %+v the plus flag), plus the invalid-verb
// case. Anything fmt can be asked to do, it is asked to do here.
var verbs = buildVerbs()

func buildVerbs() []string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	flags := []string{"", "+", "#", " ", "-", "0"}
	out := make([]string, 0, len(letters)*len(flags)+2)
	for _, flag := range flags {
		for _, letter := range letters {
			out = append(out, "%"+flag+string(letter))
		}
	}
	// A verb fmt does not know: it must not fall back to dumping the value.
	return append(out, "%!", "%9.3v")
}

// secretValues returns, by name, every value that holds the canary — both the
// secret-bearing types themselves and the containers they travel in.
func secretValues(t *testing.T) map[string]any {
	t.Helper()

	set := auth.NewTokenSet(canary, canary, time.Unix(1<<30, 0), []string{"read"})
	header := auth.NewHeader("Authorization", "Bearer "+canary)
	creds := auth.NewClientCredentials("client-id", canary)

	store := auth.NewMemoryStore()
	key := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"}
	if err := store.Store(context.Background(), key, set); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	type wrapper struct {
		Note   string
		Tokens auth.TokenSet
		Header auth.Header
		Creds  auth.ClientCredentials
	}

	return map[string]any{
		"TokenSet":                  set,
		"TokenSet pointer":          &set,
		"Header":                    header,
		"Header pointer":            &header,
		"ClientCredentials":         creds,
		"ClientCredentials pointer": &creds,
		"[]TokenSet":                []auth.TokenSet{set},
		"[]Header":                  []auth.Header{header},
		"[]ClientCredentials":       []auth.ClientCredentials{creds},
		"map[Key]TokenSet":          map[auth.Key]auth.TokenSet{key: set},
		"wrapping struct":           wrapper{Note: "n", Tokens: set, Header: header, Creds: creds},
		"MemoryStore":               store,
	}
}

// The formatting half of the matrix: no verb, over no container, may render
// the canary.
func TestNoSecretsInFormatting(t *testing.T) {
	t.Parallel()

	for name, value := range secretValues(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, verb := range verbs {
				got := fmt.Sprintf(verb, value)
				if strings.Contains(got, canary) {
					t.Errorf("fmt.Sprintf(%q, %s) leaked the secret: %s", verb, name, got)
				}
				// %x/%X would deliver a leak hex-encoded, which a plain
				// substring check would sail straight past.
				if dec, err := hex.DecodeString(strings.ToLower(got)); err == nil && bytes.Contains(dec, []byte(canary)) {
					t.Errorf("fmt.Sprintf(%q, %s) leaked the secret hex-encoded: %s", verb, name, dec)
				}
				if got == "" {
					t.Errorf("fmt.Sprintf(%q, %s) rendered empty; redaction must still say something", verb, name)
				}
			}
		})
	}
}

// The JSON half: marshalling must never emit the canary, through the output or
// through the error. Secret-bearing types refuse outright, and containers
// inherit the refusal because encoding/json propagates the error from the
// element's MarshalJSON.
//
// The assertion is "does not leak" rather than "returns ErrMarshalRefused",
// because a container can fail earlier for its own reasons — map[Key]TokenSet
// is rejected for its key type before the encoder ever reaches a value. That is
// still a non-leaking outcome, which is the property under test.
// TestMarshalJSONRefuses pins the exact error for the types that own it.
func TestNoSecretsInJSON(t *testing.T) {
	t.Parallel()

	for name, value := range secretValues(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(value)
			if err != nil {
				if strings.Contains(err.Error(), canary) {
					t.Errorf("json.Marshal(%s) leaked the secret through its error: %v", name, err)
				}
				return
			}
			if strings.Contains(string(got), canary) {
				t.Errorf("json.Marshal(%s) leaked the secret: %s", name, got)
			}
		})
	}
}

// The refusal must be reachable through errors.Is even after encoding/json has
// wrapped it in a *json.MarshalerError, and must name the type so the operator
// knows what to fix.
func TestMarshalJSONRefuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value json.Marshaler
	}{
		{name: "TokenSet", value: auth.NewTokenSet(canary, canary, time.Time{}, nil)},
		{name: "Header", value: auth.NewHeader("Authorization", canary)},
		{name: "ClientCredentials", value: auth.NewClientCredentials("id", canary)},
		{name: "zero TokenSet", value: auth.TokenSet{}},
		{name: "zero Header", value: auth.Header{}},
		{name: "zero ClientCredentials", value: auth.ClientCredentials{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.value.MarshalJSON()
			if err == nil {
				t.Fatalf("MarshalJSON() = %s, want an error", got)
			}
			if !errors.Is(err, auth.ErrMarshalRefused) {
				t.Errorf("MarshalJSON() error = %v, want ErrMarshalRefused", err)
			}
		})
	}
}

// The fmt and json matrices above test the mechanisms. This tests the thing the
// design actually promises: that a secret does not reach a log. slog is how Go
// programs log, so it is the realistic way a TokenSet ends up one call away from
// disk — and it reaches values through two different paths (a text handler
// formats via fmt, a JSON handler marshals), so it exercises both layers of the
// defense at once, through the API an application really uses.
//
// gob is here for the same reason in a different direction: it is the other
// reflection-based encoder in the standard library, and unlike json it has no
// Marshaler hook to refuse from. Unexported fields are what stop it.
func TestNoSecretsInLoggingPipelines(t *testing.T) {
	t.Parallel()

	set := auth.NewTokenSet(canary, canary, time.Unix(1<<30, 0), []string{"read"})
	header := auth.NewHeader("Authorization", "Bearer "+canary)

	t.Run("slog", func(t *testing.T) {
		t.Parallel()
		handlers := map[string]func(*bytes.Buffer) slog.Handler{
			"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
			"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		}
		for name, newHandler := range handlers {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				var buf bytes.Buffer
				slog.New(newHandler(&buf)).Info("tokens", "set", set, "header", header)
				if strings.Contains(buf.String(), canary) {
					t.Errorf("slog %s handler leaked the secret: %s", name, buf.String())
				}
			})
		}
	})

	t.Run("gob", func(t *testing.T) {
		t.Parallel()
		for name, value := range map[string]any{"TokenSet": set, "Header": header} {
			var buf bytes.Buffer
			// gob refuses a type with no exported fields. The error is the
			// desired outcome; what matters is that no secret reached buf.
			err := gob.NewEncoder(&buf).Encode(value)
			if err == nil {
				t.Errorf("gob encoded %s without error; it must have nothing exported to encode", name)
			}
			if bytes.Contains(buf.Bytes(), []byte(canary)) {
				t.Errorf("gob leaked the secret for %s: %s", name, buf.Bytes())
			}
		}
	})
}

// A secret-bearing value held in someone else's UNEXPORTED field is the case
// methods cannot defend: fmt reaches it by reflection but cannot call a method
// on it (CanInterface is false), so Formatter, Stringer and GoStringer are all
// skipped. It is also a realistic case — an application's own credential
// manager keeping `set auth.TokenSet` as a private field, then logging itself,
// is an obvious thing to write.
//
// It holds because the secrets sit behind a pointer, which fmt renders as an
// address rather than following. Note what this test does NOT prove: any
// pointer passes it, including a *string. The closure earns its keep against
// reflectors that are not fmt — see TestSecretsSurviveUnsafeReflection, which
// is the test that actually pins it.
func TestSecretsSurviveUnexportedFieldWrapper(t *testing.T) {
	t.Parallel()

	type wrapper struct {
		set    auth.TokenSet
		header auth.Header
	}
	w := wrapper{
		set:    auth.NewTokenSet(canary, canary, time.Time{}, []string{"read"}),
		header: auth.NewHeader("Authorization", canary),
	}

	for _, verb := range verbs {
		if got := fmt.Sprintf(verb, w); strings.Contains(got, canary) {
			t.Errorf("fmt.Sprintf(%q, wrapper-with-unexported-fields) leaked: %s", verb, got)
		}
	}

	// The same shape through the logger an application would really use.
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("creds", "w", w)
	if strings.Contains(buf.String(), canary) {
		t.Errorf("slog leaked a wrapper's unexported secret fields: %s", buf.String())
	}
}

// This is the test that justifies the secret closure, and the only one that
// does. Everything else in this file passes with the secrets held in a plain
// *string, because fmt never dereferences a pointer to a string.
//
// A reflector that uses unsafe does dereference it, and prints the credential.
// Swap secret's closure for a *string and this test fails; that is precisely
// its job, because the indirection reads as a pointless allocation to anyone
// who has not met this failure.
//
// The walker itself lives in internal/secrettest, because the unexported
// secret-bearing types added by the OAuth flow — the PKCE verifier, the CSRF
// state, the authorization code — can only be reached from an internal test,
// and one adversary tested from both sides beats two that can drift. See
// oauth_internal_test.go for that half.
func TestSecretsSurviveUnsafeReflection(t *testing.T) {
	t.Parallel()

	set := auth.NewTokenSet(canary, canary, time.Unix(1<<30, 0), []string{"read"})
	header := auth.NewHeader("Authorization", "Bearer "+canary)
	creds := auth.NewClientCredentials("client-id", canary)

	store := auth.NewMemoryStore()
	key := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"}
	if err := store.Store(context.Background(), key, set); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// A whole provider: the realistic worst case, since it transitively holds
	// the client secret and a store full of tokens, and is exactly the kind of
	// long-lived object an application keeps in a struct and dumps when
	// something goes wrong.
	provider, err := auth.NewOAuthProvider(auth.OAuthConfig{
		ServerURL:   "https://a.example.com/mcp",
		Credentials: creds,
		Store:       store,
		Browser:     refusingBrowser{},
	})
	if err != nil {
		t.Fatalf("NewOAuthProvider() error = %v", err)
	}

	// The shapes a dumper realistically meets: the values themselves, a
	// caller's private struct holding them, and a whole store.
	type private struct {
		set    auth.TokenSet
		header auth.Header
		creds  auth.ClientCredentials
	}
	subjects := map[string]any{
		"TokenSet":                set,
		"Header":                  header,
		"ClientCredentials":       creds,
		"private wrapper":         private{set: set, header: header, creds: creds},
		"MemoryStore":             store,
		"OAuthProvider":           provider,
		"slice of TokenSet":       []auth.TokenSet{set},
		"map of Key to TokenSet":  map[auth.Key]auth.TokenSet{key: set},
		"pointer to the TokenSet": &set,
	}
	for name, subject := range subjects {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := secrettest.Dump(subject)
			if strings.Contains(got, canary) {
				t.Errorf("an unsafe reflection walker recovered the secret from %s: %s", name, got)
			}
			if !secrettest.ReachedSecret(got) {
				t.Errorf("walker never reached a secret in %s; the test proves nothing: %s", name, got)
			}
		})
	}
}

// refusingBrowser is the BrowserOpener a headless service would supply: it
// refuses rather than blocking on a human who is not there. These tests never
// reach a browser, so refusing is also the assertion that they never do.
type refusingBrowser struct{}

func (refusingBrowser) OpenURL(context.Context, string) error {
	return errors.New("refusingBrowser: no browser here")
}

// GoString is unreachable through fmt — Format is consulted before GoStringer,
// so %#v never lands here — which is exactly why it needs a test of its own.
// It is kept as defense in depth: if Format were ever removed, GoString would
// silently become what serves %#v again, and it must already be correct when
// that happens. An untested fallback is not a fallback.
func TestGoStringRedactsForDirectCallers(t *testing.T) {
	t.Parallel()

	store := auth.NewMemoryStore()
	if err := store.Store(context.Background(),
		auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"},
		auth.NewTokenSet(canary, canary, time.Time{}, nil)); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	subjects := map[string]fmt.GoStringer{
		"TokenSet":    auth.NewTokenSet(canary, canary, time.Time{}, []string{"read"}),
		"Header":      auth.NewHeader("Authorization", "Bearer "+canary),
		"MemoryStore": store,
	}
	for name, subject := range subjects {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := subject.GoString()
			if strings.Contains(got, canary) {
				t.Errorf("%s.GoString() leaked the secret: %s", name, got)
			}
			if got == "" {
				t.Errorf("%s.GoString() rendered empty", name)
			}
		})
	}
}

// Refusing to marshal is only half a contract: a store that persists a TokenSet
// must not be able to silently decode an empty one back.
func TestUnmarshalJSONRefuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target json.Unmarshaler
	}{
		{name: "TokenSet", target: &auth.TokenSet{}},
		{name: "Header", target: &auth.Header{}},
		{name: "ClientCredentials", target: &auth.ClientCredentials{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.target.UnmarshalJSON([]byte(`{"access":"x"}`)); !errors.Is(err, auth.ErrMarshalRefused) {
				t.Errorf("UnmarshalJSON() error = %v, want ErrMarshalRefused", err)
			}
		})
	}

	// And through the encoding/json entry point a caller would really use.
	var set auth.TokenSet
	if err := json.Unmarshal([]byte(`{"access":"x"}`), &set); !errors.Is(err, auth.ErrMarshalRefused) {
		t.Errorf("json.Unmarshal error = %v, want ErrMarshalRefused", err)
	}
}

// Redaction must not be so total that it is useless: the rendered text should
// still identify the type and carry the non-secret metadata an operator needs.
func TestRedactedTextIsUseful(t *testing.T) {
	t.Parallel()

	expiry := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	set := auth.NewTokenSet(canary, canary, expiry, []string{"read", "write"})

	got := set.String()
	for _, want := range []string{"TokenSet", "read", "write", "2026"} {
		if !strings.Contains(got, want) {
			t.Errorf("TokenSet.String() = %q, want it to contain %q", got, want)
		}
	}
	if !strings.Contains(got, auth.Redacted) {
		t.Errorf("TokenSet.String() = %q, want it to contain the redaction marker %q", got, auth.Redacted)
	}

	header := auth.NewHeader("Authorization", canary)
	if got := header.String(); !strings.Contains(got, "Authorization") || !strings.Contains(got, auth.Redacted) {
		t.Errorf("Header.String() = %q, want it to name the header and redact the value", got)
	}
}

// Redaction reports presence, not content. An absent secret renders as empty
// rather than as the marker: there is nothing to redact, and the difference
// between "the server issued no refresh token" and "we hold one" is exactly the
// non-secret fact an operator reading a log is trying to establish.
func TestRedactionReportsPresenceNotContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		set         auth.TokenSet
		wantMarker  bool
		wantEmptyIn bool
	}{
		{name: "both present", set: auth.NewTokenSet(canary, canary, time.Time{}, nil), wantMarker: true},
		{name: "neither present", set: auth.NewTokenSet("", "", time.Time{}, nil), wantEmptyIn: true},
		{name: "access only", set: auth.NewTokenSet(canary, "", time.Time{}, nil), wantMarker: true, wantEmptyIn: true},
		{name: "zero value", set: auth.TokenSet{}, wantEmptyIn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.set.String()
			if strings.Contains(got, canary) {
				t.Fatalf("String() leaked: %s", got)
			}
			if gotMarker := strings.Contains(got, auth.Redacted); gotMarker != tt.wantMarker {
				t.Errorf("String() = %q, redaction marker present = %v, want %v", got, gotMarker, tt.wantMarker)
			}
			if gotEmpty := strings.Contains(got, "<empty>"); gotEmpty != tt.wantEmptyIn {
				t.Errorf("String() = %q, empty marker present = %v, want %v", got, gotEmpty, tt.wantEmptyIn)
			}
		})
	}
}

// The accessors are the deliberate escape hatch: a TokenStore that persists
// must be able to reach the secret. If this test fails, persistence is
// impossible and the design is wrong in the other direction.
func TestAccessorsExposeSecretsDeliberately(t *testing.T) {
	t.Parallel()

	set := auth.NewTokenSet(canary, canary+"-r", time.Time{}, nil)
	if got := set.Access(); got != canary {
		t.Errorf("Access() = %q, want the access token back verbatim", got)
	}
	if got := set.Refresh(); got != canary+"-r" {
		t.Errorf("Refresh() = %q, want the refresh token back verbatim", got)
	}
	header := auth.NewHeader("Authorization", canary)
	if got := header.Value(); got != canary {
		t.Errorf("Header.Value() = %q, want the value back verbatim", got)
	}
}

// An auth Error must never render secret text, even when the cause carries it:
// Error deliberately does not substitute wrapped text into its message.
func TestErrorDoesNotRenderWrappedSecret(t *testing.T) {
	t.Parallel()

	cause := fmt.Errorf("keyring said: %s", canary)
	err := auth.NewError(auth.ClassFailed, "refresh", "token refresh rejected", cause)

	for _, verb := range verbs {
		if got := fmt.Sprintf(verb, err); strings.Contains(got, canary) {
			t.Errorf("fmt.Sprintf(%q, err) leaked the wrapped secret: %s", verb, got)
		}
	}
	if got := err.Error(); strings.Contains(got, canary) {
		t.Errorf("Error() leaked the wrapped secret: %s", got)
	}
	// The cause must still be reachable for programmatic inspection.
	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false, want true: the cause must stay reachable")
	}
}

// Status is designed to be logged as-is. Nothing that reaches it may carry a
// secret, and its Failure text is bounded and normalized at construction.
func TestStatusDoesNotCarrySecrets(t *testing.T) {
	t.Parallel()

	status := auth.NewStatus(auth.StateFailed, time.Time{}, []string{"read"}, "refresh rejected")
	for _, verb := range verbs {
		if got := fmt.Sprintf(verb, status); strings.Contains(got, canary) {
			t.Errorf("fmt.Sprintf(%q, status) leaked: %s", verb, got)
		}
	}
	got, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("json.Marshal(Status) error = %v, want Status to marshal: it is designed to be logged", err)
	}
	if strings.Contains(string(got), canary) {
		t.Errorf("json.Marshal(Status) leaked: %s", got)
	}
}
