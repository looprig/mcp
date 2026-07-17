package auth_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/looprig/mcp/pkg/auth"
)

func TestClassStringUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		class auth.Class
	}{
		{name: "zero value", class: auth.Class(0)},
		{name: "max uint8", class: auth.Class(255)},
		{name: "arbitrary undeclared", class: auth.Class(200)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.class.String(); got != "unknown" {
				t.Errorf("Class(%d).String() = %q, want %q", tt.class, got, "unknown")
			}
		})
	}
}

func TestErrorRendering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *auth.Error
		want string
	}{
		{
			name: "full",
			err:  auth.NewError(auth.ClassDenied, "authorize", "user declined consent", nil),
			want: "auth: authorize: denied: user declined consent",
		},
		{
			name: "no op",
			err:  auth.NewError(auth.ClassExpired, "", "token expired", nil),
			want: "auth: expired: token expired",
		},
		{
			name: "no message",
			err:  auth.NewError(auth.ClassNoToken, "load", "", nil),
			want: "auth: load: no_token",
		},
		{
			name: "unknown class",
			err:  auth.NewError(auth.Class(0), "load", "boom", nil),
			want: "auth: load: unknown: boom",
		},
		{
			name: "wrapped cause is not rendered",
			err:  auth.NewError(auth.ClassFailed, "refresh", "", errors.New("dial tcp: secret in here")),
			want: "auth: refresh: failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewErrorBoundsMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		msg   string
		check func(t *testing.T, got string)
	}{
		{
			name: "over-long message is truncated",
			msg:  strings.Repeat("x", auth.MaxMessageBytes*2),
			check: func(t *testing.T, got string) {
				if len(got) > auth.MaxMessageBytes {
					t.Errorf("Msg is %d bytes, want at most %d", len(got), auth.MaxMessageBytes)
				}
			},
		},
		{
			name: "control characters are normalized",
			msg:  "a\nb\x00c",
			check: func(t *testing.T, got string) {
				if strings.ContainsAny(got, "\n\x00") {
					t.Errorf("Msg = %q, want control characters replaced", got)
				}
			},
		},
		{
			name: "invalid utf-8 is repaired",
			msg:  "ok\xff\xfebad",
			check: func(t *testing.T, got string) {
				if !utf8.ValidString(got) {
					t.Errorf("Msg = %q, want valid UTF-8", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.check(t, auth.NewError(auth.ClassFailed, "op", tt.msg, nil).Msg)
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("cause")
	err := auth.NewError(auth.ClassFailed, "refresh", "failed", cause)

	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false, want true")
	}
	if got := errors.Unwrap(err); got != cause {
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}
}

func TestClassOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		wantClass auth.Class
		wantOK    bool
	}{
		{
			name:      "direct",
			err:       auth.NewError(auth.ClassDenied, "authorize", "no", nil),
			wantClass: auth.ClassDenied,
			wantOK:    true,
		},
		{
			name:      "wrapped in a plain error",
			err:       fmt.Errorf("context: %w", auth.NewError(auth.ClassExpired, "refresh", "no", nil)),
			wantClass: auth.ClassExpired,
			wantOK:    true,
		},
		{name: "not an auth error", err: errors.New("plain"), wantOK: false},
		{name: "nil", err: nil, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := auth.ClassOf(tt.err)
			if ok != tt.wantOK {
				t.Fatalf("ClassOf() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got != tt.wantClass {
				t.Errorf("ClassOf() = %v, want %v", got, tt.wantClass)
			}
		})
	}
}

// ErrNoToken is the contract every TokenStore implementation must honor for an
// absent token, so it must be reachable both as a sentinel and as a class.
func TestNewNoTokenError(t *testing.T) {
	t.Parallel()

	err := auth.NewNoTokenError("load")
	if !errors.Is(err, auth.ErrNoToken) {
		t.Error("errors.Is(NewNoTokenError(...), ErrNoToken) = false, want true")
	}
	if class, ok := auth.ClassOf(err); !ok || class != auth.ClassNoToken {
		t.Errorf("ClassOf() = (%v, %v), want (%v, true)", class, ok, auth.ClassNoToken)
	}
}

// An absent token must be distinguishable from a store failure: this is the
// fail-closed distinction the whole sentinel exists for.
func TestErrNoTokenDistinguishesAbsentFromFailure(t *testing.T) {
	t.Parallel()

	failure := auth.NewError(auth.ClassFailed, "load", "keyring unavailable", nil)
	if errors.Is(failure, auth.ErrNoToken) {
		t.Error("a store failure matched ErrNoToken; absent and broken must not be conflated")
	}
}

// TestErrorNeverRendersTheCauseThroughACopy pins "never rendered" as a property
// of the TYPE, not of the pointers this package happens to hand out.
//
// Error's methods had pointer receivers, so Formatter was in *Error's method set
// alone and a VALUE copy fell through to fmt's reflection path — which reads the
// exported Err field and prints the wrapped cause in full. `fmt.Sprintf("%v",
// *err)` printed the secret the type promises never to render. Copying an error
// value is not a misuse, so the guarantee has to survive it.
func TestErrorNeverRendersTheCauseThroughACopy(t *testing.T) {
	t.Parallel()
	const secret = "SECRET-CAUSE-TEXT"
	ptr := auth.NewError(auth.ClassFailed, "refresh", "boom", errors.New(secret))
	value := *ptr

	// Verbs held in variables: a literal would let vet reject the wrong-type
	// verbs this test exists to drive, and those are exactly a caller's typo.
	for _, verb := range []string{"%v", "%s", "%q", "%d", "%x", "%#v", "%+v", "%t", "%c"} {
		for _, target := range []struct {
			what string
			val  any
		}{
			{"pointer", ptr},
			{"value copy", value},
			{"pointer to the copy", &value},
			{"slice of values", []auth.Error{value}},
			{"struct embedding a value", struct{ E auth.Error }{value}},
		} {
			got := fmt.Sprintf(verb, target.val)
			if strings.Contains(got, secret) {
				t.Errorf("%s rendered with %s leaks the wrapped cause: %s", target.what, verb, got)
			}
		}
	}
}
