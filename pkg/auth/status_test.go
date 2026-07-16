package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/looprig/mcp/pkg/auth"
)

func TestStateStringUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state auth.State
	}{
		{name: "zero value", state: auth.State(0)},
		{name: "max uint8", state: auth.State(255)},
		{name: "arbitrary undeclared", state: auth.State(200)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != "unknown" {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, "unknown")
			}
		})
	}
}

func TestNewStatusBoundsFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		failure string
		check   func(t *testing.T, got string)
	}{
		{
			name:    "short text is preserved",
			failure: "refresh rejected",
			check: func(t *testing.T, got string) {
				if got != "refresh rejected" {
					t.Errorf("Failure = %q, want it unchanged", got)
				}
			},
		},
		{
			name:    "empty stays empty",
			failure: "",
			check: func(t *testing.T, got string) {
				if got != "" {
					t.Errorf("Failure = %q, want empty", got)
				}
			},
		},
		{
			name:    "over-long text is truncated",
			failure: strings.Repeat("x", auth.MaxMessageBytes*2),
			check: func(t *testing.T, got string) {
				if len(got) > auth.MaxMessageBytes {
					t.Errorf("Failure is %d bytes, want at most %d", len(got), auth.MaxMessageBytes)
				}
			},
		},
		{
			name:    "control characters are normalized",
			failure: "line one\nline two\x00\x07",
			check: func(t *testing.T, got string) {
				if strings.ContainsAny(got, "\n\x00\x07") {
					t.Errorf("Failure = %q, want control characters replaced", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := auth.NewStatus(auth.StateFailed, time.Time{}, nil, tt.failure)
			tt.check(t, got.Failure)
		})
	}
}

func TestNewStatusFields(t *testing.T) {
	t.Parallel()

	expiry := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	scopes := []string{"read", "write"}
	got := auth.NewStatus(auth.StateAuthenticated, expiry, scopes, "")

	if got.State != auth.StateAuthenticated {
		t.Errorf("State = %v, want %v", got.State, auth.StateAuthenticated)
	}
	if !got.Expiry.Equal(expiry) {
		t.Errorf("Expiry = %v, want %v", got.Expiry, expiry)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("Scopes = %v, want 2 entries", got.Scopes)
	}

	// The Status must be detached from the caller's backing array.
	scopes[0] = "mutated"
	if got.Scopes[0] != "read" {
		t.Errorf("mutating the argument changed the Status: Scopes[0] = %q, want %q", got.Scopes[0], "read")
	}
}

// A Status for an unauthenticated binding carries no expiry and no failure.
func TestNewStatusAnonymous(t *testing.T) {
	t.Parallel()

	got := auth.NewStatus(auth.StateAnonymous, time.Time{}, nil, "")
	if !got.Expiry.IsZero() {
		t.Errorf("Expiry = %v, want zero", got.Expiry)
	}
	if got.Failure != "" {
		t.Errorf("Failure = %q, want empty", got.Failure)
	}
	if got.Scopes != nil {
		t.Errorf("Scopes = %v, want nil", got.Scopes)
	}
}

// StatusOf is the one place the token model and the observable model meet, so
// the mapping is pinned here rather than left to each caller.
func TestStatusOf(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)

	tests := []struct {
		name string
		set  auth.TokenSet
		want auth.State
	}{
		{name: "valid unexpired token", set: auth.NewTokenSet("tok", "", expiry, nil), want: auth.StateAuthenticated},
		{name: "no expiry is authenticated", set: auth.NewTokenSet("tok", "", time.Time{}, nil), want: auth.StateAuthenticated},
		{name: "expired token", set: auth.NewTokenSet("tok", "ref", now.Add(-time.Hour), nil), want: auth.StateExpired},
		{name: "inside skew is expired", set: auth.NewTokenSet("tok", "", now.Add(auth.ExpirySkew-time.Second), nil), want: auth.StateExpired},
		{name: "no access token", set: auth.TokenSet{}, want: auth.StateRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := auth.StatusOf(tt.set, now)
			if got.State != tt.want {
				t.Errorf("StatusOf().State = %v, want %v", got.State, tt.want)
			}
			if got.Failure != "" {
				t.Errorf("StatusOf().Failure = %q, want empty: a token posture is not a failure", got.Failure)
			}
		})
	}
}

func TestStatusOfCarriesMetadata(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	got := auth.StatusOf(auth.NewTokenSet("tok", "", expiry, []string{"read"}), now)

	if !got.Expiry.Equal(expiry) {
		t.Errorf("Expiry = %v, want %v", got.Expiry, expiry)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "read" {
		t.Errorf("Scopes = %v, want [read]", got.Scopes)
	}
}
