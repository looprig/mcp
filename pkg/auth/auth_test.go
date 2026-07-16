package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/looprig/mcp/pkg/auth"
)

func TestHeaderAccessors(t *testing.T) {
	t.Parallel()

	h := auth.NewHeader("Authorization", "Bearer abc")
	if got := h.Name(); got != "Authorization" {
		t.Errorf("Name() = %q, want %q", got, "Authorization")
	}
	if got := h.Value(); got != "Bearer abc" {
		t.Errorf("Value() = %q, want %q", got, "Bearer abc")
	}
}

func TestHeaderValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  auth.Header
		wantErr bool
	}{
		{name: "well formed", header: auth.NewHeader("Authorization", "Bearer abc")},
		{name: "empty value is allowed", header: auth.NewHeader("X-Trace", "")},
		{name: "empty name", header: auth.NewHeader("", "v"), wantErr: true},
		{name: "space in name", header: auth.NewHeader("X Trace", "v"), wantErr: true},
		{name: "colon in name", header: auth.NewHeader("X:Trace", "v"), wantErr: true},
		{name: "newline in name", header: auth.NewHeader("X\nTrace", "v"), wantErr: true},
		{name: "non-ascii in name", header: auth.NewHeader("X-Träce", "v"), wantErr: true},
		{name: "newline in value", header: auth.NewHeader("X-Trace", "a\nb"), wantErr: true},
		{name: "carriage return in value", header: auth.NewHeader("X-Trace", "a\rb"), wantErr: true},
		{name: "nul in value", header: auth.NewHeader("X-Trace", "a\x00b"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.header.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				return
			}
			if class, ok := auth.ClassOf(err); !ok || class != auth.ClassInvalidConfig {
				t.Errorf("ClassOf() = (%v, %v), want (%v, true)", class, ok, auth.ClassInvalidConfig)
			}
		})
	}
}

// A rejected header must not echo its own value: the value is the secret, and
// a validation error is exactly the kind of thing that gets logged.
func TestHeaderValidateErrorHidesValue(t *testing.T) {
	t.Parallel()

	err := auth.NewHeader("X-Trace", "super-secret-\n-injected").Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want an error")
	}
	if got := err.Error(); strings.Contains(got, "super-secret") {
		t.Errorf("Validate() error leaked the header value: %s", got)
	}
}

// staticHeaders is a minimal HeaderProvider, standing in for the bearer-token
// providers an application supplies. Its presence here proves the interface is
// implementable from outside the module.
type staticHeaders struct {
	headers []auth.Header
	err     error
}

func (s staticHeaders) Headers(ctx context.Context) ([]auth.Header, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.headers, nil
}

func TestHeaderProviderContract(t *testing.T) {
	t.Parallel()

	var provider auth.HeaderProvider = staticHeaders{
		headers: []auth.Header{auth.NewHeader("Authorization", "Bearer abc")},
	}

	got, err := provider.Headers(context.Background())
	if err != nil {
		t.Fatalf("Headers() error = %v", err)
	}
	if len(got) != 1 || got[0].Name() != "Authorization" {
		t.Fatalf("Headers() = %v, want one Authorization header", got)
	}

	// A provider must honor cancellation: it may be doing I/O to mint a token.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Headers(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Headers() with a cancelled context error = %v, want context.Canceled", err)
	}
}

// recordingOpener is a minimal BrowserOpener, proving the interface is
// implementable from outside and that a test can observe the URL without a
// real browser.
type recordingOpener struct{ opened string }

func (r *recordingOpener) OpenURL(ctx context.Context, url string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.opened = url
	return nil
}

func TestBrowserOpenerContract(t *testing.T) {
	t.Parallel()

	opener := &recordingOpener{}
	var browser auth.BrowserOpener = opener

	const url = "https://auth.example.com/authorize?client_id=abc"
	if err := browser.OpenURL(context.Background(), url); err != nil {
		t.Fatalf("OpenURL() error = %v", err)
	}
	if opener.opened != url {
		t.Errorf("OpenURL() recorded %q, want %q", opener.opened, url)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := browser.OpenURL(ctx, url); !errors.Is(err, context.Canceled) {
		t.Errorf("OpenURL() with a cancelled context error = %v, want context.Canceled", err)
	}
}
