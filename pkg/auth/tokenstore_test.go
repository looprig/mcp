package auth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/pkg/auth"
)

func TestKeyValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     auth.Key
		wantErr bool
	}{
		{name: "https origin", key: auth.Key{ServerOrigin: "https://mcp.example.com", ClientID: "abc"}},
		{name: "https origin with port", key: auth.Key{ServerOrigin: "https://mcp.example.com:8443", ClientID: "abc"}},
		{name: "empty client id is allowed", key: auth.Key{ServerOrigin: "https://mcp.example.com"}},
		{name: "http loopback ipv4", key: auth.Key{ServerOrigin: "http://127.0.0.1:8080"}},
		{name: "http loopback ipv4 other octet", key: auth.Key{ServerOrigin: "http://127.9.9.9:8080"}},
		{name: "http loopback ipv6", key: auth.Key{ServerOrigin: "http://[::1]:8080"}},
		{name: "http localhost", key: auth.Key{ServerOrigin: "http://localhost:3000"}},
		{name: "https loopback", key: auth.Key{ServerOrigin: "https://127.0.0.1:8443"}},

		{name: "empty origin", key: auth.Key{ServerOrigin: ""}, wantErr: true},
		{name: "http non-loopback", key: auth.Key{ServerOrigin: "http://mcp.example.com"}, wantErr: true},
		{name: "http public ip", key: auth.Key{ServerOrigin: "http://8.8.8.8"}, wantErr: true},
		{name: "non-http scheme", key: auth.Key{ServerOrigin: "ftp://mcp.example.com"}, wantErr: true},
		{name: "scheme missing", key: auth.Key{ServerOrigin: "mcp.example.com"}, wantErr: true},
		{name: "path present", key: auth.Key{ServerOrigin: "https://mcp.example.com/mcp"}, wantErr: true},
		{name: "trailing slash is a path", key: auth.Key{ServerOrigin: "https://mcp.example.com/"}, wantErr: true},
		{name: "query present", key: auth.Key{ServerOrigin: "https://mcp.example.com?a=b"}, wantErr: true},
		{name: "fragment present", key: auth.Key{ServerOrigin: "https://mcp.example.com#f"}, wantErr: true},
		{name: "userinfo present", key: auth.Key{ServerOrigin: "https://user:pw@mcp.example.com"}, wantErr: true},
		{name: "host missing", key: auth.Key{ServerOrigin: "https://"}, wantErr: true},
		{name: "uppercase host is not canonical", key: auth.Key{ServerOrigin: "https://MCP.example.com"}, wantErr: true},
		{name: "punycode a-label is canonical", key: auth.Key{ServerOrigin: "https://xn--exmple-cua.com"}},
		{name: "unicode idn host is rejected", key: auth.Key{ServerOrigin: "https://exämple.com"}, wantErr: true},
		{name: "mixed-case unicode idn host is rejected", key: auth.Key{ServerOrigin: "https://ExÄmple.com"}, wantErr: true},
		{name: "uppercase scheme is not canonical", key: auth.Key{ServerOrigin: "HTTPS://mcp.example.com"}, wantErr: true},
		{name: "default https port is not canonical", key: auth.Key{ServerOrigin: "https://mcp.example.com:443"}, wantErr: true},
		{name: "default http port is not canonical", key: auth.Key{ServerOrigin: "http://localhost:80"}, wantErr: true},
		{name: "opaque url", key: auth.Key{ServerOrigin: "https:opaque"}, wantErr: true},
		// url.Parse accepts these: it checks the port is digits, not that it
		// is a port. The range check is ours.
		{name: "port above range", key: auth.Key{ServerOrigin: "https://mcp.example.com:99999"}, wantErr: true},
		{name: "port zero", key: auth.Key{ServerOrigin: "https://mcp.example.com:0"}, wantErr: true},
		{name: "non-numeric port", key: auth.Key{ServerOrigin: "https://mcp.example.com:abc"}, wantErr: true},
		{name: "control byte in origin", key: auth.Key{ServerOrigin: "https://mcp.example.com\n"}, wantErr: true},
		{name: "origin over max", key: auth.Key{ServerOrigin: "https://" + strings.Repeat("a", auth.MaxOriginBytes) + ".com"}, wantErr: true},
		{name: "client id over max", key: auth.Key{ServerOrigin: "https://mcp.example.com", ClientID: strings.Repeat("c", auth.MaxClientIDBytes+1)}, wantErr: true},
		{name: "control byte in client id", key: auth.Key{ServerOrigin: "https://mcp.example.com", ClientID: "a\nb"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.key.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Key{%q, %q}.Validate() error = %v, wantErr %v", tt.key.ServerOrigin, tt.key.ClientID, err, tt.wantErr)
			}
			if !tt.wantErr {
				return
			}
			if class, ok := auth.ClassOf(err); !ok || class != auth.ClassInvalidConfig {
				t.Errorf("ClassOf(%v) = (%v, %v), want (%v, true)", err, class, ok, auth.ClassInvalidConfig)
			}
		})
	}
}

func TestKeyString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  auth.Key
		want string
	}{
		{name: "with client id", key: auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"}, want: "https://a.example.com#cid"},
		{name: "without client id", key: auth.Key{ServerOrigin: "https://a.example.com"}, want: "https://a.example.com#-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.key.String(); got != tt.want {
				t.Errorf("Key.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTokenSetExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	newSet := func(expiry time.Time) auth.TokenSet {
		return auth.NewTokenSet("access", "refresh", expiry, nil)
	}

	tests := []struct {
		name string
		set  auth.TokenSet
		want bool
	}{
		{name: "zero expiry never expires", set: newSet(time.Time{}), want: false},
		{name: "far future", set: newSet(now.Add(time.Hour)), want: false},
		{name: "just outside skew", set: newSet(now.Add(auth.ExpirySkew + time.Second)), want: false},
		{name: "exactly at skew boundary", set: newSet(now.Add(auth.ExpirySkew)), want: true},
		{name: "inside skew window", set: newSet(now.Add(auth.ExpirySkew - time.Second)), want: true},
		{name: "exactly at expiry", set: newSet(now), want: true},
		{name: "past expiry", set: newSet(now.Add(-time.Hour)), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.set.Expired(now); got != tt.want {
				t.Errorf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenSetValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		set  auth.TokenSet
		want bool
	}{
		{name: "has access token", set: auth.NewTokenSet("a", "", time.Time{}, nil), want: true},
		{name: "expired but still has access token", set: auth.NewTokenSet("a", "", time.Unix(1, 0), nil), want: true},
		{name: "no access token", set: auth.NewTokenSet("", "refresh", time.Time{}, nil), want: false},
		{name: "zero value", set: auth.TokenSet{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.set.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenSetAccessors(t *testing.T) {
	t.Parallel()

	expiry := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	set := auth.NewTokenSet("access-tok", "refresh-tok", expiry, []string{"a", "b"})

	if got := set.Access(); got != "access-tok" {
		t.Errorf("Access() = %q, want %q", got, "access-tok")
	}
	if got := set.Refresh(); got != "refresh-tok" {
		t.Errorf("Refresh() = %q, want %q", got, "refresh-tok")
	}
	if got := set.Expiry(); !got.Equal(expiry) {
		t.Errorf("Expiry() = %v, want %v", got, expiry)
	}
	if got := set.Scopes(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("Scopes() = %v, want [a b]", got)
	}
}

// NewTokenSet must detach from the caller's backing array, and Scopes must
// hand out a copy — otherwise a caller can mutate a stored TokenSet.
func TestTokenSetScopesAreDetached(t *testing.T) {
	t.Parallel()

	in := []string{"a", "b"}
	set := auth.NewTokenSet("tok", "", time.Time{}, in)

	in[0] = "mutated"
	if got := set.Scopes(); got[0] != "a" {
		t.Errorf("mutating the constructor argument changed the TokenSet: Scopes()[0] = %q, want %q", got[0], "a")
	}

	out := set.Scopes()
	out[0] = "mutated"
	if got := set.Scopes(); got[0] != "a" {
		t.Errorf("mutating a returned scope slice changed the TokenSet: Scopes()[0] = %q, want %q", got[0], "a")
	}
}

func TestMemoryStoreLoadAbsent(t *testing.T) {
	t.Parallel()

	store := auth.NewMemoryStore()
	key := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"}

	_, err := store.Load(context.Background(), key)
	if err == nil {
		t.Fatal("Load() of an absent key returned nil error, want ErrNoToken")
	}
	if !errors.Is(err, auth.ErrNoToken) {
		t.Errorf("errors.Is(%v, ErrNoToken) = false, want true", err)
	}
	if class, ok := auth.ClassOf(err); !ok || class != auth.ClassNoToken {
		t.Errorf("ClassOf(%v) = (%v, %v), want (%v, true)", err, class, ok, auth.ClassNoToken)
	}
}

func TestMemoryStoreRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := auth.NewMemoryStore()
	key := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"}
	expiry := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	want := auth.NewTokenSet("access-tok", "refresh-tok", expiry, []string{"read"})

	if err := store.Store(ctx, key, want); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	got, err := store.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Access() != want.Access() || got.Refresh() != want.Refresh() || !got.Expiry().Equal(want.Expiry()) {
		t.Errorf("Load() = %v, want the stored set", got)
	}
	if scopes := got.Scopes(); len(scopes) != 1 || scopes[0] != "read" {
		t.Errorf("Load().Scopes() = %v, want [read]", scopes)
	}
}

// A TokenSet handed back by Load must be a copy: mutating its scopes must not
// reach the stored state. This is the aliasing bug class the accessor design
// is meant to make impossible.
func TestMemoryStoreLoadReturnsCopy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := auth.NewMemoryStore()
	key := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"}
	if err := store.Store(ctx, key, auth.NewTokenSet("tok", "", time.Time{}, []string{"read"})); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	first, err := store.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	first.Scopes()[0] = "admin"

	second, err := store.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := second.Scopes()[0]; got != "read" {
		t.Errorf("stored scopes were mutated through a loaded copy: got %q, want %q", got, "read")
	}
}

func TestMemoryStoreStoreOverwrites(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := auth.NewMemoryStore()
	key := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"}

	if err := store.Store(ctx, key, auth.NewTokenSet("first", "", time.Time{}, nil)); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	if err := store.Store(ctx, key, auth.NewTokenSet("second", "", time.Time{}, nil)); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	got, err := store.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Access() != "second" {
		t.Errorf("Load().Access() = %q, want %q", got.Access(), "second")
	}
}

func TestMemoryStoreDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := auth.NewMemoryStore()
	key := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"}

	// Delete of an absent key is a no-op, not an error: the caller's intent
	// (no token for this key) already holds.
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() of an absent key error = %v, want nil", err)
	}
	if err := store.Store(ctx, key, auth.NewTokenSet("tok", "", time.Time{}, nil)); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Load(ctx, key); !errors.Is(err, auth.ErrNoToken) {
		t.Errorf("Load() after Delete() error = %v, want ErrNoToken", err)
	}
}

// Keys differing only by ClientID are distinct: the same server reached with a
// different registered client must not share a token.
func TestMemoryStoreKeyIdentity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := auth.NewMemoryStore()
	a := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "one"}
	b := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "two"}

	if err := store.Store(ctx, a, auth.NewTokenSet("tok-a", "", time.Time{}, nil)); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	if _, err := store.Load(ctx, b); !errors.Is(err, auth.ErrNoToken) {
		t.Errorf("Load() with a different ClientID error = %v, want ErrNoToken", err)
	}
}

func TestMemoryStoreRejectsInvalidKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := auth.NewMemoryStore()
	bad := auth.Key{ServerOrigin: "http://public.example.com"}

	if err := store.Store(ctx, bad, auth.NewTokenSet("tok", "", time.Time{}, nil)); err == nil {
		t.Error("Store() with an invalid key returned nil error, want an error")
	}
	if _, err := store.Load(ctx, bad); err == nil {
		t.Error("Load() with an invalid key returned nil error, want an error")
	}
	if err := store.Delete(ctx, bad); err == nil {
		t.Error("Delete() with an invalid key returned nil error, want an error")
	}
}

func TestMemoryStoreHonorsContext(t *testing.T) {
	t.Parallel()

	store := auth.NewMemoryStore()
	key := auth.Key{ServerOrigin: "https://a.example.com", ClientID: "cid"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := store.Store(ctx, key, auth.NewTokenSet("tok", "", time.Time{}, nil)); !errors.Is(err, context.Canceled) {
		t.Errorf("Store() with a cancelled context error = %v, want context.Canceled", err)
	}
	if _, err := store.Load(ctx, key); !errors.Is(err, context.Canceled) {
		t.Errorf("Load() with a cancelled context error = %v, want context.Canceled", err)
	}
	if err := store.Delete(ctx, key); !errors.Is(err, context.Canceled) {
		t.Errorf("Delete() with a cancelled context error = %v, want context.Canceled", err)
	}
}

func TestMemoryStoreConcurrent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := auth.NewMemoryStore()
	keys := []auth.Key{
		{ServerOrigin: "https://a.example.com", ClientID: "one"},
		{ServerOrigin: "https://b.example.com", ClientID: "two"},
	}

	const goroutines = 8
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := keys[i%len(keys)]
			for range 50 {
				if err := store.Store(ctx, key, auth.NewTokenSet("tok", "ref", time.Time{}, []string{"read"})); err != nil {
					t.Errorf("Store() error = %v", err)
					return
				}
				if set, err := store.Load(ctx, key); err == nil {
					_ = set.Scopes()
				}
				if err := store.Delete(ctx, key); err != nil {
					t.Errorf("Delete() error = %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// MemoryStore must satisfy the exported interface.
var _ auth.TokenStore = (*auth.MemoryStore)(nil)
