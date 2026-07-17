// This test covers the boundary between httpsec's Diagnostics and this package's
// classify: a diagnostic must explain the request that produced it, not a later
// one. It drives a real RoundTripper (where the per-request reset lives) and a
// real Conn.classify (where a stale diagnostic would be misapplied), because the
// bug is exactly the seam between them — a status recorded by one request being
// read to explain another.

package httpconn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/httpsec"
	"github.com/looprig/mcp/pkg/auth"
	"github.com/looprig/mcp/pkg/client"
)

// TestStaleStatusDoesNotMisclassifyALaterTransportLoss is Fix #7: request A gets
// a 401, and a later request B suffers a genuine transport loss. B's failure
// must be classified on its own cause, never on A's stale 401.
func TestStaleStatusDoesNotMisclassifyALaterTransportLoss(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	origin, err := auth.CanonicalOrigin(srv.URL)
	if err != nil {
		t.Fatalf("CanonicalOrigin() error = %v", err)
	}
	diags := &httpsec.Diagnostics{}
	rt := &httpsec.RoundTripper{
		Base:    http.DefaultTransport,
		Diags:   diags,
		Origin:  origin,
		Request: 2 * time.Second,
		Wire:    httpsec.WireLimits{MaxBody: 1 << 20, MaxFrame: 1 << 16},
	}

	// Request A: a real 401, recorded on the connection's diagnostics.
	reqA, err := http.NewRequest(http.MethodPost, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest(A) error = %v", err)
	}
	respA, err := rt.RoundTrip(reqA)
	if err != nil {
		t.Fatalf("RoundTrip(A) error = %v", err)
	}
	_ = respA.Body.Close()
	if status, ok := diags.Status(); !ok || status != http.StatusUnauthorized {
		t.Fatalf("after request A: diags.Status() = (%d, %v), want (401, true)", status, ok)
	}

	// The server goes away, so request B cannot connect: a genuine transport loss
	// with no response and no status of its own.
	srv.Close()
	reqB, err := http.NewRequest(http.MethodPost, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest(B) error = %v", err)
	}
	_, errB := rt.RoundTrip(reqB)
	if errB == nil {
		t.Fatal("RoundTrip(B) error = nil, want a transport loss against a closed server")
	}

	// The mechanism: B's RoundTrip cleared A's status, so nothing stale survives.
	if status, ok := diags.Status(); ok {
		t.Errorf("after request B: diags.Status() = (%d, %v), want cleared: A's 401 must not outlive its request", status, ok)
	}

	// The consequence: classifying B's failure yields B's own cause, not A's 401
	// class (FailureAuthRequired).
	c := New(nil, diags, "streamable HTTP", srv.URL, origin)
	out := c.classify(context.Background(), OpCallTool, errB)
	class, ok := client.ClassOf(out)
	if !ok {
		t.Fatalf("classify() returned an unclassifiable error: %v", out)
	}
	if class == statusClass(http.StatusUnauthorized) {
		t.Errorf("B's transport loss was classified %v — A's stale 401 class; want B's own transport cause", class)
	}
	if class != client.FailureServerProtocol {
		t.Errorf("classify() class = %v, want %v (the transport-loss fallback)", class, client.FailureServerProtocol)
	}
}
