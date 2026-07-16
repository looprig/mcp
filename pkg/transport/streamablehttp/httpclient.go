// This file is the HTTP layer this transport owns: the client it builds, the
// client it will accept from a caller, and the RoundTripper through which every
// request and every response passes.
//
// The RoundTripper is where this package's guarantees actually live. The SDK
// above it composes MCP out of HTTP requests; this is the one place that sees
// all of them, so it is the only place that can attach a credential to each one,
// bound what each one may return, and record why one failed.

package streamablehttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/auth"
)

// minTLSVersion is the floor for every HTTPS connection this transport makes,
// on a client it built and on a client it was given alike.
const minTLSVersion = tls.VersionTLS12

// wireLimits is this package's normalized view of protocol.WireLimits: every
// field is positive.
type wireLimits struct {
	maxBody  int
	maxFrame int
}

// Defaults applied when a WireLimits field is not positive.
//
// They exist because a transport may legitimately be driven without the client
// above it — a test, or an application composing its own — and limits.BoundedReader
// treats a non-positive bound as a programmer error, not as "unbounded". The
// values match client.DefaultLimits; they are restated rather than imported
// because pkg/client imports this direction, not the other.
const (
	// defaultMaxBodyBytes caps one non-streaming response body.
	defaultMaxBodyBytes = 16 << 20
	// defaultMaxFrameBytes caps one SSE event.
	defaultMaxFrameBytes = 4 << 20
)

// newWireLimits normalizes what the client passed. A non-positive field means the
// caller did not set one — client.Connect always passes normalized values — and
// gets this package's default; it never means unbounded, which is not a setting.
func newWireLimits(w protocol.WireLimits) wireLimits {
	pick := func(v, def int) int {
		if v <= 0 {
			return def
		}
		return v
	}
	return wireLimits{
		maxBody:  pick(w.MaxBodyBytes, defaultMaxBodyBytes),
		maxFrame: pick(w.MaxFrameBytes, defaultMaxFrameBytes),
	}
}

// vetTransport returns the *http.Transport every connection's client is built
// on, from the caller's client if it supplied one.
//
// A supplied client is neither trusted nor mutated. It is read, refused if it
// contradicts this package's guarantees, and otherwise cloned — so a caller that
// supplies a client to pin a CA or route through a proxy gets that, without also
// getting the ability to turn certificate verification off by accident, and
// without this package reaching into a value the caller still holds.
func vetTransport(c *http.Client, t Timeouts) (*http.Transport, error) {
	if c == nil {
		return defaultTransport(t), nil
	}
	if c.Timeout != 0 {
		return nil, fmt.Errorf(
			"HTTPClient.Timeout is %v: it must be zero, because it bounds a whole exchange including the body — "+
				"it would sever the SSE streams this transport reads and cut off slow tool calls; "+
				"use Timeouts.ResponseHeader to bound a server that does not answer", c.Timeout)
	}
	if c.Transport == nil {
		return defaultTransport(t), nil
	}
	base, ok := c.Transport.(*http.Transport)
	if !ok {
		// A custom RoundTripper. There is no way to read its TLS posture, so
		// there is no way to promise anything about it — and promising anyway is
		// the fail-open this module does not do. The refusal names the way in:
		// a caller wanting custom behavior supplies an *http.Transport, which
		// carries a Proxy, a DialContext and a TLSClientConfig between them.
		return nil, fmt.Errorf("HTTPClient.Transport is %T: it must be *http.Transport, "+
			"because this transport must be able to verify that TLS is configured safely", c.Transport)
	}
	if base.TLSClientConfig != nil && base.TLSClientConfig.InsecureSkipVerify {
		return nil, errors.New("HTTPClient.Transport has TLSClientConfig.InsecureSkipVerify set: " +
			"certificate verification is not optional; to trust a private CA, set TLSClientConfig.RootCAs")
	}

	// Cloned, so what follows edits this package's copy and not the caller's
	// live client. Transport.Clone deep-copies TLSClientConfig, so the floor set
	// below cannot reach back either.
	base = base.Clone()
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{MinVersion: minTLSVersion}
	} else if base.TLSClientConfig.MinVersion < minTLSVersion {
		// Raised, not refused: zero is what a caller who never thought about it
		// leaves behind (it means "the stdlib's floor"), and refusing a client
		// that is merely unopinionated would make supplying a CA pool needlessly
		// painful. A caller who deliberately asked for TLS 1.0 gets 1.2 anyway,
		// which is the direction this package is allowed to move.
		base.TLSClientConfig.MinVersion = minTLSVersion
	}
	// The timeouts are this package's contract, not the caller's: they are
	// stated as defaults on Timeouts and documented as always applying. Fields
	// the caller set are only overwritten where this package promises a bound.
	base.TLSHandshakeTimeout = t.TLSHandshake
	base.ResponseHeaderTimeout = t.ResponseHeader
	base.IdleConnTimeout = t.Idle
	return base, nil
}

// defaultTransport builds the transport used when the caller supplies no
// client. It is http.DefaultTransport's shape with this package's bounds and a
// TLS floor, rather than http.DefaultTransport itself: that one is shared with
// the whole process, and editing it would be editing everyone's.
func defaultTransport(t Timeouts) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   t.Dial,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       t.Idle,
		TLSHandshakeTimeout:   t.TLSHandshake,
		ResponseHeaderTimeout: t.ResponseHeader,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			// Never InsecureSkipVerify. There is no configuration that sets it,
			// which is the strongest form of "never": a caller who needs a
			// private CA supplies RootCAs on their own client's transport.
			MinVersion: minTLSVersion,
		},
	}
}

// roundTripper attaches credentials to every request and bounds every response.
//
// It is one connection's, not one factory's, because the diagnostics it writes
// belong to one session's failure.
type roundTripper struct {
	base     http.RoundTripper
	headers  []auth.Header
	provider auth.HeaderProvider
	wire     wireLimits
	// request bounds a whole non-streaming exchange; see Timeouts.Request.
	request time.Duration
	diags   *diagnostics
}

// RoundTrip implements http.RoundTripper.
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Cloned before anything is written: RoundTrip must not modify the request
	// it is given, and the SDK builds requests it may still be holding.
	req = req.Clone(req.Context())

	if err := rt.attachCredentials(req); err != nil {
		return nil, err
	}

	// A request that cannot stream gets a deadline of its own. Every other
	// request's response may be an SSE stream, and a deadline on one of those is
	// a deadline on the session; those are bounded by ResponseHeaderTimeout and
	// by the caller's context instead. See Timeouts.
	var cancel context.CancelFunc
	if !mayStream(req) {
		var ctx context.Context
		ctx, cancel = context.WithTimeout(req.Context(), rt.request)
		req = req.WithContext(ctx)
	}

	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		rt.diags.recordStatus(resp.StatusCode)
	}
	resp.Body = rt.boundBody(resp, cancel)
	return resp, nil
}

// attachCredentials writes the static headers and then the provider's onto req.
//
// Order matters and is documented on Config.Headers: the provider is applied
// second and with Set, so a live credential wins over a configured one naming
// the same field.
//
// Every header is validated before it is written, including the provider's. The
// static ones were validated by New, but a provider is application code that
// mints a value per request, and a value with a newline in it appends headers of
// the application's choosing to this request. Validating here is what makes that
// impossible rather than unlikely.
func (rt *roundTripper) attachCredentials(req *http.Request) error {
	for _, h := range rt.headers {
		req.Header.Set(h.Name(), h.Value())
	}
	if rt.provider == nil {
		return nil
	}

	// The request's context, so a credential that needs I/O to mint is bounded
	// by the caller who wanted the request.
	headers, err := rt.provider.Headers(req.Context())
	if err != nil {
		return rt.rejectCredentials(err)
	}
	for i, h := range headers {
		if err := h.Validate(); err != nil {
			return rt.rejectCredentials(fmt.Errorf("auth header provider returned an invalid header at index %d: %w", i, err))
		}
		req.Header.Set(h.Name(), h.Value())
	}
	return nil
}

// rejectCredentials records an auth failure and returns it.
//
// It is recorded as well as returned because returning is not enough: the SDK
// flattens some of its error paths with %v, so the chain this error travels in
// may not survive to reach classify. The recording is what does.
func (rt *roundTripper) rejectCredentials(err error) error {
	rt.diags.recordAuthError(err)
	return err
}

// boundBody wraps resp.Body so that nothing unbounded is ever buffered, and so
// that a non-streaming request's deadline is released when its body is done.
//
// The bound depends on what the body is, and the difference is not a detail: a
// non-streaming body is one message and is capped whole, while an SSE stream is
// a session's worth of messages and is capped per frame. Capping a stream whole
// would work perfectly and then kill a healthy session in an hour, which is the
// kind of bug that reaches production.
func (rt *roundTripper) boundBody(resp *http.Response, cancel context.CancelFunc) io.ReadCloser {
	var r io.Reader
	if isEventStream(resp.Header.Get("Content-Type")) {
		r = newFrameReader(resp.Body, rt.wire.maxFrame, rt.diags)
	} else {
		r = &recordingReader{
			r:     limits.BoundedReader(resp.Body, rt.wire.maxBody),
			diags: rt.diags,
		}
	}
	return &boundedBody{Reader: r, closer: resp.Body, cancel: cancel}
}

// mayStream reports whether req's response could be an SSE stream.
//
// It is a question about this transport's own traffic, not a general one: the
// SDK POSTs messages (whose response is JSON or a stream, decided by the
// server), GETs the standalone stream, and DELETEs the session. Only the DELETE
// is certain not to stream, so only the DELETE gets a whole-request deadline.
// The test is by exclusion — anything unrecognized is treated as possibly
// streaming — because the cost of being wrong runs one way: a missing deadline
// on a request that had another bound anyway, versus a severed session.
func mayStream(req *http.Request) bool {
	return req.Method != http.MethodDelete
}

// isEventStream reports whether a Content-Type names SSE, ignoring parameters
// ("text/event-stream; charset=utf-8") and case, both of which are the server's
// choice and neither of which changes what the body is.
func isEventStream(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "text/event-stream"
}

// boundedBody is the response body handed back to the SDK: bounded reads, the
// original's Close, and the release of a deadline this package took out.
type boundedBody struct {
	io.Reader
	closer io.Closer
	// cancel releases the whole-request context, or is nil for a request that
	// did not get one.
	cancel context.CancelFunc
}

// Close closes the underlying body and releases the request's deadline.
//
// Close, not EOF: a caller that stops reading early — which http.Client itself
// does on some paths — must still release both, and only Close is guaranteed to
// happen. It is safe to call twice; both halves are idempotent.
func (b *boundedBody) Close() error {
	err := b.closer.Close()
	if b.cancel != nil {
		b.cancel()
	}
	return err
}

// recordingReader reports an over-limit read to diagnostics as it happens.
//
// It exists because the error does not survive the trip: the SDK reads a JSON
// body with io.ReadAll and renders a failure with %v, which flattens the chain,
// so by the time classify sees it the *limits.OverLimitError is a string. This
// catches it at the only point where it is still a value.
type recordingReader struct {
	r     io.Reader
	diags *diagnostics
}

func (rr *recordingReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	var over *limits.OverLimitError
	if errors.As(err, &over) {
		rr.diags.recordLimitError(over)
	}
	return n, err
}

// diagnostics is what one connection recorded about its own failure, on the way
// past, at the point where the cause was still a value.
//
// It is a record and not a channel: nothing waits on it, and nothing acts on it
// except classify, after something has already failed. That is why the
// last-writer-wins fields below are honest — there is exactly one failure being
// explained, and it is the reason the session is over.
//
// It is safe for concurrent use: the SDK reads its streams on goroutines of its
// own, so a status and a body can be recorded from two places at once.
type diagnostics struct {
	mu sync.Mutex
	// lastStatus is the last HTTP error status seen, or 0.
	//
	// Only statuses >= 400 are recorded, so a later success cannot erase the
	// failure that is being explained. It is a diagnostic and is treated as one:
	// classify consults it only after the session has already failed, and only
	// when nothing more specific was recorded.
	lastStatus int
	authErr    error
	limitErr   error
}

func (d *diagnostics) recordStatus(status int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastStatus = status
}

func (d *diagnostics) status() (int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastStatus, d.lastStatus != 0
}

// recordAuthError keeps the first auth failure, not the last: once credentials
// are refused, every request after it fails the same way, and the first one is
// the one that explains the session.
func (d *diagnostics) recordAuthError(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.authErr == nil {
		d.authErr = err
	}
}

// authError returns the recorded auth failure as an *auth.Error, or nil.
//
// A provider is application code and may return anything. A failure that is not
// an *auth.Error is still an auth failure — the provider was asked for a
// credential and did not produce one — so it is reported as one, with the class
// that says exactly that much and no more.
func (d *diagnostics) authError() *auth.Error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.authErr == nil {
		return nil
	}
	var aerr *auth.Error
	if errors.As(d.authErr, &aerr) {
		return aerr
	}
	// Wrapped, not rendered: the provider's text is not something this package
	// can vouch for, and auth.Error never renders its cause.
	return auth.NewError(auth.ClassFailed, "headers",
		"the auth header provider did not return credentials", d.authErr)
}

func (d *diagnostics) recordLimitError(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.limitErr == nil {
		d.limitErr = err
	}
}

func (d *diagnostics) limitError() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.limitErr
}
