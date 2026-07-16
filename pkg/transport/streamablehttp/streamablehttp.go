// Package streamablehttp is the MCP Streamable HTTP transport: it speaks the
// protocol to a remote server over HTTP POST, with server-to-client messages
// arriving on SSE streams.
//
// # What this transport owns, and what it does not
//
// It owns the HTTP client. It does not own the HTTP protocol: unlike the stdio
// transport — which declines the SDK's command transport because that transport
// starts the process itself, leaving no seam for a host that confines its
// servers — this package uses the SDK's StreamableClientTransport, because the
// SDK's HTTP transport has the seam stdio's lacked. It takes an *http.Client,
// and an *http.Client is enough to own everything this module needs to own:
//
//   - credentials, via a RoundTripper that asks the auth seam per request;
//   - TLS, via that client's transport, which this package builds or vets;
//   - timeouts, likewise;
//   - what may be buffered, via the response bodies that RoundTripper returns.
//
// What is left over is the part that is fiddly and that nobody should write
// twice: the Mcp-Session-Id handshake, the Mcp-Protocol-Version header, the
// standalone SSE stream, resumption by Last-Event-ID, and the DELETE that ends
// a session. That is protocol, the SDK implements it, and this package uses the
// SDK for what the SDK is for.
//
// # Retries
//
// A tool call is never retried. Not "retried carefully" — never.
//
// This is a property of the wiring and not a promise made in a comment. The
// SDK's client re-sends a POST in exactly one place: when it is holding an
// OAuthHandler and a request comes back 401 or 403, it authorizes and sends the
// same POST again. This transport leaves OAuthHandler nil — permanently, and
// the auth seam here is a RoundTripper precisely so that it can stay nil — so
// the POST carrying a call is issued once and its failure is reported, whatever
// it was. There is no path that resends it, so there is no path that can
// double-execute a tool that charges a credit card.
//
// What is retried is reading. A dropped SSE stream is reconnected with
// Last-Event-ID, which resumes the byte stream the server is already committed
// to sending; the request that caused it is not re-issued. That is the
// protocol's own resumption and it is safe by construction: it re-reads a
// reply, it does not re-run a call.
//
// # Trust
//
// The server is untrusted and remote, which makes it strictly worse than the
// stdio child: it is anonymous until TLS says otherwise, it can hold a stream
// open forever, it can answer a small request with an unbounded body, and it can
// tell this client to go somewhere else. So TLS is verified always, cleartext is
// refused to anything but loopback, every response body is bounded before it is
// buffered, every stream is bounded per frame — because a total on a stream that
// is designed to live for a session is not a limit, it is an expiry date — and
// every frame is on a clock, because a server that starts a message and stops is
// otherwise a socket held forever.
//
// A redirect that leaves the configured origin is refused outright, credential
// or no credential. This one is worth stating plainly because getting it wrong
// makes this package *worse* than the http.Client underneath it: the stdlib
// strips Authorization across origins, and a transport that attaches
// credentials in a RoundTripper — as this one does, so that they can be
// refreshed per request — runs below that logic and would put the header back.
// See checkRedirect.
package streamablehttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/auth"
	"github.com/looprig/mcp/pkg/client"
)

// kind is the transport kind this package reports. It matches the package name
// and the spec's name for the transport; "http" would be a claim about a
// protocol rather than about which of MCP's two HTTP transports this is (the
// other being pkg/transport/sse).
const kind = "streamablehttp"

// The contracts this package exists to satisfy.
var (
	_ client.TransportFactory = (*factory)(nil)
	_ protocol.Conn           = (*conn)(nil)
)

// Operation names carried by the errors this package returns.
const (
	opNew        = "new"
	opConnect    = "connect"
	opInitialize = "initialize"
	opClose      = "close"
	// The catalog list operations, named as they appear in an error.
	opListTools             = "list_tools"
	opListPrompts           = "list_prompts"
	opListResources         = "list_resources"
	opListResourceTemplates = "list_resource_templates"
)

// streamReconnects is how many times a dropped SSE stream is reconnected before
// the session is failed. It is stated here rather than left to the SDK's default
// so that the number is a decision of this package's: reconnecting a read is
// safe (see the package comment), and five attempts with the SDK's jittered
// backoff spans about a minute of a server being briefly unreachable.
//
// It bounds reconnects that make no progress. A stream that keeps delivering
// events resets the count, so a long, healthy session is never cut off by it.
const streamReconnects = 5

// Config configures a Streamable HTTP transport.
type Config struct {
	// Endpoint is the MCP server's URL: https://, or http:// for a loopback
	// host only. It may carry a path and a query — "https://h/mcp?v=2" is an
	// ordinary endpoint — and neither ever appears in RedactedOrigin or in an
	// error, because a query string is a place people put tokens.
	//
	// It is validated once, by New, against exactly the rules auth.Key demands
	// of an origin, so a URL this transport accepts is a URL the token store
	// can key by.
	Endpoint string
	// Headers are static application-supplied headers, attached to every
	// request. A value may be a credential and is treated as one.
	//
	// They are applied before Auth, so a provider and a static header naming the
	// same field resolve in the provider's favour: the live credential wins over
	// the configured one.
	Headers []auth.Header
	// Auth supplies credential headers per request. Nil means no auth headers.
	//
	// It is consulted on every request rather than once per connection, which is
	// what makes an expiring credential work: a provider that refreshes returns
	// the new value on the next request without the connection noticing.
	Auth auth.HeaderProvider
	// HTTPClient is the client to use. Nil selects a client built from Timeouts
	// with TLS 1.2 as its floor, which is the expected case.
	//
	// A supplied client is vetted, not trusted: New refuses one whose transport
	// disables certificate verification, and the transport is cloned and given a
	// TLS 1.2 floor rather than being used as-is — so this package's guarantees
	// hold for a caller's client too, and the caller's client is not mutated. A
	// non-zero Timeout is refused: it is a deadline on a whole exchange, and it
	// would sever the streams this transport is built on.
	//
	// The default client honors the proxy environment (HTTP_PROXY, HTTPS_PROXY,
	// NO_PROXY), as http.DefaultTransport and pkg/auth do. That is worth knowing
	// for a transport this deliberate about what may see a credential: those
	// variables can route this traffic through a host the endpoint does not
	// name. It stays the default because it is what every Go HTTP client does
	// and operators rely on it, and because the exposure is narrow — an https
	// endpoint stays end-to-end encrypted through a proxy's CONNECT, so the
	// proxy sees the host but not the credential, and loopback is exempt.
	// Supply an HTTPClient whose transport sets Proxy: nil to opt out.
	HTTPClient *http.Client
	// Timeouts bounds the network. Zero fields select their defaults.
	Timeouts Timeouts
}

// Timeouts bounds every wait the HTTP layer performs. Every field is explicit
// and defaulted; none is ever zero in a running transport.
//
// There is deliberately no whole-request deadline for MCP traffic. The obvious
// one — http.Client.Timeout — cancels a response while its body is being read,
// which for this transport means killing the SSE stream a session is listening
// on, and killing a long tool call that is answering exactly as intended. Those
// two are bounded where the knowledge is: ResponseHeader catches a server that
// is not answering, the caller's context bounds the call (which is what the
// client's own Timeouts.Request sets), and Frame catches the case neither of
// those sees — a server that answers, starts a message, and stops.
//
// Between them the bounds cover a request end to end: getting a socket (Dial,
// TLSHandshake), getting an answer (ResponseHeader), getting each message of it
// (Frame), and letting go (Request, IdleConn).
type Timeouts struct {
	// Dial bounds the TCP connect. Zero means DefaultDialTimeout.
	Dial time.Duration
	// TLSHandshake bounds the TLS handshake. Zero means
	// DefaultTLSHandshakeTimeout.
	TLSHandshake time.Duration
	// ResponseHeader bounds the wait for a response's headers, on every
	// request. This is the bound that catches a server which accepts a request
	// and then says nothing — it stops before the body, so it costs a stream
	// nothing. Zero means DefaultResponseHeaderTimeout.
	ResponseHeader time.Duration
	// Frame bounds how long one wire frame may take to arrive, measured from
	// its first byte to its last. Zero means DefaultFrameTimeout.
	//
	// This is the "idle timeout" the transport needs, expressed in the only
	// unit that means anything for a stream that is idle by design. A bound on
	// silence would be wrong: a healthy SSE stream says nothing for hours at a
	// time, and cutting it off for that would break the sessions it is meant to
	// protect. Silence inside a frame the server has already begun is the thing
	// that is never legitimate, and that is what this bounds — see frames.go.
	//
	// It is a completion deadline and not an idle one, deliberately: a deadline
	// that any byte resets is a deadline a server dribbling one byte at a time
	// never trips, which is the attack. A frame that legitimately needs longer
	// than this is a very large frame on a very slow link; raise it.
	Frame time.Duration
	// IdleConn bounds how long a pooled connection is kept alive unused. It is
	// about sockets this transport is not using; for the bound on a server that
	// has gone quiet mid-message, see Frame. Zero means
	// DefaultIdleConnTimeout.
	IdleConn time.Duration
	// Request bounds a whole request that cannot stream — in practice the DELETE
	// that ends the session at Close, which is the one request this transport
	// makes whose response is not, and cannot become, a stream. Zero means
	// DefaultRequestTimeout.
	//
	// It is the bound on how long a server can drag out a shutdown, and that is
	// not only Close's problem: the SDK closes the session itself when a
	// handshake fails, from inside the call, so a cancelled Initialize does not
	// return until the DELETE it triggers has finished or hit this. A server
	// that accepts a DELETE and never answers therefore delays a cancelled
	// caller by up to this long. Lower it if a caller must come back sooner;
	// it cannot be removed, because a DELETE with no bound would hang shutdown
	// outright.
	Request time.Duration
}

// Defaults applied when the corresponding Timeouts field is zero.
const (
	// DefaultDialTimeout bounds the TCP connect.
	DefaultDialTimeout = 10 * time.Second
	// DefaultTLSHandshakeTimeout bounds the TLS handshake.
	DefaultTLSHandshakeTimeout = 10 * time.Second
	// DefaultResponseHeaderTimeout bounds the wait for response headers. It is
	// generous because a legitimate tool call can be slow to start answering,
	// and a server that has said nothing for this long is not going to.
	DefaultResponseHeaderTimeout = 30 * time.Second
	// DefaultFrameTimeout bounds one frame's arrival. It is generous enough for
	// a large result over a poor link — the frame cap is a few mebibytes, and a
	// minute of it is a floor of tens of kilobytes a second — and short enough
	// that a server which has stopped mid-message is noticed the same minute.
	DefaultFrameTimeout = 60 * time.Second
	// DefaultIdleConnTimeout bounds an unused pooled connection.
	DefaultIdleConnTimeout = 90 * time.Second
	// DefaultRequestTimeout bounds a whole non-streaming request — the DELETE
	// that releases the session. It is shorter than the other bounds on
	// purpose: nothing reads the DELETE's answer, a server that has not
	// released a session in this long is not going to, and this is the bound a
	// cancelled caller waits out (see Timeouts.Request), so a generous value
	// here is paid for by the caller who already gave up.
	DefaultRequestTimeout = 10 * time.Second
)

// withDefaults returns a copy with every zero field replaced by its default.
func (t Timeouts) withDefaults() Timeouts {
	pick := func(v, def time.Duration) time.Duration {
		if v == 0 {
			return def
		}
		return v
	}
	return Timeouts{
		Dial:           pick(t.Dial, DefaultDialTimeout),
		TLSHandshake:   pick(t.TLSHandshake, DefaultTLSHandshakeTimeout),
		ResponseHeader: pick(t.ResponseHeader, DefaultResponseHeaderTimeout),
		Frame:          pick(t.Frame, DefaultFrameTimeout),
		IdleConn:       pick(t.IdleConn, DefaultIdleConnTimeout),
		Request:        pick(t.Request, DefaultRequestTimeout),
	}
}

// validate reports the first negative field, naming it. Zero is valid (it means
// "use the default").
func (t Timeouts) validate() error {
	for _, f := range []struct {
		name  string
		value time.Duration
	}{
		{"Timeouts.Dial", t.Dial},
		{"Timeouts.TLSHandshake", t.TLSHandshake},
		{"Timeouts.ResponseHeader", t.ResponseHeader},
		{"Timeouts.Frame", t.Frame},
		{"Timeouts.IdleConn", t.IdleConn},
		{"Timeouts.Request", t.Request},
	} {
		if f.value < 0 {
			return fmt.Errorf("%s: negative duration %v", f.name, f.value)
		}
	}
	return nil
}

// factory is the TransportFactory. It is immutable once New has returned it,
// which is what makes Kind, RedactedOrigin and Connect safe to call
// concurrently.
type factory struct {
	// endpoint is the validated request URL, path and query included.
	endpoint string
	// origin is the precomputed RedactedOrigin: scheme://host[:port] and
	// nothing else. It never depends on anything that could change, so it
	// cannot drift from what was validated.
	origin   string
	headers  []auth.Header
	provider auth.HeaderProvider
	times    Timeouts
	// base is the vetted HTTP transport every connection's client is built on.
	// It is shared: an *http.Transport is a connection pool and is safe for
	// concurrent use, and sharing it is what lets two connections to one server
	// reuse a socket.
	base *http.Transport
}

// New validates cfg and returns a Streamable HTTP TransportFactory.
//
// It fails closed: every violation is a *client.Error of class
// FailureInvalidConfig, and no connection is attempted, no credential is
// fetched and no name is resolved until Connect. Config errors name the
// offending field, and the endpoint's origin — which is not a secret — but
// never a header's value, a query string, or a token, which may be.
func New(cfg Config) (client.TransportFactory, error) {
	fail := func(msg string) error {
		return client.NewError(client.FailureInvalidConfig, "", opNew, msg, nil)
	}

	endpoint, origin, err := resolveEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, fail(err.Error())
	}
	for i, h := range cfg.Headers {
		if err := h.Validate(); err != nil {
			// The auth error already names the header and withholds its value;
			// the index is added because a caller's slice is what it must fix.
			return nil, fail(fmt.Sprintf("Headers[%d]: %s", i, err.Error()))
		}
	}
	if err := cfg.Timeouts.validate(); err != nil {
		return nil, fail(err.Error())
	}
	base, err := vetTransport(cfg.HTTPClient, cfg.Timeouts.withDefaults())
	if err != nil {
		return nil, fail(err.Error())
	}

	return &factory{
		endpoint: endpoint,
		origin:   origin,
		// A detached copy: a Definition is immutable after validation, and a
		// caller that keeps its slice must not be able to rewrite what was
		// validated onto a live request.
		headers:  slices.Clone(cfg.Headers),
		provider: cfg.Auth,
		times:    cfg.Timeouts.withDefaults(),
		base:     base,
	}, nil
}

// resolveEndpoint validates rawURL and splits it into the URL to request and
// the origin to display.
//
// The validation is auth.CanonicalOrigin's, not a second opinion: it is the
// function that decides what an origin is for the token store, and a transport
// that accepted a URL the store cannot key — or refused one it can — would put
// a credential and the server it is for in disagreement about what "the server"
// means. It brings the loopback rule with it, which is the rule that matters:
// cleartext is for a server on this machine, and tokens do not cross a network
// unencrypted.
//
// The request URL keeps its path and query; only the origin is derived. The two
// are separate values because they have separate audiences: one is sent, the
// other is shown.
func resolveEndpoint(rawURL string) (endpoint, origin string, err error) {
	const field = "Endpoint"
	if rawURL == "" {
		return "", "", fmt.Errorf("%s is empty", field)
	}
	origin, err = auth.CanonicalOrigin(rawURL)
	if err != nil {
		// The auth error is already bounded, normalized and secret-free — it is
		// built to be logged — and it never renders its cause. Its text is the
		// message; the URL it describes is not repeated, because a query string
		// is not something to put in an error.
		return "", "", fmt.Errorf("%s is not usable: %s", field, err.Error())
	}
	// Parsed again only to normalize the request URL. CanonicalOrigin has
	// already accepted it, so this cannot fail; the error is checked rather
	// than discarded because "cannot fail" is a claim about today's code.
	u, perr := url.Parse(rawURL)
	if perr != nil {
		return "", "", fmt.Errorf("%s is not a valid URL", field)
	}
	// Rebuilt from the canonical origin rather than reusing the caller's
	// scheme/host spelling: "HTTPS://Example.COM:0443/mcp" and
	// "https://example.com/mcp" must not become two different endpoints when
	// they are one server, and the origin is the spelling the token store uses.
	u.Scheme = ""
	u.Host = ""
	u.User = nil
	u.Fragment = ""
	return origin + u.String(), origin, nil
}

// Kind implements client.TransportFactory.
func (f *factory) Kind() string { return kind }

// RedactedOrigin implements client.TransportFactory. It is the endpoint's
// origin — scheme://host[:port] — and nothing else.
//
// The path and the query are withheld, and that is the whole point rather than
// tidiness: "?access_token=..." is a real thing that appears in real
// configuration, and RedactedOrigin's output is destined for logs. Headers and
// the auth provider are not consulted at all.
func (f *factory) RedactedOrigin() string { return f.origin }

// Connect returns a connection ready to be initialized. It performs no I/O:
// there is no process to start and no socket to open until a request is made,
// and the handshake is Initialize's job — so a server that is unreachable is
// reported by the operation that discovered it rather than by construction.
//
// ctx bounds nothing here for that reason; it is checked so that an already
// cancelled caller does not receive a connection it never asked to keep.
func (f *factory) Connect(ctx context.Context, cfg protocol.ConnectConfig) (protocol.Conn, error) {
	if err := ctx.Err(); err != nil {
		class := client.FailureCancelled
		if errors.Is(err, context.DeadlineExceeded) {
			class = client.FailureStartupTimeout
		}
		return nil, client.NewError(class, "", opConnect,
			"the streamable HTTP transport was not connected", err)
	}

	// Per connection, not per factory: diags is where a failure's cause is
	// recorded on its way past, and two connections must not read each other's.
	d := &diagnostics{}
	c := &conn{diags: d, endpoint: f.endpoint, origin: f.origin}
	c.session = protocol.NewSession(&mcp.StreamableClientTransport{
		Endpoint:   f.endpoint,
		HTTPClient: f.httpClient(d, newWireLimits(cfg.Wire)),
		MaxRetries: streamReconnects,
		// OAuthHandler is deliberately left nil, and this is load-bearing: it is
		// the SDK's only path that re-sends a POST, and a re-sent POST is a
		// re-run tool call. Credentials reach a request through the RoundTripper
		// instead — see the package comment.
	}, cfg)
	return c, nil
}

// httpClient builds the client for one connection: the shared, vetted transport
// underneath, wrapped in this connection's own RoundTripper.
//
// The wrapper is per-connection because what it carries is: the credentials for
// this binding, and the diagnostics buffer this connection's errors are
// classified from. The pool underneath is shared, so the wrapping costs a
// struct and not a socket.
func (f *factory) httpClient(d *diagnostics, w wireLimits) *http.Client {
	return &http.Client{
		// No Timeout, by design: see Timeouts. The bounds live on the transport
		// underneath and in the RoundTripper, where a stream can be told apart
		// from an exchange.
		CheckRedirect: f.checkRedirect,
		Transport: &roundTripper{
			base:     f.base,
			headers:  f.headers,
			provider: f.provider,
			wire:     w,
			request:  f.times.Request,
			frame:    f.times.Frame,
			diags:    d,
		},
	}
}

// maxRedirects bounds a redirect chain. Even a same-origin chain is bounded: a
// server that bounces a request between two of its own paths forever is a hang,
// and a hang is what every bound in this package exists to prevent.
const maxRedirects = 5

// checkRedirect refuses any redirect that leaves the configured origin.
//
// This is not a hardening nicety; without it this transport is strictly worse
// than the http.Client it wraps. The stdlib strips Authorization when a redirect
// crosses origins — and then this package's RoundTripper, which runs *below*
// that logic and attaches credentials to every request it sees, puts it back. A
// 302 from a configured endpoint to an attacker's host would hand over the
// bearer token, in cleartext if the redirect said http. A test proves both
// halves, because the failure is invisible from the happy path.
//
// The policy is origin-pinning, and it is deliberately stricter than the
// scheme check pkg/auth's defaultHTTPClient applies to its own flows:
//
//   - An MCP endpoint is configuration. The caller named one server; a server
//     that answers "I am actually over there" is not a redirect to follow, it is
//     a different server, and only the caller can decide to talk to it.
//   - The credential is keyed by origin. auth.Key binds a token to the origin it
//     was minted for, so sending it to another origin is incoherent by
//     construction — whatever the scheme, whatever the trust.
//   - Allowing cross-origin https "because TLS" would still send a token for
//     server A to server B. The scheme is not what makes that wrong.
//
// So same-origin redirects pass — "/mcp" to "/mcp/" is an ordinary thing for a
// server to do, and the credential is not going anywhere new — and everything
// else is refused. Refusing costs a caller nothing but an explicit config
// change, which is the point: it makes the move deliberate.
//
// Canonicalization is auth.CanonicalOrigin, the same function New validated the
// endpoint with, which is what makes config time and run time agree. A hop to a
// non-loopback http host does not need its own check: it fails to match the
// origin, and would fail CanonicalOrigin too.
func (f *factory) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	origin, err := auth.CanonicalOrigin(req.URL.String())
	if err != nil {
		// The URL is not repeated: a redirect target is server-controlled and a
		// query string is a place tokens live. The auth error is already
		// bounded, normalized and secret-free.
		return fmt.Errorf("refusing a redirect to an unusable URL: %s", err.Error())
	}
	if origin != f.origin {
		// Origins are not secret and naming both is the whole diagnostic.
		return fmt.Errorf("refusing a redirect from %s to %s: an MCP endpoint's origin is configuration, "+
			"and a credential minted for one origin is never sent to another", f.origin, origin)
	}
	return nil
}

// conn is one MCP session over Streamable HTTP.
//
// It is thin, and it is thin on purpose: the SDK's transport owns the session
// ID, the streams and the DELETE, so there is nothing here to hold but the
// session and the record of what went wrong underneath it.
type conn struct {
	session *protocol.Session
	diags   *diagnostics
	// endpoint and origin are held only so that cause can keep the request URL
	// out of an error message. They are the factory's, unchanged.
	endpoint string
	origin   string
}

// Initialize performs the MCP handshake.
func (c *conn) Initialize(ctx context.Context) (protocol.InitializeResult, error) {
	res, err := c.session.Initialize(ctx)
	if err != nil {
		return protocol.InitializeResult{}, c.classify(ctx, opInitialize, err)
	}
	return res, nil
}

// The catalog list methods. Each is a straight delegation to the session, with
// the transport's own classification applied to a failure: only this layer can
// tell "the server spoke badly" from "the remote server is gone", and a list that
// fails during discovery must be classified the same way a handshake would be.
//
// The four are generated through listVia rather than written out because they
// differ only in the method they call — and a hand-written fourth copy is where
// the classification would eventually go missing.

// ListTools fetches one page of tools.
func (c *conn) ListTools(ctx context.Context, cursor string) (protocol.ToolPage, error) {
	return listVia(ctx, c, opListTools, cursor, c.session.ListTools)
}

// ListPrompts fetches one page of prompts.
func (c *conn) ListPrompts(ctx context.Context, cursor string) (protocol.PromptPage, error) {
	return listVia(ctx, c, opListPrompts, cursor, c.session.ListPrompts)
}

// ListResources fetches one page of resources.
func (c *conn) ListResources(ctx context.Context, cursor string) (protocol.ResourcePage, error) {
	return listVia(ctx, c, opListResources, cursor, c.session.ListResources)
}

// ListResourceTemplates fetches one page of resource templates.
func (c *conn) ListResourceTemplates(ctx context.Context, cursor string) (protocol.ResourceTemplatePage, error) {
	return listVia(ctx, c, opListResourceTemplates, cursor, c.session.ListResourceTemplates)
}

// listVia runs one list method and classifies its failure. The page type is the
// only thing that varies, so it is the only type parameter.
func listVia[P any](
	ctx context.Context,
	c *conn,
	op string,
	cursor string,
	fetch func(context.Context, string) (P, error),
) (P, error) {
	page, err := fetch(ctx, cursor)
	if err != nil {
		var zero P
		return zero, c.classify(ctx, op, err)
	}
	return page, nil
}

// Close ends the session. The SDK's close drains the conversation and then
// issues the DELETE that releases the server's session state.
//
// It is idempotent, via Session. A server that has already forgotten the session
// is not a close failure: there is nothing left to release, which is what Close
// is for.
func (c *conn) Close(ctx context.Context) error {
	if err := c.session.Close(ctx); err != nil {
		return client.NewError(client.FailureTransportClosed, "", opClose,
			"the streamable HTTP session could not be closed", err)
	}
	return nil
}

// classify turns a session failure into a typed error.
//
// The order is a hierarchy of causes, most specific first, because the SDK
// reports very different things identically — "the connection failed" covers a
// refused credential, a 500, an oversized body and a cancelled caller alike.
// The specific causes come from diagnostics, which recorded them at the point
// they happened; the SDK's error text is only the symptom, and much of it is
// flattened with %v on the way up, so the cause is not reliably in the chain by
// the time it arrives here.
//
// The caller's own context is read first: a cancelled caller is a cancellation,
// whatever the read that noticed it returned.
func (c *conn) classify(ctx context.Context, op string, err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return client.NewError(client.FailureCancelled, "", op,
			"the streamable HTTP transport was cancelled", err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return client.NewError(client.FailureStartupTimeout, "", op,
			"the streamable HTTP server did not answer in time", err)
	}

	// An auth failure, from the provider or from the chain. The message is
	// always this package's own text plus the auth error's class: an auth
	// error's cause routinely quotes a URL or a header, and client.Error renders
	// a wrapped cause verbatim when no explicit message is given.
	if aerr := c.diags.authError(); aerr != nil {
		return client.NewError(authClass(aerr), "", op, authMessage(aerr), aerr)
	}
	var aerr *auth.Error
	if errors.As(err, &aerr) {
		return client.NewError(authClass(aerr), "", op, authMessage(aerr), err)
	}

	// A bound this transport enforced. It is reported ahead of the HTTP status
	// because a 200 that overruns the limit is the limit's verdict, not the
	// status's.
	if lerr := c.diags.limitError(); lerr != nil {
		return client.NewError(client.FailureLimitExceeded, "", op,
			"the streamable HTTP server's response exceeded a limit: "+lerr.Error(), lerr)
	}

	// A server that started a message and stopped. It is reported ahead of the
	// status for the reason the limit is: whatever the response line said, the
	// stream is what ended the session.
	if serr := c.diags.stallError(); serr != nil {
		return client.NewError(client.FailureServerProtocol, "", op,
			"the streamable HTTP server stalled mid-frame: "+serr.Error(), serr)
	}

	if status, ok := c.diags.status(); ok {
		return client.NewError(statusClass(status), "", op,
			fmt.Sprintf("the streamable HTTP server answered %d %s",
				status, http.StatusText(status)), err)
	}

	// Nothing was recorded: the request never got far enough to have a status,
	// or the session broke on something the server said rather than on the
	// transport underneath it. Either way this is not a class this package can
	// name more precisely without guessing.
	return client.NewError(client.FailureServerProtocol, "", op, c.cause(err), err)
}

// cause renders err for a client.Error's message, with the request URL kept out
// of it.
//
// Its existence is not tidiness. client.Error renders its wrapped cause verbatim
// when no explicit message is given, and every network failure this transport
// can suffer arrives wrapped in a *url.Error — whose text quotes the request
// URL, whose query is a place people put access tokens. Leaving the message
// empty therefore prints the credential, which a test here proves.
//
// So the message is never the chain's text. It is built from the one part of it
// that is URL-free by construction: url.Error's inner Err, which holds the
// actual fault ("connection refused") without the URL its parent formats in.
// The endpoint is then scrubbed anyway, because "by construction" is a claim
// about the stdlib's formatting that this package would rather not bet a
// credential on. An unrecognized error contributes no text at all — the class
// and the operation still say what happened, and the cause stays reachable
// through errors.Is and errors.As for a caller that wants to inspect it.
func (c *conn) cause(err error) string {
	var uerr *url.Error
	if !errors.As(err, &uerr) || uerr.Err == nil {
		return "the streamable HTTP request failed"
	}
	text := uerr.Err.Error()
	if text == "" {
		return "the streamable HTTP request failed"
	}
	// Belt and braces: if the URL appears anyway, it becomes the origin, which
	// is what RedactedOrigin would have said.
	text = strings.ReplaceAll(text, c.endpoint, c.origin)
	return "the streamable HTTP request failed: " + text
}

// authClass maps an auth failure onto the client taxonomy. The mapping is the
// fixed 1:1 one documented in pkg/auth/errors.go — that package is a leaf and
// must not import pkg/client, so a transport is where the translation lives.
//
// An unknown class maps to FailureAuthFailed rather than to something more
// specific: a class this code does not recognize is an auth failure whose nature
// it cannot state, and inventing a nature for it would be a fail-open.
func authClass(err *auth.Error) client.FailureClass {
	switch err.Class {
	case auth.ClassInvalidConfig:
		return client.FailureInvalidConfig
	case auth.ClassNoToken, auth.ClassRequired:
		return client.FailureAuthRequired
	case auth.ClassDenied:
		return client.FailureAuthDenied
	case auth.ClassExpired:
		return client.FailureAuthExpired
	default:
		return client.FailureAuthFailed
	}
}

// authMessage renders an auth failure for a client.Error's message.
//
// It uses the auth error's own text, which is safe by construction: pkg/auth
// bounds and normalizes it, refuses to render its cause, and documents that its
// Msg is secret-free. What must not happen is leaving the message empty and
// letting client.Error substitute the wrapped chain, which is not any of those
// things.
func authMessage(err *auth.Error) string {
	text, _ := limits.TruncateText(err.Error(), auth.MaxMessageBytes)
	return text
}

// statusClass maps an HTTP status onto the client taxonomy.
//
// 401 and 403 become auth classes because that is what they mean, and because a
// caller deciding whether to start a login should not have to parse a number out
// of a string. 401 is Required rather than Expired: the distinction is whether a
// credential was sent and has aged out, which is the provider's knowledge and
// not the status line's — an OAuthProvider that refreshed and still got 401
// reports Expired itself, through the path above.
//
// Everything else is the remote's HTTP behavior, which is one class: a 404, a
// 429 and a 500 differ in what to do about them, not in what they are, and the
// status is in the message for the caller that cares.
func statusClass(status int) client.FailureClass {
	switch status {
	case http.StatusUnauthorized:
		return client.FailureAuthRequired
	case http.StatusForbidden:
		return client.FailureAuthDenied
	default:
		return client.FailureRemoteHTTP
	}
}
