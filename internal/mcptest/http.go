// This file is the fixture's HTTP mode: the same server, over Streamable HTTP
// or over the legacy HTTP+SSE transport, instead of over a child process's
// pipes.
//
// It is an http.Handler and not a command, and the asymmetry with the stdio
// mode is the point rather than an oversight. Stdio is a process boundary, so
// testing it needs a real process — hence cmd/fixture and the build helper.
// HTTP is a socket, and httptest.NewServer already provides one in-process; a
// subprocess would add a port to allocate, a readiness race to lose, and a
// child to leak, in exchange for nothing. The transport under test still speaks
// real HTTP to a real SDK server, which is what makes this a fixture rather
// than a mock.

package mcptest

import (
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NewHTTPHandler builds a configured fixture server and returns it as an
// http.Handler speaking the Streamable HTTP transport. Mount it on an
// httptest.Server and point a client at that server's URL.
//
// Every session the handler serves gets the same *mcp.Server, which is what the
// SDK's getServer hook is for and what a real deployment does. It matters for
// Config.Mutate: mutation changes the server's tool list, so two sessions on one
// handler see each other's mutations — as they would against a real server.
//
// The Config fields that describe a process rather than a server have no meaning
// here, and NewHTTPHandler refuses them rather than ignoring them:
//
//   - Crash exits the process, which over HTTP would take the test binary down
//     with it, not a child.
//   - NoiseBytes writes to stderr, which is this process's stderr; there is no
//     child stream for it to pollute and no bounded capture reading it.
//
// A test that wants those wants the stdio fixture, which has a process to
// crash.
func NewHTTPHandler(cfg Config) (http.Handler, error) {
	s, err := newHTTPServer(cfg)
	if err != nil {
		return nil, err
	}
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil), nil
}

// NewSSEHandler builds a configured fixture server and returns it as an
// http.Handler speaking the *legacy* HTTP+SSE transport (the 2024-11-05 spec's).
// Mount it on an httptest.Server and point pkg/transport/sse at that server's
// URL.
//
// It exists because a compatibility transport tested against a fixture that
// cannot do the thing proves nothing. The legacy protocol's whole shape — the
// hanging GET, the "endpoint" event that tells the client where to POST, the
// POSTs going somewhere other than where the stream came from — is the part
// worth testing, and only a real legacy server has it. This is the SDK's own
// SSE server, so what the transport is tested against is the protocol rather
// than this module's idea of it.
//
// It shares NewHTTPHandler's restrictions, for the same reasons.
func NewSSEHandler(cfg Config) (http.Handler, error) {
	s, err := newHTTPServer(cfg)
	if err != nil {
		return nil, err
	}
	return mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return s }, nil), nil
}

// newHTTPServer builds the fixture server both HTTP modes serve, refusing the
// Config fields that describe a process rather than a server.
func newHTTPServer(cfg Config) (*mcp.Server, error) {
	if cfg.Crash {
		return nil, fmt.Errorf("mcptest: Config.Crash is not supported over HTTP: " +
			"the crash tool exits the process, which here is the test binary; use the stdio fixture")
	}
	if cfg.NoiseBytes != 0 {
		return nil, fmt.Errorf("mcptest: Config.NoiseBytes is not supported over HTTP: " +
			"the noise goes to this process's stderr, where nothing is reading it; use the stdio fixture")
	}
	return NewServer(cfg)
}
