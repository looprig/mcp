// This file is the fixture's mechanism for pinning a server session to a
// protocol revision older than 2026-07-28.
//
// SDK v1.7.0 has no public API to request an older protocol version from a
// test peer: [mcp.ClientSessionOptions] carries a protocolVersion field for
// exactly this, but it is unexported. And the SDK's own client always tries
// the SEP-2575 "server/discover" RPC first when it wants 2026-07-28 (which is
// always, by default) — succeeding at discover is what negotiates 2026-07-28,
// so there is no session to pin an older version onto after the fact. That is
// why every one of this module's stdio and in-memory tests began negotiating
// 2026-07-28 the moment the SDK bumped its own default, and why
// ServerSession's assertServerInitiatedRequestAllowed (vendor mcp/server.go)
// then refuses every ad hoc ServerSession.Elicit / ListRoots / CreateMessage
// call a test makes against it.
//
// PinLegacyProtocol closes that gap by making discover fail the way a real
// pre-SEP-2575 server would: "method not found". It does this at the
// connection layer, intercepting the request before it ever reaches
// [mcp.Server]'s own discover handler — that handler unconditionally records
// the session as initialized as a side effect of merely being called (see its
// doc in vendor mcp/server.go), which would make the legacy "initialize" that
// follows fail as a duplicate if discover were allowed to run and only
// *afterward* rejected (e.g. by restricting [mcp.ProtocolVersionSupporter],
// which was tried and hits exactly this). A discover that never reaches the
// server touches no state, so the client's documented fallback — the legacy
// initialize handshake, which the SDK negotiates at exactly
// LegacyProtocolVersion — runs clean.
package mcptest

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// LegacyProtocolVersion is the protocol revision a server connected through
// [PinLegacyProtocol] negotiates. It is the newest revision before 2026-07-28
// (SEP-2322 / SEP-2575) — the last one under which a server may still call
// ServerSession.Elicit, ServerSession.ListRoots, or ServerSession.CreateMessage
// ad hoc, rather than returning InputRequests from a multi round-trip handler.
// It is also the version the SDK's client hardcodes for its legacy-initialize
// fallback (see client.go's Connect), which is what makes it the outcome here
// rather than merely the intent.
const LegacyProtocolVersion = "2025-11-25"

// methodDiscover is the SEP-2575 "server/discover" RPC's method name. It is
// duplicated here because the SDK does not export it.
const methodDiscover = "server/discover"

// PinLegacyProtocol wraps t so a server connected over it refuses
// "server/discover" with "method not found", which is indistinguishable to
// the SDK's client from a genuine pre-2026-07-28 server and sends it down the
// legacy initialize path. See the package doc comment above for the reasoning
// and what it does to a client that connects through it.
func PinLegacyProtocol(t mcp.Transport) mcp.Transport {
	return legacyProtocolTransport{t}
}

// legacyProtocolTransport wraps the Connection it hands back from Connect,
// leaving everything else about t untouched.
type legacyProtocolTransport struct {
	underlying mcp.Transport
}

func (t legacyProtocolTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.underlying.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &legacyProtocolConnection{Connection: conn}, nil
}

// legacyProtocolConnection intercepts an incoming "server/discover" request on
// Read, answers it inline with "method not found", and continues reading
// rather than handing it to the caller — which is what keeps it from ever
// reaching Server.discover. Every other message passes through unchanged.
type legacyProtocolConnection struct {
	mcp.Connection
}

func (c *legacyProtocolConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	for {
		msg, err := c.Connection.Read(ctx)
		if err != nil {
			return nil, err
		}
		req, ok := msg.(*jsonrpc.Request)
		if !ok || req.Method != methodDiscover {
			return msg, nil
		}
		resp := &jsonrpc.Response{
			ID: req.ID,
			Error: &jsonrpc.Error{
				Code:    jsonrpc.CodeMethodNotFound,
				Message: "server/discover is not supported (mcptest.PinLegacyProtocol)",
			},
		}
		if err := c.Connection.Write(ctx, resp); err != nil {
			return nil, err
		}
		// Loop rather than return: this message was answered here, and the
		// caller is still owed the next one.
	}
}
