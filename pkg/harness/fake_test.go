// Test doubles shared by the adapter tests. They live in package mcpharness
// (not mcpharness_test) because fakeTransport implements client.TransportFactory,
// whose Connect signature names internal/protocol types — a sealed,
// module-internal boundary.

package mcpharness

import (
	"context"
	"fmt"

	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/client"
)

// fakeTransport is a client.TransportFactory that is never dialed. It exists so
// a test can build a structurally valid client.Definition without a server: the
// binding tests are about configuration rules, and a real connection would only
// add a subprocess to the failure surface of a validation table.
type fakeTransport struct {
	kind   string
	origin string
}

func (f fakeTransport) Kind() string {
	if f.kind == "" {
		return "fake"
	}
	return f.kind
}

func (f fakeTransport) RedactedOrigin() string {
	if f.origin == "" {
		return "fake://test"
	}
	return f.origin
}

func (fakeTransport) Connect(context.Context, protocol.ConnectConfig) (protocol.Conn, error) {
	return nil, fmt.Errorf("fakeTransport: Connect is not implemented; this factory is never dialed")
}

// testDefinition returns a minimal client.Definition that passes
// Definition.Validate, mounted under name.
func testDefinition(name string) client.Definition {
	return client.Definition{
		Name:      client.Name(name),
		Transport: fakeTransport{},
	}
}
