// Package protocol is the module-internal boundary between transports and the
// client. It is the only package (besides pkg/transport/*) allowed to import
// the MCP go-sdk. This stub is expanded by a later task.
package protocol

import "context"

// Conn is an established connection to an MCP server. Expanded by a later
// task.
type Conn interface {
	Close(ctx context.Context) error
}

// ConnectConfig carries client-side connection parameters a transport needs.
// Expanded by a later task.
type ConnectConfig struct{}
