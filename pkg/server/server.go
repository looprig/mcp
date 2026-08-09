// Package server provides the small MCP server surface used by CodeRig's
// injected collaboration process.
//
// The package deliberately keeps the SDK behind this boundary. Callers
// register CodeRig-owned tools and handlers, while the package owns MCP
// framing, capability advertisement, bounds, and wire-error classification.
package server

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The default identity is intentionally explicit: an empty SDK implementation
// would otherwise produce an invalid peer identity on the wire.
const (
	DefaultServerName    = "coderig-collab-mcp"
	DefaultServerVersion = "0.1.0"

	// DefaultMaxInputBytes bounds one tools/call arguments value before the
	// application handler is invoked.
	DefaultMaxInputBytes = 256 << 10
	// DefaultMaxOutputBytes bounds a handler's structured result and encoded
	// content before the SDK is allowed to serialize it.
	DefaultMaxOutputBytes = 256 << 10
	// MaxFrameOverheadBytes is reserved for the JSON-RPC/MCP envelope around a
	// bounded argument or result. It is part of the frame policy, not an
	// allowance for application payloads.
	MaxFrameOverheadBytes = 4 << 10
	// MaxRequestIDBytes bounds the encoded JSON-RPC request ID (including JSON
	// quotes for a string). The ID is echoed into every response, so this bound
	// is reserved from the frame overhead rather than allowed to consume
	// application payload capacity.
	MaxRequestIDBytes = MaxFrameOverheadBytes - 512
	// DefaultMaxMessageBytes bounds one newline-delimited MCP frame's JSON
	// bytes. The final '\n' delimiter is excluded from this count. The default
	// is deliberately larger than the maximum argument/result plus the
	// envelope, so a handler-valid boundary value cannot fail at transport.
	DefaultMaxMessageBytes = DefaultMaxOutputBytes + MaxFrameOverheadBytes
)

// These aliases make the policy easy to discover without creating a second
// set of values. They are hard bounds in the default configuration; callers
// may choose a smaller bound in Config.
const (
	MaxMessageBytes = DefaultMaxMessageBytes
	MaxInputBytes   = DefaultMaxInputBytes
	MaxOutputBytes  = DefaultMaxOutputBytes
)

const (
	invalidArgumentMessage = "invalid arguments"
	internalErrorMessage   = "internal error"
)

var (
	// ErrInvalidArgument classifies a handler failure as an MCP invalid-params
	// error. Its text is never sent to a peer, so wrapping it cannot disclose a
	// handler's detail.
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrInternal classifies a handler failure as an MCP internal error.
	ErrInternal = errors.New("internal error")

	// ErrInvalidToolName means a tool name is empty, too long, or contains a
	// character outside the MCP tool-name alphabet.
	ErrInvalidToolName = errors.New("invalid tool name")
	// ErrDuplicateTool means a tool name has already been registered.
	ErrDuplicateTool = errors.New("duplicate tool")
	// ErrInvalidToolSchema means the supplied input or output schema is not a
	// valid JSON object/schema accepted by the MCP SDK.
	ErrInvalidToolSchema = errors.New("invalid tool schema")
	// ErrInvalidConfig means a server bound was configured with a non-positive
	// value or its identity was invalid.
	ErrInvalidConfig = errors.New("invalid server configuration")

	// ErrInputLimit and ErrOutputLimit are returned by the framing seams when a
	// frame or result exceeds the configured bound.
	ErrInputLimit  = errors.New("input exceeds limit")
	ErrOutputLimit = errors.New("output exceeds limit")
	// ErrInputEnvelope is returned when a peer-controlled field that is echoed
	// in a response (currently the JSON-RPC request ID) exceeds its bound.
	ErrInputEnvelope = errors.New("input envelope exceeds limit")
)

// Config configures a Server. Zero identity fields and bounds select the
// explicit package defaults. Every running server therefore has a non-empty
// name, version, and finite input/output bound.
type Config struct {
	Name    string
	Version string

	// MaxMessageBytes bounds each newline-delimited JSON-RPC message.
	MaxMessageBytes int
	// MaxInputBytes bounds tools/call arguments before a Handler is called.
	MaxInputBytes int
	// MaxOutputBytes bounds the encoded tools/call result produced by a
	// Handler.
	MaxOutputBytes int
}

// ServerConfig is a descriptive alias for Config.
type ServerConfig = Config

func (c Config) normalized() (Config, error) {
	if strings.TrimSpace(c.Name) == "" {
		c.Name = DefaultServerName
	}
	if strings.TrimSpace(c.Version) == "" {
		c.Version = DefaultServerVersion
	}
	if c.MaxMessageBytes == 0 {
		c.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if c.MaxInputBytes == 0 {
		c.MaxInputBytes = DefaultMaxInputBytes
	}
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if strings.TrimSpace(c.Name) == "" || strings.TrimSpace(c.Version) == "" ||
		c.MaxMessageBytes < 1 || c.MaxInputBytes < 1 || c.MaxOutputBytes < 1 ||
		c.MaxMessageBytes > DefaultMaxMessageBytes ||
		c.MaxInputBytes > DefaultMaxInputBytes ||
		c.MaxOutputBytes > DefaultMaxOutputBytes ||
		c.MaxMessageBytes < maxInt(c.MaxInputBytes, c.MaxOutputBytes)+MaxFrameOverheadBytes {
		return Config{}, ErrInvalidConfig
	}
	return c, nil
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

// Server is a reusable, one-session MCP server. It is safe to register tools
// before Serve is called; each tool name can be registered at most once.
type Server struct {
	mu    sync.Mutex
	cfg   Config
	sdk   *mcp.Server
	tools map[string]struct{}
}

// New constructs a server with explicit identity, tools-only capabilities, and
// bounded framing. It does not start I/O.
func New(cfg Config) (*Server, error) {
	normalized, err := cfg.normalized()
	if err != nil {
		return nil, err
	}

	// A non-nil capabilities value disables the SDK's historical default
	// logging capability. The empty ToolsCapabilities value suppresses
	// list-changed notifications while still advertising tools once one exists.
	sdk := mcp.NewServer(
		&mcp.Implementation{Name: normalized.Name, Version: normalized.Version},
		&mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolCapabilities{},
		}},
	)
	return &Server{cfg: normalized, sdk: sdk, tools: make(map[string]struct{})}, nil
}

// NewServer is an explicit-name alias for New.
func NewServer(cfg Config) (*Server, error) { return New(cfg) }

// Config returns the immutable normalized policy used by s.
func (s *Server) Config() Config {
	if s == nil {
		return Config{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// RegisterTool adds one tool. Duplicate and invalid names are returned as
// typed sentinel errors; the underlying SDK's replacing AddTool behavior is
// intentionally not exposed.
func (s *Server) RegisterTool(tool Tool) error {
	if s == nil {
		return ErrInvalidConfig
	}
	normalized, err := normalizeTool(tool)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tools[normalized.Name]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateTool, normalized.Name)
	}

	sdkTool := &mcp.Tool{
		Name:         normalized.Name,
		Title:        normalized.Title,
		Description:  normalized.Description,
		InputSchema:  normalized.InputSchema,
		OutputSchema: normalized.OutputSchema,
	}
	// normalizeTool mirrors the SDK's panic-producing schema checks, so this
	// call cannot panic for caller-controlled definitions.
	s.sdk.AddTool(sdkTool, s.handler(normalized.Handler))
	s.tools[normalized.Name] = struct{}{}
	return nil
}

// AddTool is an alias for RegisterTool for callers familiar with the SDK's
// terminology.
func (s *Server) AddTool(tool Tool) error { return s.RegisterTool(tool) }

// Register is a concise alias for RegisterTool.
func (s *Server) Register(tool Tool) error { return s.RegisterTool(tool) }
