package serverwire

// These aliases keep SDK interoperability tests behind the single adapter
// import boundary; production packages never import the SDK directly.
import (
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Client = mcp.Client
type ClientSession = mcp.ClientSession
type Implementation = mcp.Implementation
type IOTransport = mcp.IOTransport
type CallToolParams = mcp.CallToolParams
type TextContent = mcp.TextContent
type ToolResult = mcp.CallToolResult
type JSONRPCError = jsonrpc.Error

const (
	CodeInvalidParams = jsonrpc.CodeInvalidParams
	CodeInternalError = jsonrpc.CodeInternalError
)

var NewClient = mcp.NewClient
