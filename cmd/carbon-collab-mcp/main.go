// Command carbon-collab-mcp exposes CodeRig's one loop-scoped collaboration
// operation over MCP stdio. Its broker endpoint and bearer capability arrive
// only through fixed environment entries; command-line arguments are ignored.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/looprig/mcp/pkg/collab"
	"github.com/looprig/mcp/pkg/server"
)

var errConfiguration = errors.New("invalid collaboration configuration")

const messageAgentSchema = `{"type":"object","additionalProperties":false,"properties":{"agent_id":{"type":"string"},"message":{"type":"string"},"wait_for_response":{"type":"boolean","default":true},"timeout_seconds":{"type":"integer","minimum":0,"maximum":86400}},"required":["agent_id","message"]}`

// newCollaborationServer builds the complete public MCP surface. The returned
// server contains exactly one tool and no resources, prompts, sampling, or
// elicitation capability.
func newCollaborationServer(cfg collab.ClientConfig) (*server.Server, error) {
	client, err := collab.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	mcpServer, err := server.New(server.Config{
		Name:    server.DefaultServerName,
		Version: server.DefaultServerVersion,
	})
	if err != nil {
		return nil, err
	}
	if err := mcpServer.RegisterTool(server.Tool{
		Name:        collab.ToolName,
		Description: "Send a message to an existing child agent.",
		InputSchema: json.RawMessage(messageAgentSchema),
		Handler: func(ctx context.Context, args json.RawMessage) (server.Result, error) {
			request, err := collab.DecodeMessageAgent(args)
			if err != nil {
				return server.Result{}, server.ErrInvalidArgument
			}
			response, err := client.CallJSON(ctx, request)
			if err != nil {
				// The process boundary deliberately collapses transport/auth/
				// broker failures to a generic internal error. In particular,
				// endpoint and capability diagnostics never reach the model.
				return server.Result{}, server.ErrInternal
			}
			return server.Result{
				Content:           []server.Content{{Text: string(response)}},
				StructuredContent: response,
			}, nil
		},
	}); err != nil {
		return nil, err
	}
	return mcpServer, nil
}

// Run serves the one-tool proxy over the supplied stdio-shaped streams.
// Configuration is read from the two fixed environment entries.
func Run(ctx context.Context, reader io.Reader, writer io.Writer) error {
	return run(ctx, reader, writer, os.LookupEnv)
}

func run(ctx context.Context, reader io.Reader, writer io.Writer, lookup func(string) (string, bool)) error {
	cfg, err := collab.ConfigFromEnv(lookup)
	if err != nil {
		return errConfiguration
	}
	mcpServer, err := newCollaborationServer(cfg)
	if err != nil {
		return err
	}
	return mcpServer.ServeStdio(ctx, reader, writer)
}

func main() {
	if err := Run(context.Background(), os.Stdin, os.Stdout); err != nil {
		// All package-level failures are already categorical and secret-free;
		// keep the process diagnostic equally bounded and avoid printing any
		// endpoint or capability supplied by the environment.
		_, _ = fmt.Fprintln(os.Stderr, "carbon-collab-mcp: server failed")
	}
}
