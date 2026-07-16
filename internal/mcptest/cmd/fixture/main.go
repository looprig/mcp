// Command fixture runs the mcptest fixture MCP server over stdio.
//
// It exists to be built by mcptest.BuildFixture and exec'd by this module's
// transport tests. It is not shipped, and nothing outside internal/ runs it.
//
// Usage:
//
//	fixture [flags]
//
// Flags (all off or empty by default — the bare command is a minimal server
// with the echo/slow/fail/big tools and nothing else):
//
//	-instructions string   server instructions returned at initialize
//	-prompts               expose the "greet" prompt
//	-resources             expose the static resource and the echo template
//	-mutate                expose the "mutate" tool (triggers tools/list_changed)
//	-crash                 expose the "crash" tool (exits immediately)
//	-crash-exit-code int   the status "crash" exits with (default 7)
//	-noise-bytes int       bytes of chatter to write to stderr at startup
//	-elicit-on-initialize  send an elicitation request once the client is initialized
//
// stdin and stdout are the MCP transport and carry nothing else. Diagnostics
// go to stderr.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/looprig/mcp/internal/mcptest"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// exitUsage is the status for a bad invocation, distinct from any status the
// crash tool can be configured with and from a normal serving failure.
const exitUsage = 2

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fixture: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := parseFlags()

	// Validate before anything is written or served: a bad flag must fail here,
	// not as a protocol error after the client has connected.
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "fixture: %v\n", err)
		os.Exit(exitUsage)
	}

	if err := mcptest.WriteNoise(os.Stderr, cfg.NoiseBytes); err != nil {
		return err
	}

	server, err := mcptest.NewServer(cfg)
	if err != nil {
		return err
	}

	// SIGINT/SIGTERM cancel the run so the session closes cleanly. The client
	// normally shuts us down by closing stdin instead, which ends Run on its
	// own; this is for the case where it does not.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		// A cancelled context is how a signalled shutdown ends. It is not a
		// failure, and reporting it as one would make every test that
		// terminates the fixture look like a broken fixture.
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("serving: %w", err)
	}
	return nil
}

// parseFlags builds the Config from the command line. It is a function so the
// flag set stays in one place next to the doc comment above.
func parseFlags() mcptest.Config {
	var cfg mcptest.Config
	flag.StringVar(&cfg.Instructions, "instructions", "", "server instructions returned at initialize")
	flag.BoolVar(&cfg.Prompts, "prompts", false, "expose the greet prompt")
	flag.BoolVar(&cfg.Resources, "resources", false, "expose the static resource and the echo resource template")
	flag.BoolVar(&cfg.Mutate, "mutate", false, "expose the mutate tool, which triggers tools/list_changed")
	flag.BoolVar(&cfg.Crash, "crash", false, "expose the crash tool, which exits the process immediately")
	flag.IntVar(&cfg.CrashExitCode, "crash-exit-code", mcptest.DefaultCrashExitCode, "exit status for the crash tool")
	flag.IntVar(&cfg.NoiseBytes, "noise-bytes", 0, "bytes of chatter to write to stderr at startup")
	flag.BoolVar(&cfg.ElicitOnInitialize, "elicit-on-initialize", false, "send an elicitation request once the client reports initialized")
	flag.Parse()
	return cfg
}
