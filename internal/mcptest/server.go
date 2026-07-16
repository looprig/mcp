// Package mcptest provides a real MCP server for driving this module's
// transports in tests.
//
// It is a fixture, not a mock: the server here is built on the go-sdk's server
// API and speaks the real protocol over a real transport. A hand-rolled
// JSON-RPC stub would test our idea of MCP; this tests MCP.
//
// The package is a test fixture that happens to be compiled as ordinary code,
// because cmd/fixture must build it into a binary that tests exec. Nothing in
// production imports it, and nothing here is part of any consumer contract —
// so unlike the rest of the module below internal/protocol, it may name SDK
// types freely (see internal/protocol's leak guard allowlist).
//
// # Configuration
//
// Everything is driven by Config, which cmd/fixture parses from flags. Each
// server feature is off unless a flag turns it on, so a test opts into exactly
// the surface it means to exercise and nothing else can surprise it.
//
// # Mutation and the list-changed notification
//
// The server can add and remove a tool at runtime, which makes the SDK emit
// notifications/tools/list_changed. The trigger is the "mutate" tool: the
// client that wants the notification asks for it, in-band, over the same
// connection it is already testing. The alternatives are worse — stdin is the
// transport and cannot carry a control channel, a signal needs the test to know
// the pid and races the delivery, and a polled control file adds a filesystem
// dependency and a latency floor for no gain.
//
// # Streams
//
// stdout belongs to the protocol. Everything this package writes for a human —
// the stderr noise, any diagnostic — goes to stderr, and the SDK's own logger
// defaults to discarding. A single stray byte on stdout corrupts the framing,
// which is exactly the failure the stderr-noise mode exists to test for.
package mcptest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Identity is what the fixture calls itself at initialize. Tests assert on
// these, so they are constants rather than configuration.
const (
	ServerName    = "looprig-mcp-fixture"
	ServerVersion = "0.0.1"
	ServerTitle   = "looprig MCP fixture server"
)

// Tool names the fixture may expose. MutatedToolName is the tool the "mutate"
// tool adds and removes; it is never present at startup.
const (
	ToolEcho    = "echo"
	ToolSlow    = "slow"
	ToolFail    = "fail"
	ToolBig     = "big"
	ToolMutate  = "mutate"
	ToolCrash   = "crash"
	ToolMutated = "echo2"
)

// Prompt and resource identifiers the fixture exposes when enabled.
const (
	PromptGreet = "greet"

	// ResourceStaticURI is a fixed resource with a known body.
	ResourceStaticURI = "fixture://static/hello"
	// ResourceStaticBody is that body.
	ResourceStaticBody = "hello from the fixture"

	// ResourceEchoTemplate is an RFC 6570 template: reading
	// fixture://echo/{word} returns {word}.
	ResourceEchoTemplate = "fixture://echo/{word}"
	// resourceEchoPrefix is the template's literal prefix, used to recover
	// {word} from a concrete URI.
	resourceEchoPrefix = "fixture://echo/"
)

// Bounds on tool arguments. The arguments come from a test, not an attacker,
// but a fixture that hangs for an hour or allocates a gigabyte because a test
// typo'd a zero is a bad fixture: it fails as a timeout somewhere else, long
// after the cause.
const (
	// MaxSlowMS caps the "slow" tool's sleep.
	MaxSlowMS = 5 * 60 * 1000
	// MaxBigBytes caps the "big" tool's result.
	MaxBigBytes = 32 << 20
	// MaxNoiseBytes caps the stderr noise.
	MaxNoiseBytes = 32 << 20
	// MaxInstructionsBytes caps the configured instructions string.
	MaxInstructionsBytes = 1 << 20
)

// noiseLineWidth is how often WriteNoise breaks its output. Bounded stderr
// capture is line-oriented in places; a single 4 MiB line is not a realistic
// server.
const noiseLineWidth = 80

// elicitTimeout bounds the initialize-time elicitation. It is a fixture
// talking to a test client on the same machine; if no answer arrives in this
// long, none is coming.
const elicitTimeout = 30 * time.Second

// ElicitMessage is the prompt the initialize-time elicitation sends. Tests
// match on it.
const ElicitMessage = "fixture: confirm startup"

// Config is the fixture's complete configuration. The zero value is a valid,
// minimal server: the four tools, no prompts, no resources, no instructions,
// no mutation, no crash tool, no noise.
type Config struct {
	// Instructions is the server's instructions string, returned at
	// initialize. Empty means the server sends none.
	Instructions string

	// Prompts adds the "greet" prompt (which takes arguments), and with it the
	// prompts capability.
	Prompts bool

	// Resources adds the static resource and the echo resource template, and
	// with them the resources capability.
	Resources bool

	// Mutate adds the "mutate" tool, which adds or removes ToolMutated at
	// runtime and so makes the server emit notifications/tools/list_changed.
	Mutate bool

	// Crash adds the "crash" tool, which exits the process immediately with
	// CrashExitCode: no reply, no shutdown, no flush.
	Crash bool

	// CrashExitCode is the status the "crash" tool exits with. It must be in
	// [1, 125] — a crash that exits 0 is not a crash, and the shell reserves
	// the values above 125.
	CrashExitCode int

	// NoiseBytes is how much the fixture writes to stderr at startup. It is
	// written by the command, not by NewServer; see WriteNoise.
	NoiseBytes int

	// ElicitOnInitialize makes the server send an elicitation request as soon
	// as the client's "initialized" notification arrives. See NewServer for
	// what "as soon as" can and cannot mean here.
	ElicitOnInitialize bool
}

// DefaultCrashExitCode is the "crash" tool's exit status unless configured
// otherwise.
const DefaultCrashExitCode = 7

// Validate reports whether c is usable. It is called by NewServer, and by the
// command before it starts anything, so a bad flag fails at startup with a
// clear message rather than mid-session with a protocol error.
func (c Config) Validate() error {
	if len(c.Instructions) > MaxInstructionsBytes {
		return fmt.Errorf("instructions: %d bytes exceeds the %d byte limit", len(c.Instructions), MaxInstructionsBytes)
	}
	if c.NoiseBytes < 0 || c.NoiseBytes > MaxNoiseBytes {
		return fmt.Errorf("noise bytes: %d out of range [0, %d]", c.NoiseBytes, MaxNoiseBytes)
	}
	if c.Crash && (c.CrashExitCode < 1 || c.CrashExitCode > 125) {
		return fmt.Errorf("crash exit code: %d out of range [1, 125]", c.CrashExitCode)
	}
	return nil
}

// NewServer builds a configured MCP server. It does not connect it: the caller
// chooses the transport (see cmd/fixture, which runs it over stdio).
//
// The returned server holds no process-global state except through the "crash"
// tool, so a test may build several.
func NewServer(cfg Config) (*mcp.Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("mcptest: invalid config: %w", err)
	}

	opts := &mcp.ServerOptions{Instructions: cfg.Instructions}
	if cfg.ElicitOnInitialize {
		opts.InitializedHandler = elicitOnInitialized
	}

	s := mcp.NewServer(&mcp.Implementation{
		Name:    ServerName,
		Version: ServerVersion,
		Title:   ServerTitle,
	}, opts)

	addBaseTools(s)
	if cfg.Mutate {
		addMutateTool(s)
	}
	if cfg.Crash {
		addCrashTool(s, cfg.CrashExitCode)
	}
	if cfg.Prompts {
		addPrompts(s)
	}
	if cfg.Resources {
		addResources(s)
	}
	return s, nil
}

// textResult is the shape every tool here returns: unstructured text content,
// no structured output. The tools exist to exercise the transport, not the
// SDK's schema inference on results.
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// EchoInput is the "echo" tool's argument.
type EchoInput struct {
	Text string `json:"text" jsonschema:"the text to echo back verbatim"`
}

// SlowInput is the "slow" tool's argument.
type SlowInput struct {
	MS int `json:"ms" jsonschema:"how long to sleep before replying, in milliseconds"`
}

// FailInput is the "fail" tool's argument.
type FailInput struct {
	Message string `json:"message,omitempty" jsonschema:"the message to report in the error result"`
}

// BigInput is the "big" tool's argument.
type BigInput struct {
	Bytes int `json:"bytes" jsonschema:"how many bytes of text to return"`
}

// MutateInput is the "mutate" tool's argument.
type MutateInput struct {
	Add bool `json:"add" jsonschema:"true to add the echo2 tool, false to remove it"`
}

// DefaultFailMessage is what "fail" reports when the client sends no message.
const DefaultFailMessage = "fixture: deliberate tool failure"

// addBaseTools registers the four tools every fixture server has.
//
// Each uses the SDK's generic mcp.AddTool, so the input schema is inferred
// from the argument struct and the SDK validates arguments against it before
// the handler runs — the tools advertise a well-formed schema because they
// have a real Go type behind them, not because someone hand-wrote one.
//
// The Out type parameter is `any` throughout, which is how the SDK spells "no
// structured output, no output schema" (see toolForErr). It is the SDK's
// serialization boundary, not a typed value passed onward.
func addBaseTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolEcho,
		Description: "Returns its text argument as text content.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, echoHandler)

	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolSlow,
		Description: "Sleeps for ms milliseconds, then replies. Honors cancellation.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SlowInput) (*mcp.CallToolResult, any, error) {
		if in.MS < 0 || in.MS > MaxSlowMS {
			return errorResult(fmt.Sprintf("ms: %d out of range [0, %d]", in.MS, MaxSlowMS)), nil, nil
		}
		t := time.NewTimer(time.Duration(in.MS) * time.Millisecond)
		defer t.Stop()
		select {
		case <-ctx.Done():
			// The client cancelled or the session died. Report it as an error
			// so a handler bug can never masquerade as a successful sleep;
			// the SDK drops the reply if the request was cancelled.
			return nil, nil, ctx.Err()
		case <-t.C:
			return textResult(fmt.Sprintf("slept %dms", in.MS)), nil, nil
		}
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolFail,
		Description: "Returns a tool error result (IsError). The call itself succeeds.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(_ context.Context, _ *mcp.CallToolRequest, in FailInput) (*mcp.CallToolResult, any, error) {
		msg := in.Message
		if msg == "" {
			msg = DefaultFailMessage
		}
		// Built by hand rather than by returning an error: an error from the
		// handler would also produce IsError, but this way the fixture states
		// what it is testing instead of relying on the SDK to convert it.
		return errorResult(msg), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolBig,
		Description: "Returns a text result of the requested size in bytes.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(_ context.Context, _ *mcp.CallToolRequest, in BigInput) (*mcp.CallToolResult, any, error) {
		if in.Bytes < 0 || in.Bytes > MaxBigBytes {
			return errorResult(fmt.Sprintf("bytes: %d out of range [0, %d]", in.Bytes, MaxBigBytes)), nil, nil
		}
		return textResult(strings.Repeat("x", in.Bytes)), nil, nil
	})
}

// echoHandler is the handler shared by "echo" and, once mutation adds it,
// ToolMutated.
func echoHandler(_ context.Context, _ *mcp.CallToolRequest, in EchoInput) (*mcp.CallToolResult, any, error) {
	return textResult(in.Text), nil, nil
}

// errorResult is a protocol-level tool error: a successful JSON-RPC response
// carrying IsError. It is not a transport failure, and a client must be able
// to tell the two apart.
func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

// addMutateTool registers the tool that changes the server's tool list at
// runtime. The SDK emits notifications/tools/list_changed from AddTool and
// RemoveTools, after a short debounce, to every connected session.
func addMutateTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolMutate,
		Description: "Adds or removes the " + ToolMutated + " tool, triggering tools/list_changed.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in MutateInput) (*mcp.CallToolResult, any, error) {
		if in.Add {
			mcp.AddTool(s, &mcp.Tool{
				Name:        ToolMutated,
				Description: "A second echo, added at runtime.",
				Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
			}, echoHandler)
			return textResult("added " + ToolMutated), nil, nil
		}
		s.RemoveTools(ToolMutated)
		return textResult("removed " + ToolMutated), nil, nil
	})
}

// addCrashTool registers the tool that kills the process mid-request. The
// client sees the connection die with a reply outstanding, which is the point:
// it is how a real server crash looks from the other end.
func addCrashTool(s *mcp.Server, code int) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        ToolCrash,
		Description: fmt.Sprintf("Exits the process immediately with status %d. Never replies.", code),
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true)},
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		// os.Exit, not a panic or a returned error: the mode exists to produce
		// a process that dies without unwinding, flushing, or replying — the
		// thing a client's premature-exit handling has to survive. Anything
		// gentler would test something else.
		os.Exit(code)
		return nil, nil, errors.New("unreachable: crash tool returned from os.Exit")
	})
}

func ptr[T any](v T) *T { return &v }

// GreetArg is the name of the "greet" prompt's required argument.
const GreetArg = "name"

// addPrompts registers the one prompt the fixture has. It takes a required
// argument, because a prompt without arguments does not exercise the argument
// path.
func addPrompts(s *mcp.Server) {
	s.AddPrompt(&mcp.Prompt{
		Name:        PromptGreet,
		Title:       "Greet someone",
		Description: "Produces a greeting for the named person.",
		Arguments: []*mcp.PromptArgument{{
			Name:        GreetArg,
			Title:       "Name",
			Description: "who to greet",
			Required:    true,
		}},
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		name := req.Params.Arguments[GreetArg]
		if name == "" {
			// The SDK does not validate prompt arguments, so the handler must.
			return nil, fmt.Errorf("prompt %q: missing required argument %q", PromptGreet, GreetArg)
		}
		return &mcp.GetPromptResult{
			Description: "a greeting",
			Messages: []*mcp.PromptMessage{{
				Role:    "user",
				Content: &mcp.TextContent{Text: "Hello, " + name + "!"},
			}},
		}, nil
	})
}

// addResources registers one static resource and one template, which are the
// two shapes a client has to handle.
func addResources(s *mcp.Server) {
	s.AddResource(&mcp.Resource{
		URI:         ResourceStaticURI,
		Name:        "hello",
		Title:       "A static greeting",
		Description: "A fixed resource with a known body.",
		MIMEType:    "text/plain",
	}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI:      ResourceStaticURI,
			MIMEType: "text/plain",
			Text:     ResourceStaticBody,
		}}}, nil
	})

	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: ResourceEchoTemplate,
		Name:        "echo",
		Title:       "Echo a word",
		Description: "Reading fixture://echo/{word} returns {word}.",
		MIMEType:    "text/plain",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		// The SDK routes by matching the template, but it does not extract the
		// variables, so the handler parses the concrete URI itself. The prefix
		// check is not decoration: the handler must never assume the router
		// gave it something the template matches.
		word, ok := strings.CutPrefix(req.Params.URI, resourceEchoPrefix)
		if !ok || word == "" || strings.Contains(word, "/") {
			return nil, fmt.Errorf("resource %q does not match %q", req.Params.URI, ResourceEchoTemplate)
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI:      req.Params.URI,
			MIMEType: "text/plain",
			Text:     word,
		}}}, nil
	})
}

// elicitOnInitialized sends an elicitation request once the client reports
// itself initialized.
//
// This is as close to "elicitation during initialize" as MCP allows, and the
// gap is the protocol's, not the SDK's: the server has no session to send a
// request on until initialize has returned, and the SDK enforces that (see
// ServerSession.Elicit, which refuses before the client's capabilities are
// known). "At the first moment the server is allowed to speak unprompted" is
// the real thing being tested.
//
// The send runs in its own goroutine: this handler is called from the
// session's notification dispatch, and blocking here to wait for the client's
// answer would stall the very dispatch that has to deliver it.
//
// The goroutine's context is the notification's, minus its cancellation, plus
// a timeout of our own. Not context.Background: that would discard any values
// on the request context. Not the request context as-is either — it is done
// the moment this handler returns, which would cancel the elicitation before
// the client ever saw it.
func elicitOnInitialized(reqCtx context.Context, req *mcp.InitializedRequest) {
	ss := req.Session
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), elicitTimeout)
		defer cancel()
		if _, err := ss.Elicit(ctx, &mcp.ElicitParams{
			Mode:    "form",
			Message: ElicitMessage,
		}); err != nil {
			// Expected whenever the client did not advertise elicitation. The
			// fixture reports and carries on: refusing to serve would make
			// every non-elicitation test that set the flag fail obscurely.
			fmt.Fprintf(os.Stderr, "mcptest: elicitation on initialize failed: %v\n", err)
		}
	}()
}

// noiseLine is the repeated unit of WriteNoise's output. It is recognizable on
// sight in a failure, and contains no JSON, so a test that finds it on stdout
// has found a real leak and not an artifact of the noise itself.
const noiseLine = "MCPTEST-NOISE"

// WriteNoise writes n bytes to w. It exists so the command can put a
// configurable amount of chatter on stderr — the thing real servers do, and
// the thing a client's bounded stderr capture has to survive.
//
// The output is exactly n bytes, so a test can assert on the count.
func WriteNoise(w io.Writer, n int) error {
	if n < 0 || n > MaxNoiseBytes {
		return fmt.Errorf("mcptest: noise bytes: %d out of range [0, %d]", n, MaxNoiseBytes)
	}
	if n == 0 {
		return nil
	}
	var b strings.Builder
	b.Grow(n + noiseLineWidth)
	for b.Len() < n {
		b.WriteString(noiseLine)
		if b.Len()%noiseLineWidth < len(noiseLine) {
			b.WriteByte('\n')
		}
	}
	if _, err := io.WriteString(w, b.String()[:n]); err != nil {
		return fmt.Errorf("mcptest: writing noise: %w", err)
	}
	return nil
}
