// This file defines the callbacks an application installs on a connection: the
// server-initiated capabilities it is prepared to serve (elicitation, sampling,
// roots) and the passive observers (logs, events).
//
// A handler is not a preference — it is the thing that makes a capability
// honorable. The client advertises a capability only when the Definition
// requests it AND the matching handler is installed here (see Connect), so an
// interface in this file is the difference between a capability being on the
// wire and not.
//
// The request/response types are deliberately minimal: the tasks that
// implement elicitation and sampling flesh out their semantics (schema
// validation, policy, budgets). What is fixed already is their shape — neutral,
// bounded, and free of SDK types.

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/looprig/mcp/internal/protocol"
)

// ElicitAction is how a human answered an elicitation. The zero value is not a
// valid action: a handler must say what happened.
type ElicitAction uint8

// The elicitation outcomes, per the MCP elicitation result actions.
const (
	// ElicitAccept means the human supplied the requested content.
	ElicitAccept ElicitAction = iota + 1
	// ElicitDecline means the human refused to answer.
	ElicitDecline
	// ElicitCancel means the human dismissed the request without deciding.
	ElicitCancel
)

// String returns a stable lowercase identifier, or "unknown".
func (a ElicitAction) String() string {
	switch a {
	case ElicitAccept:
		return "accept"
	case ElicitDecline:
		return "decline"
	case ElicitCancel:
		return "cancel"
	default:
		return "unknown"
	}
}

// ElicitRequest is a server's request for human input. Message and Schema are
// server-supplied and untrusted: the message is bounded text to show a person,
// and the schema constrains the answer — neither may be treated as an
// instruction to the host.
type ElicitRequest struct {
	// Binding names the server that asked.
	Binding Name
	// Message is the bounded prompt to show the human.
	Message string
	// Schema is the JSON Schema the answer must satisfy. It is raw JSON
	// because a schema is a serialization-boundary document, not domain data.
	Schema json.RawMessage
}

// ElicitResult is the human's answer. Content is meaningful only when Action is
// ElicitAccept; it must satisfy the request's Schema, which the client
// re-checks before it reaches the server.
type ElicitResult struct {
	Action  ElicitAction
	Content json.RawMessage
}

// ElicitationHandler serves server-initiated requests for human input. It is
// called on the connection's goroutine and must respect ctx, which carries the
// elicitation timeout.
//
// Installing one is what allows the elicitation capability to be advertised.
type ElicitationHandler interface {
	Elicit(ctx context.Context, req ElicitRequest) (ElicitResult, error)
}

// SampleRole is who authored a sampling message.
type SampleRole uint8

// The sampling message roles.
const (
	SampleRoleUser SampleRole = iota + 1
	SampleRoleAssistant
)

// String returns a stable lowercase identifier, or "unknown".
func (r SampleRole) String() string {
	switch r {
	case SampleRoleUser:
		return "user"
	case SampleRoleAssistant:
		return "assistant"
	default:
		return "unknown"
	}
}

// SampleMessage is one turn of a sampling conversation.
type SampleMessage struct {
	Role SampleRole
	Text string
}

// SampleRequest is a server's request for an LLM completion. Every field is
// server-supplied: the host decides which model runs it, and whether it runs
// at all.
type SampleRequest struct {
	// Binding names the server that asked.
	Binding Name
	// SystemPrompt is the server's requested system prompt, bounded.
	SystemPrompt string
	// Messages is the bounded conversation to complete.
	Messages []SampleMessage
	// MaxTokens is the server's requested completion budget. The host caps it
	// against Limits.MaxSamplingTokens; a server never raises the ceiling.
	MaxTokens int
}

// SampleResult is the completion the host produced.
type SampleResult struct {
	// Model names the model the host actually used, which need not be one the
	// server asked for.
	Model string
	// Text is the completion.
	Text string
	// StopReason is why generation stopped, verbatim from the host.
	StopReason string
}

// SamplingHandler serves server-initiated LLM completion requests. Returning an
// error of class FailureSamplingDenied is how a host refuses one.
//
// Installing one is what allows the sampling capability to be advertised.
type SamplingHandler interface {
	Sample(ctx context.Context, req SampleRequest) (SampleResult, error)
}

// Root is a filesystem root exposed to a server. Exposing one grants a server
// knowledge of a path, never access to it: the host still mediates every read.
type Root struct {
	// URI is the root's file:// URI.
	URI string
	// Name is a display name for the root.
	Name string
}

// RootsProvider supplies the filesystem roots visible to a server. It is called
// whenever the server asks, so a host may narrow the set at any time.
//
// Installing one is what allows the roots capability to be advertised.
type RootsProvider interface {
	Roots(ctx context.Context) ([]Root, error)
}

// LogLevel is the severity of a server log message, per the MCP logging levels
// (which follow syslog).
type LogLevel string

// The MCP log levels, ordered least to most severe.
const (
	LogDebug     LogLevel = "debug"
	LogInfo      LogLevel = "info"
	LogNotice    LogLevel = "notice"
	LogWarning   LogLevel = "warning"
	LogError     LogLevel = "error"
	LogCritical  LogLevel = "critical"
	LogAlert     LogLevel = "alert"
	LogEmergency LogLevel = "emergency"
)

// LogMessage is one log record a server sent. Every field is server-supplied
// and bounded before it reaches a handler: Text is truncated to
// Limits.MaxLogMessageBytes. Treat it as diagnostics from an untrusted peer —
// never as a fact about the host.
type LogMessage struct {
	// Binding names the server that logged.
	Binding Name
	// Level is the severity the server claimed.
	Level LogLevel
	// Logger is the server-side logger name, if it sent one.
	Logger string
	// Text is the bounded message.
	Text string
}

// LogHandler receives server log messages. A nil LogHandler drops them.
type LogHandler func(LogMessage)

// Event is a client-emitted notification about a binding. It is a sealed union:
// only this package can add a member, so callers may exhaust it with a type
// switch — but must still tolerate an unknown member, since a later task adds
// events and a default case is what keeps that from breaking them.
type Event interface {
	event()
}

// StateChanged reports a lifecycle transition. It carries safe metadata only.
type StateChanged struct {
	// Binding names the binding that moved.
	Binding Name
	// From and To are the transition.
	From, To State
	// At is when the transition was observed.
	At time.Time
}

func (StateChanged) event() {}

// EventHandler receives binding events. It is invoked synchronously on the
// goroutine that caused the event and blocks that goroutine — a handler that
// needs to do work must hand it off. A nil EventHandler drops every event.
type EventHandler func(Event)

// Handlers are the application callbacks for one connection. It is legal to
// install a handler for a capability the Definition does not request — the
// handler is simply never called — but requesting a capability without its
// handler is a configuration error that Connect rejects, rather than a silent
// downgrade of what the application asked for.
type Handlers struct {
	// Elicitation serves human-input requests. Nil means the elicitation
	// capability is not advertised.
	Elicitation ElicitationHandler
	// Sampling serves LLM completion requests. Nil means the sampling
	// capability is not advertised.
	Sampling SamplingHandler
	// Roots supplies filesystem roots. Nil means the roots capability is not
	// advertised.
	Roots RootsProvider
	// Log receives server log messages. Nil drops them.
	Log LogHandler
	// Event receives binding events. Nil drops them.
	Event EventHandler
}

// advertised reports the capabilities to put on the wire for caps, and fails
// closed when a requested capability has no handler to serve it.
//
// Advertising is the intersection of "asked for" and "able to serve": a
// capability the host cannot honor must never be advertised, because a server
// that believes in it will make requests that can only be refused. But a
// requested capability with no handler is a mistake in the application's
// configuration, not a preference to be quietly honored halfway — so it is
// reported rather than downgraded.
func (h Handlers) advertised(binding Name, caps ClientCapabilities) (protocol.ClientCapabilities, error) {
	for _, c := range []struct {
		name      string
		requested bool
		handled   bool
	}{
		{"Elicitation", caps.Elicitation, h.Elicitation != nil},
		{"Sampling", caps.Sampling, h.Sampling != nil},
		{"Roots", caps.Roots, h.Roots != nil},
	} {
		if c.requested && !c.handled {
			return protocol.ClientCapabilities{}, NewError(FailureInvalidConfig, binding, "validate",
				fmt.Sprintf("Capabilities.%s is requested but Handlers.%s is nil: a capability with no handler cannot be advertised", c.name, c.name), nil)
		}
	}
	return protocol.ClientCapabilities{
		Elicitation: caps.Elicitation,
		Sampling:    caps.Sampling,
		Roots:       caps.Roots,
	}, nil
}
