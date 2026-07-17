// Tests for the shared classification: the part of a transport's failure
// reporting that is the same whichever HTTP transport suffered it.

package httpconn

import (
	"testing"

	"github.com/looprig/mcp/pkg/client"
)

// TestDeadlineClass pins the op-aware classification of a blown deadline.
//
// It is a direct unit test because deadlineClass is a pure function of the op
// and because the paths that reach it cannot cover the op set cheaply: the
// classification a caller acts on is decided here, so this is where every op is
// stated. The regression it exists to catch is the one this code started with —
// reporting every deadline as a startup timeout, which tells a caller that its
// healthy binding failed to start — and that mistake is invisible to a test
// that only ever blows one deadline.
func TestDeadlineClass(t *testing.T) {
	t.Parallel()

	// Every op this package defines, so that a new op has to be classified here
	// rather than defaulting in silence.
	tests := []struct {
		name string
		op   string
		want client.FailureClass
	}{
		// Startup: the binding never came up, and the caller may retry or drop it.
		{name: "connect", op: OpConnect, want: client.FailureStartupTimeout},
		{name: "initialize", op: OpInitialize, want: client.FailureStartupTimeout},

		// Everything else: the binding is fine and this operation ran out of time.
		{name: "new", op: OpNew, want: client.FailureDeadline},
		{name: "close", op: OpClose, want: client.FailureDeadline},
		{name: "list tools", op: OpListTools, want: client.FailureDeadline},
		{name: "list prompts", op: OpListPrompts, want: client.FailureDeadline},
		{name: "list resources", op: OpListResources, want: client.FailureDeadline},
		{name: "list resource templates", op: OpListResourceTemplates, want: client.FailureDeadline},
		{name: "call tool", op: OpCallTool, want: client.FailureDeadline},
		{name: "get prompt", op: OpGetPrompt, want: client.FailureDeadline},
		{name: "read resource", op: OpReadResource, want: client.FailureDeadline},
		{name: "subscribe", op: OpSubscribe, want: client.FailureDeadline},
		{name: "set log level", op: OpSetLogLevel, want: client.FailureDeadline},

		// An op this package does not define is not a startup: defaulting the
		// unknown case to a startup timeout would misreport a caller's binding.
		{name: "unknown op", op: "no_such_op", want: client.FailureDeadline},
		{name: "empty op", op: "", want: client.FailureDeadline},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := deadlineClass(tt.op); got != tt.want {
				t.Errorf("deadlineClass(%q) = %v, want %v", tt.op, got, tt.want)
			}
		})
	}
}
