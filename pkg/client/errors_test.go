package client

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// allClasses lists every declared FailureClass exactly once. Keep in sync with
// the const block in errors.go; TestFailureClassString proves it is exhaustive
// by comparing its length against failureClassSentinel, the unexported marker
// that must remain the final const in the block — any class appended before
// the sentinel bumps its value and fails the guard until it is listed here.
var allClasses = []FailureClass{
	FailureInvalidConfig,
	FailureUnsupportedProtocol,
	FailureStartupTimeout,
	FailureAuthRequired,
	FailureAuthDenied,
	FailureAuthExpired,
	FailureAuthFailed,
	FailureTransportClosed,
	FailureFraming,
	FailureRemoteHTTP,
	FailureServerProtocol,
	FailureDeadline,
	FailureCancelled,
	FailureCatalogInvalid,
	FailureCatalogStale,
	FailureCatalogOverLimit,
	FailureNotFound,
	FailureToolUnavailable,
	FailureToolSchemaChanged,
	FailureRemoteToolError,
	FailureLimitExceeded,
	FailureElicitationDeclined,
	FailureElicitationCancelled,
	FailureElicitationInvalid,
	FailureElicitationTimeout,
	FailureSamplingDenied,
	FailureSamplingOverBudget,
	FailureIndeterminate,
	FailureShutdown,
}

func TestFailureClassString(t *testing.T) {
	t.Parallel()

	if got, want := int(failureClassSentinel)-1, len(allClasses); got != want {
		t.Fatalf("declared class count = %d, want %d (allClasses out of sync with const block)", got, want)
	}

	snake := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	seenValues := make(map[FailureClass]bool, len(allClasses))
	seenStrings := make(map[string]FailureClass, len(allClasses))
	for _, c := range allClasses {
		if c == 0 {
			t.Fatalf("declared class has zero value")
		}
		if seenValues[c] {
			t.Errorf("class value %d declared twice", c)
		}
		seenValues[c] = true

		s := c.String()
		if s == "unknown" {
			t.Errorf("class %d: String() = %q, want a declared identifier", c, s)
		}
		if !snake.MatchString(s) {
			t.Errorf("class %d: String() = %q, want lowercase snake identifier", c, s)
		}
		if prev, dup := seenStrings[s]; dup {
			t.Errorf("classes %d and %d share String() %q", prev, c, s)
		}
		seenStrings[s] = c
	}
}

func TestFailureClassStringUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		class FailureClass
	}{
		{name: "zero value", class: FailureClass(0)},
		{name: "sentinel", class: failureClassSentinel},
		{name: "past sentinel", class: failureClassSentinel + 1},
		{name: "max uint8", class: FailureClass(255)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.class.String(); got != "unknown" {
				t.Errorf("FailureClass(%d).String() = %q, want %q", tt.class, got, "unknown")
			}
		})
	}
}

func TestNewErrorBoundsMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msg  string
		want string
	}{
		{name: "empty", msg: "", want: ""},
		{name: "short unchanged", msg: "connection refused", want: "connection refused"},
		{
			name: "control chars become spaces",
			msg:  "line one\nline two\ttab\r\x00nul\x1besc",
			want: "line one line two tab  nul esc",
		},
		{name: "space preserved", msg: "a b", want: "a b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := NewError(FailureRemoteHTTP, "srv", "call", tt.msg, nil)
			if e.Msg != tt.want {
				t.Errorf("Msg = %q, want %q", e.Msg, tt.want)
			}
		})
	}
}

func TestNewErrorTruncatesLongMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msg  string
	}{
		{name: "ascii overflow", msg: strings.Repeat("a", MaxMessageBytes+500)},
		{name: "multibyte overflow", msg: strings.Repeat("é", MaxMessageBytes)},
		{name: "exact limit not truncated", msg: strings.Repeat("b", MaxMessageBytes)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := NewError(FailureRemoteToolError, "srv", "call", tt.msg, nil)
			if len(e.Msg) > MaxMessageBytes {
				t.Errorf("len(Msg) = %d, want <= %d", len(e.Msg), MaxMessageBytes)
			}
			if !utf8.ValidString(e.Msg) {
				t.Errorf("Msg is not valid UTF-8 after truncation")
			}
			if len(tt.msg) > MaxMessageBytes {
				if !strings.HasSuffix(e.Msg, truncationMarker) {
					t.Errorf("truncated Msg missing marker %q, got tail %q", truncationMarker, e.Msg[len(e.Msg)-20:])
				}
			} else if e.Msg != tt.msg {
				t.Errorf("Msg altered although within bound")
			}
		})
	}
}

func TestErrorFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		class   FailureClass
		binding Name
		op      string
		msg     string
		wrapped error
		want    string
	}{
		{
			name:  "all segments",
			class: FailureAuthDenied, binding: "github", op: "call_tool", msg: "denied by server",
			want: "mcp: github: call_tool: auth_denied: denied by server",
		},
		{
			name:  "empty binding omitted",
			class: FailureAuthDenied, op: "call_tool", msg: "denied",
			want: "mcp: call_tool: auth_denied: denied",
		},
		{
			name:  "empty op omitted",
			class: FailureAuthDenied, binding: "github", msg: "denied",
			want: "mcp: github: auth_denied: denied",
		},
		{
			name:  "class only",
			class: FailureShutdown,
			want:  "mcp: shutdown",
		},
		{
			name:  "wrapped text used when msg empty",
			class: FailureTransportClosed, binding: "gh", op: "read",
			wrapped: errors.New("pipe broken"),
			want:    "mcp: gh: read: transport_closed: pipe broken",
		},
		{
			name:  "wrapped text suppressed when msg present",
			class: FailureTransportClosed, binding: "gh", op: "read", msg: "stream ended",
			wrapped: errors.New("pipe broken"),
			want:    "mcp: gh: read: transport_closed: stream ended",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := NewError(tt.class, tt.binding, tt.op, tt.msg, tt.wrapped)
			if got := e.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrorRedactionAndBounding(t *testing.T) {
	t.Parallel()

	canary := strings.Repeat("CANARY_SECRET_TOKEN_", 200) // 4000 bytes, well over MaxMessageBytes
	wrapped := fmt.Errorf("http 401: authorization header was Bearer %s", canary)
	binding, op := Name("github"), "initialize"

	// overhead is everything Error() may add around the bounded message.
	overhead := len("mcp: ") + len(binding) + len(op) + len(FailureAuthFailed.String()) + 3*len(": ")

	t.Run("msg provided: wrapped canary never appears", func(t *testing.T) {
		t.Parallel()
		e := NewError(FailureAuthFailed, binding, op, "authentication failed", wrapped)
		out := e.Error()
		if strings.Contains(out, "CANARY_SECRET_TOKEN_") {
			t.Errorf("Error() leaked wrapped error text: %q", out[:80])
		}
		if len(out) > MaxMessageBytes+overhead {
			t.Errorf("len(Error()) = %d, want <= %d", len(out), MaxMessageBytes+overhead)
		}
	})

	t.Run("msg empty: wrapped text included but bounded", func(t *testing.T) {
		t.Parallel()
		e := NewError(FailureAuthFailed, binding, op, "", wrapped)
		out := e.Error()
		if len(out) > MaxMessageBytes+overhead {
			t.Errorf("len(Error()) = %d, want <= %d", len(out), MaxMessageBytes+overhead)
		}
		if strings.Contains(out, canary) {
			t.Errorf("Error() contains the full unbounded canary")
		}
		if !strings.HasSuffix(out, truncationMarker) {
			t.Errorf("bounded wrapped text missing truncation marker")
		}
	})
}

func TestClassOf(t *testing.T) {
	t.Parallel()

	inner := NewError(FailureFraming, "gh", "read", "bad frame", nil)
	outer := NewError(FailureTransportClosed, "gh", "call", "closed", inner)

	tests := []struct {
		name      string
		err       error
		wantClass FailureClass
		wantOK    bool
	}{
		{name: "nil error", err: nil, wantOK: false},
		{name: "plain error", err: errors.New("boom"), wantOK: false},
		{name: "direct", err: inner, wantClass: FailureFraming, wantOK: true},
		{name: "outermost wins", err: outer, wantClass: FailureTransportClosed, wantOK: true},
		{
			name:      "through fmt.Errorf wrap",
			err:       fmt.Errorf("context: %w", inner),
			wantClass: FailureFraming, wantOK: true,
		},
		{
			name:      "double wrap outermost wins",
			err:       fmt.Errorf("context: %w", outer),
			wantClass: FailureTransportClosed, wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			class, ok := ClassOf(tt.err)
			if ok != tt.wantOK {
				t.Fatalf("ClassOf() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && class != tt.wantClass {
				t.Errorf("ClassOf() = %v, want %v", class, tt.wantClass)
			}
		})
	}
}

func TestErrorWrappingChain(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("underlying cause")
	e := NewError(FailureRemoteHTTP, "srv", "fetch", "http failure", sentinel)

	if got := e.Unwrap(); got != sentinel {
		t.Errorf("Unwrap() = %v, want sentinel", got)
	}
	if !errors.Is(e, sentinel) {
		t.Errorf("errors.Is(e, sentinel) = false, want true")
	}

	doubly := fmt.Errorf("outer context: %w", e)
	if !errors.Is(doubly, sentinel) {
		t.Errorf("errors.Is through fmt.Errorf = false, want true")
	}
	var target *Error
	if !errors.As(doubly, &target) {
		t.Fatalf("errors.As through fmt.Errorf = false, want true")
	}
	if target.Class != FailureRemoteHTTP {
		t.Errorf("errors.As target class = %v, want %v", target.Class, FailureRemoteHTTP)
	}
}
