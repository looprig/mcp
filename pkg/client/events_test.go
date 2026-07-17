package client

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/internal/secrettest"
)

// eventUnion is every member of the Event union. A member missing from this list
// escapes every sweep in this file, so TestEventUnionIsComplete checks it
// against the package's own declarations rather than against someone's memory.
func eventUnion() []Event {
	return []Event{
		StateChanged{},
		CatalogStale{},
		CatalogCandidate{},
		CatalogRefreshed{},
		CatalogAdopted{},
		CatalogRejected{},
		ConnectionLost{},
		ConnectionRestored{},
		ServerLog{},
		RequestProgress{},
	}
}

// TestEventUnionIsComplete keeps eventUnion honest by construction: every type
// in this package that implements Event must be in it. A new event added
// without a line here fails this test, and so does not slip past the redaction
// sweeps below.
func TestEventUnionIsComplete(t *testing.T) {
	t.Parallel()

	// The sealed interface's method set is what makes this checkable: only this
	// package can implement Event, so the union is closed and enumerable.
	declared := make(map[string]bool)
	for _, e := range eventUnion() {
		declared[reflect.TypeOf(e).Name()] = true
	}

	// Every exported struct in the package that satisfies Event. Reflection
	// cannot enumerate a package's types, so this is the next best thing: the
	// types that the module's own emitters construct, gathered from the one
	// place they are all named.
	for _, name := range eventTypeNames(t) {
		if !declared[name] {
			t.Errorf("%s implements Event but is missing from eventUnion(): it escapes every redaction sweep in this file", name)
		}
	}
}

// eventTypeNames returns the name of every type this package's events.go and
// handlers.go seal into the union, read from the source's event() method
// receivers. Reading the source is the only way to enumerate the union without
// trusting the very list under test.
func eventTypeNames(t *testing.T) []string {
	t.Helper()

	var names []string
	for _, file := range []string{"events.go", "handlers.go"} {
		src := readSource(t, file)
		for _, line := range strings.Split(src, "\n") {
			// "func (StateChanged) event() {}"
			const prefix = "func ("
			const suffix = ") event()"
			if !strings.HasPrefix(line, prefix) || !strings.Contains(line, suffix) {
				continue
			}
			name := strings.TrimPrefix(line[:strings.Index(line, suffix)], prefix)
			names = append(names, strings.TrimSpace(name))
		}
	}
	if len(names) == 0 {
		t.Fatal("found no event() implementations: the sweep is not reading the source it thinks it is")
	}
	return names
}

// TestEventFieldsAreSafeByConstruction sweeps every event's fields and rejects
// any type that could carry something an event must never carry.
//
// This is a structural check rather than a behavioural one, and that is the
// point: an event with a json.RawMessage field is one careless emitter away from
// carrying a tool's arguments, and no test of today's emitters would catch the
// one added next year. The allowlist is what makes an unsafe field a compile-…
// well, a test-time failure, at the moment someone writes it.
func TestEventFieldsAreSafeByConstruction(t *testing.T) {
	t.Parallel()

	// The types an event field may have. Everything here is either bounded text
	// this module produced, a closed enum, an ordinal, or a timestamp.
	allowed := map[reflect.Type]string{
		reflect.TypeOf(Name("")):        "a binding name: configured by the host, validated, bounded",
		reflect.TypeOf(""):              "bounded text: see TestEventTextIsBounded",
		reflect.TypeOf(uint64(0)):       "a generation ordinal",
		reflect.TypeOf(0):               "a count",
		reflect.TypeOf(float64(0)):      "a progress figure",
		reflect.TypeOf(false):           "a flag",
		reflect.TypeOf(time.Time{}):     "a timestamp",
		reflect.TypeOf(State(0)):        "a lifecycle state: a closed enum",
		reflect.TypeOf(FailureClass(0)): "a failure class: a closed enum",
		reflect.TypeOf(LogLevel("")):    "a log level: a closed enum of MCP's own levels",
		reflect.TypeOf(ServerIdentity{}): "the server's claimed identity: three bounded strings, cosmetic, " +
			"and already in Status",
	}

	for _, e := range eventUnion() {
		typ := reflect.TypeOf(e)
		t.Run(typ.Name(), func(t *testing.T) {
			t.Parallel()
			for i := range typ.NumField() {
				f := typ.Field(i)
				if _, ok := allowed[f.Type]; !ok {
					t.Errorf("%s.%s is a %s: not an allowed event field type.\n"+
						"An event carries safe metadata only — no payloads, no schemas, no raw bytes, no errors.\n"+
						"If this type is genuinely safe, add it to the allowlist with the reason.",
						typ.Name(), f.Name, f.Type)
				}
			}
		})
	}
}

// TestEventsCarryNoSecrets points the module's own adversary — the reflection
// walker that reads unexported fields and follows pointers — at a fully
// populated event of every kind, and checks that nothing secret is reachable.
//
// Events are secret-free by construction (see the field sweep above), so this
// cannot fail while that passes. It is here because "by construction" is an
// argument, and an argument is worth exactly as much as the test that would
// catch it being wrong.
func TestEventsCarryNoSecrets(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-token-value"

	for _, e := range populatedEvents(secret) {
		typ := reflect.TypeOf(e)
		t.Run(typ.Name(), func(t *testing.T) {
			t.Parallel()
			// Every event here was built with the secret offered to every field
			// that would take it, which is what makes the assertion meaningful:
			// the walker is looking at the worst case an emitter could produce.
			dump := secrettest.Dump(e)
			if strings.Contains(dump, secret) {
				t.Errorf("%s exposes a value an emitter passed in:\n%s", typ.Name(), dump)
			}
		})
	}
}

// populatedEvents builds one of every event with the emitter's own bounded
// values, and with taint offered wherever a field would accept it.
//
// The taint is what an emitter must never put in an event: a credential, a
// header, a raw argument. It goes through the same constructors the client uses
// (NewError, failureMessage) so that what is asserted is the client's own
// handling of a value, not a test's idea of it.
func populatedEvents(taint string) []Event {
	now := time.Now()
	// A failure whose text a careless emitter would render verbatim: the taint
	// is in the wrapped cause, which is exactly where a transport's own error
	// would put a credential-bearing URL.
	tainted := NewError(FailureTransportClosed, "srv", "call_tool", "", errTainted(taint))

	return []Event{
		StateChanged{Binding: "srv", From: StateReady, To: StateDegraded, At: now},
		CatalogStale{Binding: "srv", Family: "tools", At: now},
		CatalogCandidate{Binding: "srv", Generation: 2, Digest: "abc", Adopted: 1, At: now},
		CatalogRefreshed{Binding: "srv", Generation: 1, Digest: "abc", At: now},
		CatalogAdopted{Binding: "srv", Generation: 2, Digest: "abc", Previous: 1, At: now},
		CatalogRejected{
			Binding: "srv", Class: tainted.Class,
			Message: failureMessage(tainted), Adopted: 1, Retrying: true, At: now,
		},
		ConnectionLost{
			Binding: "srv", Class: tainted.Class,
			Message: failureMessage(tainted), Adopted: 1, Retrying: true, At: now,
		},
		ConnectionRestored{Binding: "srv", Server: ServerIdentity{Name: "srv"}, Adopted: 1, Generation: 2, At: now},
		ServerLog{Binding: "srv", Level: LogInfo, Logger: "srv", Text: "hello", At: now},
		RequestProgress{Binding: "srv", Progress: 1, Total: 2, Message: "working", At: now},
	}
}

// errTainted is an error carrying a secret, standing in for a transport error
// that quotes a credential-bearing URL.
type errTainted string

func (e errTainted) Error() string {
	return "dial https://user:" + string(e) + "@example.com/mcp: connection reset"
}

// TestEventTextIsBounded: the free text an event carries is an *Error's Msg,
// which NewError bounds at construction. A message this module writes about a
// server's failure must not become unbounded because the failure was.
func TestEventTextIsBounded(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("A", 4*MaxMessageBytes)
	err := NewError(FailureTransportClosed, "srv", "call_tool", huge, nil)

	got := failureMessage(err)
	if len(got) > MaxMessageBytes {
		t.Errorf("an event's message is %d bytes, want at most MaxMessageBytes (%d)", len(got), MaxMessageBytes)
	}
	if !strings.Contains(got, truncationMarker) {
		t.Errorf("the message was not marked as truncated: %q", got)
	}
}

// TestEventTextExcludesWrappedErrors is the redaction rule itself, and the
// reason failureMessage is not Error.Error.
//
// A wrapped cause is a transport's or a server's own error. net/http renders the
// request URL into its errors verbatim — userinfo included — so a wrapped error
// is one step away from putting `https://user:token@host` into every event
// handler, journal and telemetry sink an application installs. Design §Events is
// explicit that authorization URLs containing secrets are excluded, and bounding
// that text would only make the leak shorter.
func TestEventTextExcludesWrappedErrors(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-token-value"

	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{
			name: "a wrapped cause never reaches the message",
			err:  NewError(FailureTransportClosed, "srv", "call_tool", "", errTainted(secret)),
			// No message was written, so the class is all that is known — and
			// all that is said.
			want: "the binding reported a transport_closed failure",
		},
		{
			name: "an explicit message wins, and the cause is still excluded",
			err:  NewError(FailureTransportClosed, "srv", "call_tool", "the server process exited", errTainted(secret)),
			want: "the server process exited",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := failureMessage(tt.err)
			if got != tt.want {
				t.Errorf("failureMessage() = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, secret) {
				t.Errorf("failureMessage() leaked a wrapped error's text: %q", got)
			}
			// The cause is not destroyed — a caller holding the error can still
			// unwrap it, which is what an operator debugging a connection needs.
			// It just does not travel to an event handler. (Error.Error is not
			// asked here: an explicit Msg suppresses the cause's text there too,
			// so unwrapping is the only place the premise is observable.)
			cause := errors.Unwrap(tt.err)
			if cause == nil || !strings.Contains(cause.Error(), secret) {
				t.Error("the test's own premise is broken: the wrapped cause does not carry the secret")
			}
		})
	}
}

// TestServerLogEventIsBounded: a log's text is bounded by the protocol boundary
// before it reaches an event, per Limits.MaxLogMessageBytes. This drives the
// real adapter rather than constructing the event, because the bound is the
// conversion's and the event is only its carrier.
func TestServerLogEventIsBounded(t *testing.T) {
	t.Parallel()

	rec := &eventRecorder{}
	conn := okConn()
	conn.initResult.Capabilities.Logging = true
	tr := newFakeTransport(conn)
	def := okDefinition(tr)
	def.Limits.MaxLogMessageBytes = 32

	c, err := Connect(context.Background(), def, Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	// The record the transport delivers is already bounded by the protocol
	// layer; the client must not undo that, and must not add to it.
	onLog := tr.lastConfig().OnLog
	if onLog == nil {
		t.Fatal("the client installed no OnLog callback, so no log can reach an event")
	}
	onLog(protocol.LogRecord{Level: "info", Logger: "srv", Text: strings.Repeat("L", 32)})

	logs := eventsOf[ServerLog](rec)
	if len(logs) != 1 {
		t.Fatalf("ServerLog events = %d, want 1", len(logs))
	}
	if got := len(logs[0].Text); got > def.Limits.MaxLogMessageBytes {
		t.Errorf("ServerLog.Text = %d bytes, want at most the binding's %d", got, def.Limits.MaxLogMessageBytes)
	}
}

// TestEventHandlerAloneEnablesServerLogs: a binding whose only observer is the
// event stream must still receive the server's logs. A server sends none until a
// level is asked for, so a client that only asked when a Log handler was
// installed would leave such a binding in a silence indistinguishable from a
// quiet server.
func TestEventHandlerAloneEnablesServerLogs(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.initResult.Capabilities.Logging = true
	tr := newFakeTransport(conn)

	rec := &eventRecorder{}
	c, err := Connect(context.Background(), okDefinition(tr), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	level, calls := conn.requestedLogLevel()
	if calls != 1 || level != string(DefaultLogLevel) {
		t.Errorf("the server was asked for level %q %d times, want %q once", level, calls, DefaultLogLevel)
	}
}

// TestNoHandlersRequestsNoLogs is the other side: a binding nobody is watching
// must not turn a server's log stream on. The stream costs the server work and
// the connection bandwidth, and it would all be discarded at the boundary.
func TestNoHandlersRequestsNoLogs(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.initResult.Capabilities.Logging = true
	tr := newFakeTransport(conn)

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	if _, calls := conn.requestedLogLevel(); calls != 0 {
		t.Errorf("a binding with no log or event handler asked the server for logs %d times, want 0", calls)
	}
	if tr.lastConfig().OnLog != nil {
		t.Error("a binding with no observers installed an OnLog callback")
	}
}

// TestProgressEventOnlyForCallsThatAskedForIt: installing an observer must not
// change what the server is asked to do. A progress token goes on the wire only
// because a caller wanted progress, never because someone is watching events.
func TestProgressEventOnlyForCallsThatAskedForIt(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.callProgress = []protocol.ProgressUpdate{{Progress: 1, Total: 2, Message: "working"}}
	tr := newFakeTransport(conn)

	rec := &eventRecorder{}
	c, err := Connect(context.Background(), okDefinition(tr), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	// No Progress callback: no token, so the server sends nothing and there is
	// nothing to mirror.
	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if got := len(eventsOf[RequestProgress](rec)); got != 0 {
		t.Errorf("RequestProgress events = %d for a call that asked for no progress, want 0", got)
	}

	// With one, the caller's callback and the event stream both see it.
	var direct int
	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{
		Progress: func(Progress) { direct++ },
	}); err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if direct != 1 {
		t.Errorf("the caller's progress callback ran %d times, want 1", direct)
	}
	events := eventsOf[RequestProgress](rec)
	if len(events) != 1 {
		t.Fatalf("RequestProgress events = %d, want 1", len(events))
	}
	if events[0].Progress != 1 || events[0].Total != 2 || events[0].Message != "working" {
		t.Errorf("RequestProgress = %+v, want the server's report", events[0])
	}
}

// readSource reads a file from this package's own directory. The tests run with
// the package dir as the working directory, so a bare name resolves.
func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}
