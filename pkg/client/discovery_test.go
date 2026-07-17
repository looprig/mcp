package client

import (
	"context"
	"errors"
	"testing"

	"github.com/looprig/mcp/internal/protocol"
)

// TestConnectDiscoversBeforeReady is the design's discovery step 9: the catalog
// is adopted before the owner becomes ready, so anyone who sees StateReady can
// read the catalog that goes with it.
func TestConnectDiscoversBeforeReady(t *testing.T) {
	t.Parallel()

	rec := &eventRecorder{}

	conn := okConn()
	tr := newFakeTransport(conn)

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	states := rec.states()
	// Discovering must appear, and it must appear before ready.
	discovering, ready := -1, -1
	for i, s := range states {
		switch s {
		case StateDiscovering:
			discovering = i
		case StateReady:
			ready = i
		}
	}
	if discovering < 0 {
		t.Fatalf("states = %v, want StateDiscovering among them: Connect skipped discovery", states)
	}
	if ready < 0 || discovering > ready {
		t.Fatalf("states = %v, want discovering before ready", states)
	}
	if !c.Catalog().Valid() {
		t.Error("a ready binding has no adopted catalog")
	}
}

// TestConnectFailsOnDiscoveryFailure covers the unwind: a binding with no
// catalog has nothing to offer, so startup fails rather than returning a ready
// Client whose every call would fail.
//
// The conn must be closed on the way out. That is the leak this path has had
// before, and it is invisible without asserting on it: Connect returns nil, so
// nothing else holds a reference to the connection that was opened.
func TestConnectFailsOnDiscoveryFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		conn func() *fakeConn
		want FailureClass
	}{
		{
			name: "the server fails the list",
			conn: func() *fakeConn {
				c := okConn()
				c.listErr = errors.New("connection reset")
				return c
			},
			want: FailureServerProtocol,
		},
		{
			name: "the catalog is defective",
			conn: func() *fakeConn {
				c := okConn()
				// Two tools with one name: every call to it would be ambiguous.
				c.tools = []protocol.ToolSpec{fakeTool("dup"), fakeTool("dup")}
				return c
			},
			want: FailureCatalogInvalid,
		},
		{
			name: "a tool name that is not an identifier",
			conn: func() *fakeConn {
				c := okConn()
				c.tools = []protocol.ToolSpec{fakeTool("bad\x1b[31mname")}
				return c
			},
			want: FailureCatalogInvalid,
		},
		{
			name: "the transport's own typed error survives classification",
			conn: func() *fakeConn {
				c := okConn()
				c.listErr = NewError(FailureTransportClosed, "srv", "list_tools", "the process exited", nil)
				return c
			},
			want: FailureTransportClosed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := tt.conn()
			tr := newFakeTransport(conn)

			c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
			if err == nil {
				t.Fatal("Connect() succeeded despite a failed discovery")
			}
			if c != nil {
				t.Error("Connect() returned a Client alongside its error")
			}
			if class, ok := ClassOf(err); !ok || class != tt.want {
				t.Errorf("class = %v (ok=%v), want %v", class, ok, tt.want)
			}
			// The unwind closed the transport exactly once. Anything else is a
			// leaked connection nobody can reach.
			if got := conn.closeCount(); got != 1 {
				t.Errorf("conn closed %d times, want exactly 1: a failed discovery must not leak the connection", got)
			}
		})
	}
}

// TestConnectFailsOnOverLimitCatalog keeps the two catalog classes distinct: an
// over-limit catalog might be accepted with a raised bound, while a defective
// one is broken whatever the bounds are.
func TestConnectFailsOnOverLimitCatalog(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.tools = []protocol.ToolSpec{fakeTool("a"), fakeTool("b"), fakeTool("c")}
	tr := newFakeTransport(conn)

	def := okDefinition(tr)
	def.Limits.MaxCatalogItems = 2

	c, err := Connect(context.Background(), def, Handlers{})
	if err == nil {
		t.Fatal("Connect() accepted a catalog over the item bound")
	}
	if c != nil {
		t.Error("Connect() returned a Client alongside its error")
	}
	if class, _ := ClassOf(err); class != FailureCatalogOverLimit {
		t.Errorf("class = %v, want %v", class, FailureCatalogOverLimit)
	}
	if got := conn.closeCount(); got != 1 {
		t.Errorf("conn closed %d times, want exactly 1", got)
	}
}

// TestConnectPaginatesDiscovery proves the client's limits actually reach
// discovery — a multi-page server is walked to the end.
func TestConnectPaginatesDiscovery(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.toolPages = []protocol.ToolPage{
		{Tools: []protocol.ToolSpec{fakeTool("a")}, NextCursor: "p1"},
		{Tools: []protocol.ToolSpec{fakeTool("b")}, NextCursor: "p2"},
		{Tools: []protocol.ToolSpec{fakeTool("c")}},
	}
	c := connectTo(t, conn, nil)

	cat := c.Catalog()
	if len(cat.Tools) != 3 {
		t.Fatalf("Tools = %d, want 3: pagination lost a page", len(cat.Tools))
	}
	for _, want := range []string{"a", "b", "c"} {
		if _, ok := cat.ToolByRawName(want); !ok {
			t.Errorf("tool %q missing from the paginated catalog", want)
		}
	}
}

// TestConnectHonorsThePageBound proves the client's MaxCatalogPages is the one
// discovery enforces, rather than a default buried below.
func TestConnectHonorsThePageBound(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.toolPages = []protocol.ToolPage{
		{Tools: []protocol.ToolSpec{fakeTool("a")}, NextCursor: "p1"},
		{Tools: []protocol.ToolSpec{fakeTool("b")}, NextCursor: "p2"},
		{Tools: []protocol.ToolSpec{fakeTool("c")}},
	}
	def := okDefinition(newFakeTransport(conn))
	def.Limits.MaxCatalogPages = 2

	_, err := Connect(context.Background(), def, Handlers{})
	if err == nil {
		t.Fatal("Connect() accepted a catalog needing more pages than the bound allows")
	}
	if class, _ := ClassOf(err); class != FailureCatalogOverLimit {
		t.Errorf("class = %v, want %v", class, FailureCatalogOverLimit)
	}
}

// TestConnectOnlyFetchesAdvertisedFamilies is the compatibility rule at
// startup: a family the server never advertised is never fetched.
func TestConnectOnlyFetchesAdvertisedFamilies(t *testing.T) {
	t.Parallel()

	conn := okConn() // advertises tools only
	// Everything is available if asked for, so a stray fetch would show up.
	conn.prompts = []protocol.PromptSpec{{RawName: "greet"}}
	conn.resources = []protocol.ResourceSpec{{URI: "x://a"}}
	conn.templates = []protocol.ResourceTemplateSpec{{URITemplate: "x://{a}"}}

	c := connectTo(t, conn, nil)
	cat := c.Catalog()

	// Exactly one list call: tools. Prompts, resources and templates were never
	// advertised, so asking would be guessing at a method the server never
	// promised.
	if got := int(conn.lists.Load()); got != 1 {
		t.Errorf("list calls = %d, want exactly 1 (tools): an unadvertised family was fetched", got)
	}
	if len(cat.Prompts) != 0 || len(cat.Resources) != 0 || len(cat.ResourceTemplates) != 0 {
		t.Errorf("catalog carries unadvertised families: %d prompts, %d resources, %d templates",
			len(cat.Prompts), len(cat.Resources), len(cat.ResourceTemplates))
	}
	if len(cat.Tools) != 1 {
		t.Errorf("Tools = %+v, want the advertised tool", cat.Tools)
	}
}

// TestDiscoveryClass pins the mapping a caller branches on.
func TestDiscoveryClass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want FailureClass
	}{
		{"a plain error", errors.New("boom"), FailureServerProtocol},
		{"a wrapped context error", context.Canceled, FailureServerProtocol},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := discoveryClass(tt.err); got != tt.want {
				t.Errorf("discoveryClass(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestConnectCancelledDuringDiscovery: a cancelled startup is a cancellation,
// and it still closes the connection.
func TestConnectCancelledDuringDiscovery(t *testing.T) {
	t.Parallel()

	conn := okConn()
	ctx, cancel := context.WithCancel(context.Background())

	tr := newFakeTransport(conn)
	tr.beforeConnect = func() { cancel() }

	c, err := Connect(ctx, okDefinition(tr), Handlers{})
	if err == nil {
		t.Fatal("Connect() succeeded despite a cancelled context")
	}
	if c != nil {
		t.Error("Connect() returned a Client alongside its error")
	}
	if class, _ := ClassOf(err); class != FailureCancelled {
		t.Errorf("class = %v, want %v", class, FailureCancelled)
	}
}
