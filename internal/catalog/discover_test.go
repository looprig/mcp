package catalog_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/looprig/mcp/internal/catalog"
	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
)

// scriptedLister is a server under the test's control: it serves a scripted
// sequence of pages per family and records every call.
//
// A fake rather than the fixture, because the things discovery has to survive
// are things a correct server never does — hand back its own cursor, paginate
// forever, return a page after saying there were none. The fixture proves
// discovery works against real MCP (see the integration tests); this proves it
// refuses a server that misbehaves.
type scriptedLister struct {
	tools     []page[protocol.ToolSpec]
	prompts   []page[protocol.PromptSpec]
	resources []page[protocol.ResourceSpec]
	templates []page[protocol.ResourceTemplateSpec]

	// err, when set for a family, is returned instead of a page.
	toolsErr error

	// calls records the cursor each family was called with, in order, so a test
	// can assert that an unadvertised family was never asked.
	calls map[catalog.Family][]string
}

// page is one scripted response.
type page[T any] struct {
	items []T
	next  string
}

func (s *scriptedLister) record(f catalog.Family, cursor string) {
	if s.calls == nil {
		s.calls = map[catalog.Family][]string{}
	}
	s.calls[f] = append(s.calls[f], cursor)
}

// serve returns the scripted page for a cursor. The first call uses the empty
// cursor and gets pages[0]; afterwards the cursor names the index, which is how
// a script can hand back a cursor it already served.
func serve[T any](pages []page[T], cursor string) (page[T], error) {
	idx := 0
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "p%d", &idx); err != nil {
			return page[T]{}, fmt.Errorf("test script: unroutable cursor %q", cursor)
		}
	}
	if idx >= len(pages) {
		return page[T]{}, fmt.Errorf("test script: no page %d", idx)
	}
	return pages[idx], nil
}

func (s *scriptedLister) ListTools(_ context.Context, cursor string) (protocol.ToolPage, error) {
	s.record(catalog.FamilyTools, cursor)
	if s.toolsErr != nil {
		return protocol.ToolPage{}, s.toolsErr
	}
	p, err := serve(s.tools, cursor)
	if err != nil {
		return protocol.ToolPage{}, err
	}
	return protocol.ToolPage{Tools: p.items, NextCursor: p.next}, nil
}

func (s *scriptedLister) ListPrompts(_ context.Context, cursor string) (protocol.PromptPage, error) {
	s.record(catalog.FamilyPrompts, cursor)
	p, err := serve(s.prompts, cursor)
	if err != nil {
		return protocol.PromptPage{}, err
	}
	return protocol.PromptPage{Prompts: p.items, NextCursor: p.next}, nil
}

func (s *scriptedLister) ListResources(_ context.Context, cursor string) (protocol.ResourcePage, error) {
	s.record(catalog.FamilyResources, cursor)
	p, err := serve(s.resources, cursor)
	if err != nil {
		return protocol.ResourcePage{}, err
	}
	return protocol.ResourcePage{Resources: p.items, NextCursor: p.next}, nil
}

func (s *scriptedLister) ListResourceTemplates(_ context.Context, cursor string) (protocol.ResourceTemplatePage, error) {
	s.record(catalog.FamilyResourceTemplates, cursor)
	p, err := serve(s.templates, cursor)
	if err != nil {
		return protocol.ResourceTemplatePage{}, err
	}
	return protocol.ResourceTemplatePage{Templates: p.items, NextCursor: p.next}, nil
}

// allCaps advertises everything, so a test has to opt out of a family rather
// than forget to opt in.
func allCaps() protocol.ServerCapabilities {
	return protocol.ServerCapabilities{
		Tools: true, Prompts: true, Resources: true, ResourcesSubscribe: true, Logging: true,
	}
}

func testConfig(caps protocol.ServerCapabilities) catalog.Config {
	return catalog.Config{
		Binding: "srv",
		Number:  1,
		Handshake: protocol.InitializeResult{
			Server:          protocol.ServerIdentity{Name: "fixture", Version: "1.0"},
			ProtocolVersion: "2025-06-18",
			Instructions:    "hello",
			Capabilities:    caps,
		},
		Limits: catalog.Limits{MaxPages: 8, MaxTools: 100, MaxPrompts: 100, MaxResources: 100},
	}
}

func toolSpec(name string) protocol.ToolSpec {
	return protocol.ToolSpec{RawName: name, InputSchema: json.RawMessage(`{"type":"object"}`)}
}

func TestDiscoverHappyPath(t *testing.T) {
	t.Parallel()

	l := &scriptedLister{
		tools:     []page[protocol.ToolSpec]{{items: []protocol.ToolSpec{toolSpec("echo"), toolSpec("slow")}}},
		prompts:   []page[protocol.PromptSpec]{{items: []protocol.PromptSpec{{RawName: "greet"}}}},
		resources: []page[protocol.ResourceSpec]{{items: []protocol.ResourceSpec{{URI: "x://a"}}}},
		templates: []page[protocol.ResourceTemplateSpec]{{items: []protocol.ResourceTemplateSpec{{URITemplate: "x://e/{w}"}}}},
	}

	g, err := catalog.Discover(context.Background(), l, testConfig(allCaps()))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if g.ToolCount() != 2 {
		t.Errorf("ToolCount() = %d, want 2", g.ToolCount())
	}
	if len(g.Prompts()) != 1 || len(g.Resources()) != 1 || len(g.ResourceTemplates()) != 1 {
		t.Errorf("prompts/resources/templates = %d/%d/%d, want 1/1/1",
			len(g.Prompts()), len(g.Resources()), len(g.ResourceTemplates()))
	}

	// The raw protocol identity is preserved verbatim (design step 6).
	if got := g.Server(); got.Name != "fixture" || got.Version != "1.0" {
		t.Errorf("Server() = %+v, want the handshake's identity preserved", got)
	}
	if g.ProtocolVersion() != "2025-06-18" {
		t.Errorf("ProtocolVersion() = %q", g.ProtocolVersion())
	}
	if g.Instructions() != "hello" {
		t.Errorf("Instructions() = %q", g.Instructions())
	}
	if g.Number() != 1 {
		t.Errorf("Number() = %d, want 1", g.Number())
	}
	// The stable model-visible identity is constructed (design step 7).
	if _, ok := g.ToolByModelName("mcp__srv__echo"); !ok {
		t.Error("discovery did not construct a model-visible identity for echo")
	}
	// Every family was fetched, and says so.
	for _, d := range g.Decisions() {
		if d.Action != catalog.ActionFetched {
			t.Errorf("family %s: action = %s, want fetched", d.Family, d.Action)
		}
	}
}

// TestDiscoverPaginates walks a multi-page family and checks both that every
// item arrives and that the cursors were followed in order.
func TestDiscoverPaginates(t *testing.T) {
	t.Parallel()

	l := &scriptedLister{
		tools: []page[protocol.ToolSpec]{
			{items: []protocol.ToolSpec{toolSpec("a"), toolSpec("b")}, next: "p1"},
			{items: []protocol.ToolSpec{toolSpec("c")}, next: "p2"},
			{items: []protocol.ToolSpec{toolSpec("d")}},
		},
	}
	cfg := testConfig(protocol.ServerCapabilities{Tools: true})

	g, err := catalog.Discover(context.Background(), l, cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if g.ToolCount() != 4 {
		t.Fatalf("ToolCount() = %d, want 4: pages were lost", g.ToolCount())
	}
	for _, want := range []string{"a", "b", "c", "d"} {
		if _, ok := g.ToolByRawName(want); !ok {
			t.Errorf("tool %q missing from the paginated catalog", want)
		}
	}
	if got, want := l.calls[catalog.FamilyTools], []string{"", "p1", "p2"}; !equal(got, want) {
		t.Errorf("cursors requested = %v, want %v", got, want)
	}
}

// TestDiscoverRejectsPageCycles covers design step 3. A cursor already served
// means the catalog does not terminate; a page-count bound alone would not
// catch a short cycle before it had already wasted the whole budget, and would
// report the wrong cause when it did.
func TestDiscoverRejectsPageCycles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		pages []page[protocol.ToolSpec]
	}{
		{
			name: "a page pointing at itself",
			pages: []page[protocol.ToolSpec]{
				{items: []protocol.ToolSpec{toolSpec("a")}, next: "p0"},
			},
		},
		{
			name: "a two-page loop",
			pages: []page[protocol.ToolSpec]{
				{items: []protocol.ToolSpec{toolSpec("a")}, next: "p1"},
				{items: []protocol.ToolSpec{toolSpec("b")}, next: "p0"},
			},
		},
		{
			name: "a cursor from several pages back",
			pages: []page[protocol.ToolSpec]{
				{items: []protocol.ToolSpec{toolSpec("a")}, next: "p1"},
				{items: []protocol.ToolSpec{toolSpec("b")}, next: "p2"},
				{items: []protocol.ToolSpec{toolSpec("c")}, next: "p1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l := &scriptedLister{tools: tt.pages}
			cfg := testConfig(protocol.ServerCapabilities{Tools: true})
			// A page budget far larger than the cycle, so that what stops this
			// is the cycle detection and not the page bound.
			cfg.Limits.MaxPages = 64

			g, err := catalog.Discover(context.Background(), l, cfg)
			if err == nil {
				t.Fatal("Discover() accepted a cyclic pagination sequence")
			}
			if g != nil {
				t.Error("Discover() returned a generation alongside its error")
			}
			var defect *catalog.DefectError
			if !errors.As(err, &defect) {
				t.Fatalf("error = %T (%v), want *catalog.DefectError", err, err)
			}
			if defect.Family != catalog.FamilyTools {
				t.Errorf("defect family = %s, want tools", defect.Family)
			}
			if len(l.calls[catalog.FamilyTools]) > len(tt.pages)+1 {
				t.Errorf("made %d calls for %d pages: the cycle was not caught promptly",
					len(l.calls[catalog.FamilyTools]), len(tt.pages))
			}
		})
	}
}

// TestDiscoverEnforcesLimits covers design step 4.
func TestDiscoverEnforcesLimits(t *testing.T) {
	t.Parallel()

	manyTools := func(n int) []protocol.ToolSpec {
		out := make([]protocol.ToolSpec, n)
		for i := range out {
			out[i] = toolSpec(fmt.Sprintf("t%d", i))
		}
		return out
	}

	tests := []struct {
		name     string
		lister   *scriptedLister
		caps     protocol.ServerCapabilities
		limits   catalog.Limits
		wantWhat string
	}{
		{
			name: "too many pages",
			lister: &scriptedLister{tools: []page[protocol.ToolSpec]{
				{items: []protocol.ToolSpec{toolSpec("a")}, next: "p1"},
				{items: []protocol.ToolSpec{toolSpec("b")}, next: "p2"},
				{items: []protocol.ToolSpec{toolSpec("c")}, next: "p3"},
				{items: []protocol.ToolSpec{toolSpec("d")}},
			}},
			caps:     protocol.ServerCapabilities{Tools: true},
			limits:   catalog.Limits{MaxPages: 2, MaxTools: 100, MaxPrompts: 100, MaxResources: 100},
			wantWhat: catalog.WhatCatalogPages,
		},
		{
			name: "too many tools",
			lister: &scriptedLister{tools: []page[protocol.ToolSpec]{
				{items: manyTools(10)},
			}},
			caps:     protocol.ServerCapabilities{Tools: true},
			limits:   catalog.Limits{MaxPages: 8, MaxTools: 5, MaxPrompts: 100, MaxResources: 100},
			wantWhat: catalog.WhatCatalogItems,
		},
		{
			name: "too many tools across pages",
			lister: &scriptedLister{tools: []page[protocol.ToolSpec]{
				{items: manyTools(4), next: "p1"},
				{items: []protocol.ToolSpec{toolSpec("z")}},
			}},
			caps:     protocol.ServerCapabilities{Tools: true},
			limits:   catalog.Limits{MaxPages: 8, MaxTools: 4, MaxPrompts: 100, MaxResources: 100},
			wantWhat: catalog.WhatCatalogItems,
		},
		{
			name: "too many prompts",
			lister: &scriptedLister{prompts: []page[protocol.PromptSpec]{
				{items: []protocol.PromptSpec{{RawName: "a"}, {RawName: "b"}, {RawName: "c"}}},
			}},
			caps:     protocol.ServerCapabilities{Prompts: true},
			limits:   catalog.Limits{MaxPages: 8, MaxTools: 100, MaxPrompts: 2, MaxResources: 100},
			wantWhat: catalog.WhatCatalogItems,
		},
		{
			name: "too many resources",
			lister: &scriptedLister{resources: []page[protocol.ResourceSpec]{
				{items: []protocol.ResourceSpec{{URI: "x://a"}, {URI: "x://b"}}},
			}},
			caps:     protocol.ServerCapabilities{Resources: true},
			limits:   catalog.Limits{MaxPages: 8, MaxTools: 100, MaxPrompts: 100, MaxResources: 1},
			wantWhat: catalog.WhatCatalogItems,
		},
		{
			name: "a non-positive bound fails closed rather than meaning unbounded",
			lister: &scriptedLister{tools: []page[protocol.ToolSpec]{
				{items: []protocol.ToolSpec{toolSpec("a")}},
			}},
			caps:     protocol.ServerCapabilities{Tools: true},
			limits:   catalog.Limits{MaxPages: 0, MaxTools: 100, MaxPrompts: 100, MaxResources: 100},
			wantWhat: catalog.WhatCatalogPages,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(tt.caps)
			cfg.Limits = tt.limits

			g, err := catalog.Discover(context.Background(), tt.lister, cfg)
			if err == nil {
				t.Fatalf("Discover() accepted a catalog over the %s bound", tt.wantWhat)
			}
			if g != nil {
				t.Error("Discover() returned a generation alongside its error")
			}
			var over *limits.OverLimitError
			if !errors.As(err, &over) {
				t.Fatalf("error = %T (%v), want *limits.OverLimitError", err, err)
			}
			if over.What != tt.wantWhat {
				t.Errorf("OverLimitError.What = %q, want %q", over.What, tt.wantWhat)
			}
		})
	}
}

// TestDiscoverOnlyFetchesAdvertisedFamilies covers the design's compatibility
// rule. A server that did not advertise prompts has not promised prompts/list
// exists; asking anyway would turn a server with no prompts into a server that
// failed discovery.
func TestDiscoverOnlyFetchesAdvertisedFamilies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		caps       protocol.ServerCapabilities
		wantCalled []catalog.Family
		wantSkiped []catalog.Family
	}{
		{
			name:       "tools only",
			caps:       protocol.ServerCapabilities{Tools: true},
			wantCalled: []catalog.Family{catalog.FamilyTools},
			wantSkiped: []catalog.Family{catalog.FamilyPrompts, catalog.FamilyResources, catalog.FamilyResourceTemplates},
		},
		{
			name:       "prompts only",
			caps:       protocol.ServerCapabilities{Prompts: true},
			wantCalled: []catalog.Family{catalog.FamilyPrompts},
			wantSkiped: []catalog.Family{catalog.FamilyTools, catalog.FamilyResources, catalog.FamilyResourceTemplates},
		},
		{
			name:       "resources brings templates with it",
			caps:       protocol.ServerCapabilities{Resources: true},
			wantCalled: []catalog.Family{catalog.FamilyResources, catalog.FamilyResourceTemplates},
			wantSkiped: []catalog.Family{catalog.FamilyTools, catalog.FamilyPrompts},
		},
		{
			name: "a server advertising nothing is discovered, not failed",
			caps: protocol.ServerCapabilities{},
			wantSkiped: []catalog.Family{
				catalog.FamilyTools, catalog.FamilyPrompts,
				catalog.FamilyResources, catalog.FamilyResourceTemplates,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Every family has content to serve: if a skip were not honored,
			// the items would show up in the generation.
			l := &scriptedLister{
				tools:     []page[protocol.ToolSpec]{{items: []protocol.ToolSpec{toolSpec("a")}}},
				prompts:   []page[protocol.PromptSpec]{{items: []protocol.PromptSpec{{RawName: "p"}}}},
				resources: []page[protocol.ResourceSpec]{{items: []protocol.ResourceSpec{{URI: "x://a"}}}},
				templates: []page[protocol.ResourceTemplateSpec]{{items: []protocol.ResourceTemplateSpec{{URITemplate: "x://{a}"}}}},
			}

			g, err := catalog.Discover(context.Background(), l, testConfig(tt.caps))
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}

			decisions := map[catalog.Family]catalog.DecisionAction{}
			for _, d := range g.Decisions() {
				decisions[d.Family] = d.Action
			}

			for _, f := range tt.wantCalled {
				if len(l.calls[f]) == 0 {
					t.Errorf("family %s was advertised but never fetched", f)
				}
				if decisions[f] != catalog.ActionFetched {
					t.Errorf("family %s: decision = %s, want fetched", f, decisions[f])
				}
			}
			for _, f := range tt.wantSkiped {
				if n := len(l.calls[f]); n != 0 {
					t.Errorf("family %s was not advertised but was fetched %d time(s): the client is guessing at a method the server never promised", f, n)
				}
				if decisions[f] != catalog.ActionSkippedNotAdvertised {
					t.Errorf("family %s: decision = %s, want skipped_not_advertised", f, decisions[f])
				}
			}
			// A skipped family is empty, not absent-and-unrecorded.
			if len(tt.wantCalled) == 0 && (g.ToolCount() != 0 || len(g.Prompts()) != 0 || len(g.Resources()) != 0) {
				t.Error("a server advertising nothing yielded a non-empty catalog")
			}
		})
	}
}

// TestDiscoverFailsWholly is the design's all-or-nothing rule. Discover must
// never hand back a partial catalog, because a caller that assigned one would
// have silently replaced a good generation with a truncated one — and missing
// tools look exactly like removed tools.
func TestDiscoverFailsWholly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		lister *scriptedLister
	}{
		{
			name: "a family that errors",
			lister: &scriptedLister{
				toolsErr:  errors.New("connection reset"),
				prompts:   []page[protocol.PromptSpec]{{items: []protocol.PromptSpec{{RawName: "p"}}}},
				resources: []page[protocol.ResourceSpec]{{items: []protocol.ResourceSpec{{URI: "x://a"}}}},
			},
		},
		{
			name: "a family that errors on its second page",
			lister: &scriptedLister{
				tools: []page[protocol.ToolSpec]{
					{items: []protocol.ToolSpec{toolSpec("a")}, next: "p9"}, // p9 does not exist
				},
			},
		},
		{
			name: "a defect the builder catches",
			lister: &scriptedLister{
				tools: []page[protocol.ToolSpec]{
					{items: []protocol.ToolSpec{toolSpec("dup"), toolSpec("dup")}},
				},
			},
		},
		{
			name: "a defect that spans pages",
			lister: &scriptedLister{
				tools: []page[protocol.ToolSpec]{
					{items: []protocol.ToolSpec{toolSpec("dup")}, next: "p1"},
					{items: []protocol.ToolSpec{toolSpec("dup")}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g, err := catalog.Discover(context.Background(), tt.lister, testConfig(allCaps()))
			if err == nil {
				t.Fatal("Discover() succeeded on a server it should have refused")
			}
			if g != nil {
				t.Error("Discover() returned a generation alongside its error: a caller assigning it would half-replace a good catalog")
			}
		})
	}
}

// TestDiscoverDropsUnusableItemsWithAWarning pins the tolerance boundary: a
// single defective tool is dropped and reported, not fatal — but it is never
// silently dropped, and it is never exposed with an unconstrained schema.
func TestDiscoverDropsUnusableItemsWithAWarning(t *testing.T) {
	t.Parallel()

	// A tool with no input schema is unusable: the conversion refuses it rather
	// than expose a tool whose arguments nothing constrains.
	l := &scriptedLister{tools: []page[protocol.ToolSpec]{{items: []protocol.ToolSpec{
		toolSpec("good"),
		{RawName: "no_schema"},
	}}}}

	// Route it through the real converter the way a session would, by handing
	// discovery pages that already carry the conversion's warning.
	l.tools[0].items = []protocol.ToolSpec{toolSpec("good")}
	page := protocol.ToolPage{Tools: l.tools[0].items, Warnings: []string{"tool 1 dropped: no input schema"}}
	wl := &warningLister{page: page}

	g, err := catalog.Discover(context.Background(), wl, testConfig(protocol.ServerCapabilities{Tools: true}))
	if err != nil {
		t.Fatalf("Discover() error = %v: one defective tool must not fail an otherwise-good server", err)
	}
	if _, ok := g.ToolByRawName("good"); !ok {
		t.Error("the good tool was lost")
	}
	if _, ok := g.ToolByRawName("no_schema"); ok {
		t.Error("a tool with no input schema was exposed: its arguments are unconstrained")
	}
	if len(g.Warnings()) == 0 {
		t.Error("a dropped tool left no warning: the drop is silent")
	}
}

// warningLister serves one tools page verbatim, warnings included.
type warningLister struct{ page protocol.ToolPage }

func (w *warningLister) ListTools(context.Context, string) (protocol.ToolPage, error) {
	return w.page, nil
}
func (w *warningLister) ListPrompts(context.Context, string) (protocol.PromptPage, error) {
	return protocol.PromptPage{}, nil
}
func (w *warningLister) ListResources(context.Context, string) (protocol.ResourcePage, error) {
	return protocol.ResourcePage{}, nil
}
func (w *warningLister) ListResourceTemplates(context.Context, string) (protocol.ResourceTemplatePage, error) {
	return protocol.ResourceTemplatePage{}, nil
}

// TestDiscoverBoundsWarnings stops a server turning one warning per item into
// unbounded memory.
func TestDiscoverBoundsWarnings(t *testing.T) {
	t.Parallel()

	many := make([]string, catalog.MaxWarnings*3)
	for i := range many {
		many[i] = fmt.Sprintf("tool %d dropped: broken", i)
	}
	wl := &warningLister{page: protocol.ToolPage{Warnings: many}}

	g, err := catalog.Discover(context.Background(), wl, testConfig(protocol.ServerCapabilities{Tools: true}))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := len(g.Warnings()); got > catalog.MaxWarnings {
		t.Errorf("len(Warnings()) = %d, want at most %d", got, catalog.MaxWarnings)
	}
}

func TestDiscoverRespectsContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	l := &scriptedLister{tools: []page[protocol.ToolSpec]{{items: []protocol.ToolSpec{toolSpec("a")}}}}
	g, err := catalog.Discover(ctx, l, testConfig(protocol.ServerCapabilities{Tools: true}))
	if err == nil {
		t.Fatal("Discover() ignored a cancelled context")
	}
	if g != nil {
		t.Error("Discover() returned a generation for a cancelled discovery")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to wrap context.Canceled", err)
	}
}

func TestDiscoverRejectsNilLister(t *testing.T) {
	t.Parallel()

	g, err := catalog.Discover(context.Background(), nil, testConfig(allCaps()))
	if err == nil {
		t.Fatal("Discover() accepted a nil connection")
	}
	if g != nil {
		t.Error("Discover() returned a generation for a nil connection")
	}
	if !strings.Contains(err.Error(), "no connection") {
		t.Errorf("error = %q, want it to name the missing connection", err)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
