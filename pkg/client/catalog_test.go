package client

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/looprig/mcp/internal/protocol"
)

func TestCatalogAfterConnect(t *testing.T) {
	t.Parallel()

	conn := allCapsConn()
	conn.tools = []protocol.ToolSpec{
		{
			RawName:      "search_issues",
			Title:        "Search",
			Description:  "searches",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			OutputSchema: json.RawMessage(`{"type":"object"}`),
			Annotations:  &protocol.ToolAnnotations{ReadOnlyHint: true},
		},
		{RawName: "create_issue", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
	conn.prompts = []protocol.PromptSpec{{
		RawName:   "greet",
		Arguments: []protocol.PromptArgSpec{{Name: "name", Required: true}},
	}}
	conn.resources = []protocol.ResourceSpec{{URI: "x://a", Name: "a", MIMEType: "text/plain"}}
	conn.templates = []protocol.ResourceTemplateSpec{{URITemplate: "x://e/{w}", Name: "echo"}}
	conn.initResult.Instructions = "be careful"

	c := connectTo(t, conn, nil)
	cat := c.Catalog()

	if !cat.Valid() {
		t.Fatal("Catalog() from a ready binding is not Valid")
	}
	if cat.Binding != "srv" {
		t.Errorf("Binding = %q", cat.Binding)
	}
	if cat.Generation != 1 {
		t.Errorf("Generation = %d, want the first generation to be 1", cat.Generation)
	}
	if len(cat.Digest) != 64 {
		t.Errorf("Digest = %q, want a 64-char hex digest", cat.Digest)
	}
	if cat.ProtocolVersion != "2025-06-18" {
		t.Errorf("ProtocolVersion = %q", cat.ProtocolVersion)
	}
	if cat.Instructions != "be careful" {
		t.Errorf("Instructions = %q, want the server's hint reported", cat.Instructions)
	}
	if !cat.Capabilities.Tools || !cat.Capabilities.ResourcesSubscribe {
		t.Errorf("Capabilities = %+v, want what the server advertised", cat.Capabilities)
	}

	if len(cat.Tools) != 2 {
		t.Fatalf("Tools = %d, want 2", len(cat.Tools))
	}
	// Canonical order, from the generation.
	if cat.Tools[0].RawName != "create_issue" || cat.Tools[1].RawName != "search_issues" {
		t.Errorf("tools are not in canonical order: %s, %s", cat.Tools[0].RawName, cat.Tools[1].RawName)
	}

	search, ok := cat.ToolByRawName("search_issues")
	if !ok {
		t.Fatal("ToolByRawName(search_issues) not found")
	}
	if search.ModelName != "mcp__srv__search_issues" {
		t.Errorf("ModelName = %q", search.ModelName)
	}
	if len(search.InputSchemaDigest) != 64 {
		t.Errorf("InputSchemaDigest = %q, want a hex digest", search.InputSchemaDigest)
	}
	if len(search.OutputSchemaDigest) != 64 {
		t.Errorf("OutputSchemaDigest = %q, want a hex digest", search.OutputSchemaDigest)
	}
	if search.Annotations == nil || !search.Annotations.ReadOnlyHint {
		t.Errorf("Annotations = %+v, want the server's hints", search.Annotations)
	}

	// A tool with no output schema reports an empty digest, not 64 zeros: an
	// all-zero digest would read as a real one.
	create, _ := cat.ToolByRawName("create_issue")
	if create.OutputSchemaDigest != "" {
		t.Errorf("OutputSchemaDigest = %q, want empty for a tool with no output schema", create.OutputSchemaDigest)
	}

	if got, ok := cat.ToolByModelName("mcp__srv__search_issues"); !ok || got.RawName != "search_issues" {
		t.Errorf("ToolByModelName resolved to %+v, %v", got, ok)
	}
	if _, ok := cat.ToolByModelName("nope"); ok {
		t.Error("ToolByModelName found a tool that does not exist")
	}

	if len(cat.Prompts) != 1 || cat.Prompts[0].Name != "greet" {
		t.Fatalf("Prompts = %+v", cat.Prompts)
	}
	if len(cat.Prompts[0].Arguments) != 1 || !cat.Prompts[0].Arguments[0].Required {
		t.Errorf("prompt arguments = %+v, want the required one preserved", cat.Prompts[0].Arguments)
	}
	if len(cat.Resources) != 1 || cat.Resources[0].URI != "x://a" {
		t.Errorf("Resources = %+v", cat.Resources)
	}
	if len(cat.ResourceTemplates) != 1 || cat.ResourceTemplates[0].URITemplate != "x://e/{w}" {
		t.Errorf("ResourceTemplates = %+v", cat.ResourceTemplates)
	}
}

// TestCatalogAppliesTheToolFilter is the projection decision: the generation
// holds what the server offered, and this view shows what the model may see.
func TestCatalogAppliesTheToolFilter(t *testing.T) {
	t.Parallel()

	newConn := func() *fakeConn {
		conn := okConn()
		conn.tools = []protocol.ToolSpec{
			fakeTool("read"), fakeTool("write"), fakeTool("delete"),
		}
		return conn
	}

	tests := []struct {
		name   string
		filter ToolFilter
		want   []string
	}{
		{"no filter shows everything", ToolFilter{}, []string{"delete", "read", "write"}},
		{"deny removes one", ToolFilter{Deny: []string{"delete"}}, []string{"read", "write"}},
		{"allow restricts to a set", ToolFilter{Allow: []string{"read"}}, []string{"read"}},
		{"deny beats allow", ToolFilter{Allow: []string{"read", "delete"}, Deny: []string{"delete"}}, []string{"read"}},
		{"everything denied", ToolFilter{Allow: []string{"nothing"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := newConn()
			c := connectTo(t, conn, func(d *Definition) { d.ToolFilter = tt.filter })
			cat := c.Catalog()

			var got []string
			for _, tool := range cat.Tools {
				got = append(got, tool.RawName)
			}
			if !equalStrs(got, tt.want) {
				t.Errorf("Tools = %v, want %v", got, tt.want)
			}
			// The catalog is still a real catalog even when the filter empties
			// it: a binding with no permitted tools is configured, not broken.
			if !cat.Valid() {
				t.Error("a filtered catalog reports itself invalid")
			}
		})
	}
}

// TestCatalogDigestIgnoresTheFilter: the digest identifies the server's
// offering, so two hosts with different policies must agree on it. If the
// filter moved the digest, a shared cache keyed on it would be wrong and
// change-detection would fire on a config edit.
func TestCatalogDigestIgnoresTheFilter(t *testing.T) {
	t.Parallel()

	newConn := func() *fakeConn {
		conn := okConn()
		conn.tools = []protocol.ToolSpec{fakeTool("read"), fakeTool("write")}
		return conn
	}

	unfiltered := connectTo(t, newConn(), nil).Catalog()
	filtered := connectTo(t, newConn(), func(d *Definition) {
		d.ToolFilter = ToolFilter{Deny: []string{"write"}}
	}).Catalog()

	if unfiltered.Digest != filtered.Digest {
		t.Errorf("digests differ (%s vs %s): the host's filter changed the identity of the server's catalog",
			unfiltered.Digest, filtered.Digest)
	}
	// ...and the filter did do something, or this test proves nothing.
	if len(filtered.Tools) == len(unfiltered.Tools) {
		t.Fatal("the filter removed nothing; the digest comparison is vacuous")
	}
}

// TestCatalogBeforeReadyAndAfterClose pins the two edges the API has to define.
func TestCatalogBeforeReadyAndAfterClose(t *testing.T) {
	t.Parallel()

	t.Run("before discovery there is no catalog", func(t *testing.T) {
		t.Parallel()
		// A Client that has not started: Connect never hands one of these out,
		// so this is reachable only from inside the package — which is exactly
		// why the zero value has to be defined rather than assumed impossible.
		c := newClient(okDefinition(newFakeTransport(okConn())).normalized(), Handlers{})
		cat := c.Catalog()
		if cat.Valid() {
			t.Error("a binding that never discovered reports a valid catalog")
		}
		if cat.Generation != 0 || cat.Digest != "" || len(cat.Tools) != 0 {
			t.Errorf("Catalog() = %+v, want the zero Catalog", cat)
		}
	})

	t.Run("after close the last catalog remains readable", func(t *testing.T) {
		t.Parallel()
		conn := okConn()
		c := connectTo(t, conn, nil)
		before := c.Catalog()

		if err := c.Close(context.Background()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}

		after := c.Catalog()
		if !after.Valid() {
			t.Fatal("Catalog() went blank after Close: a snapshot of what a server offered stays true after the connection ends")
		}
		if after.Digest != before.Digest || len(after.Tools) != len(before.Tools) {
			t.Errorf("Catalog() changed across Close: %+v vs %+v", after, before)
		}
		// Reading it must not imply the binding is usable — every call path
		// refuses a closed binding, which TestCallsAfterCloseAreRefused proves.
		if c.Status().State != StateClosed {
			t.Errorf("State = %v, want closed", c.Status().State)
		}
	})
}

// TestCatalogIsASnapshot: the returned value must share nothing with the
// client, or a caller could rewrite the catalog every other caller reads.
func TestCatalogIsASnapshot(t *testing.T) {
	t.Parallel()

	conn := allCapsConn()
	conn.tools = []protocol.ToolSpec{{
		RawName:     "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Annotations: &protocol.ToolAnnotations{ReadOnlyHint: true},
		Warnings:    []string{"a warning"},
	}}
	c := connectTo(t, conn, nil)

	first := c.Catalog()
	first.Tools[0].RawName = "hijacked"
	first.Tools[0].InputSchema[0] = 'X'
	first.Tools[0].Annotations.ReadOnlyHint = false
	first.Tools[0].Warnings[0] = "hijacked"
	first.Prompts = nil
	first.Instructions = "hijacked"

	second := c.Catalog()
	if second.Tools[0].RawName != "echo" {
		t.Error("Catalog() aliases the client's tools: a caller renamed one in place")
	}
	if second.Tools[0].InputSchema[0] == 'X' {
		t.Error("Catalog() aliases the client's schemas")
	}
	if !second.Tools[0].Annotations.ReadOnlyHint {
		t.Error("Catalog() aliases the client's annotations: a caller flipped a hint")
	}
	if second.Tools[0].Warnings[0] == "hijacked" {
		t.Error("Catalog() aliases the client's warnings")
	}
	if len(second.Prompts) == 0 {
		t.Error("Catalog() aliases the client's prompt list")
	}
	if second.Instructions == "hijacked" {
		t.Error("Catalog() aliases the client's instructions")
	}
}

// TestCatalogValid distinguishes "no catalog" from "an empty one". A server
// that legitimately offers nothing is still discovered.
func TestCatalogValid(t *testing.T) {
	t.Parallel()

	conn := okConn()
	conn.initResult.Capabilities = protocol.ServerCapabilities{}
	conn.tools = nil
	c := connectTo(t, conn, nil)

	cat := c.Catalog()
	if !cat.Valid() {
		t.Error("a server that advertises nothing produced an invalid catalog; it should produce an empty one")
	}
	if len(cat.Tools) != 0 {
		t.Errorf("Tools = %+v, want none", cat.Tools)
	}
	if (Catalog{}).Valid() {
		t.Error("the zero Catalog reports itself Valid")
	}
}

func equalStrs(a, b []string) bool {
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
