package catalog_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/looprig/mcp/internal/catalog"
	"github.com/looprig/mcp/internal/protocol"
)

// richBuilder returns a Builder with every digested field set to a distinctive
// non-zero value.
//
// Every field matters: the sensitivity sweep below mutates each one in turn and
// demands the digest move, which it can only do reliably if the starting value
// is not already the zero the mutation might collide with.
func richBuilder() catalog.Builder {
	return catalog.Builder{
		Binding: "github",
		Number:  4,
		// The default profile's policy: the sweep mutates raw names into shapes
		// that need normalizing, and under a strict policy Build would reject
		// them rather than digest them.
		Tolerances:      catalog.Tolerances{InvalidOutputSchema: true, NormalizeDisplayNames: true},
		ProtocolVersion: "2025-06-18",
		Capabilities: protocol.ServerCapabilities{
			Tools:              true,
			Prompts:            true,
			Resources:          true,
			ResourcesSubscribe: true,
			Logging:            true,
			Completions:        true,
		},
		Server:       protocol.ServerIdentity{Name: "srv", Version: "1.2.3", Title: "Server"},
		Instructions: "be careful",
		Tools: []protocol.ToolSpec{
			{
				RawName:      "search_issues",
				Title:        "Search issues",
				Description:  "searches",
				InputSchema:  json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
				OutputSchema: json.RawMessage(`{"type":"object"}`),
				Annotations: &protocol.ToolAnnotations{
					Title:           "Search",
					ReadOnlyHint:    true,
					IdempotentHint:  true,
					DestructiveHint: ptr(false),
					OpenWorldHint:   ptr(true),
				},
				Warnings: []string{"a warning"},
			},
			{
				RawName:     "create_issue",
				Title:       "Create issue",
				Description: "creates",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"title":{"type":"string"}}}`),
			},
		},
		Prompts: []protocol.PromptSpec{{
			RawName:     "greet",
			Title:       "Greet",
			Description: "greets",
			Arguments: []protocol.PromptArgSpec{
				{Name: "name", Title: "Name", Description: "who", Required: true},
				{Name: "mood", Title: "Mood", Description: "how", Required: false},
			},
		}},
		Resources: []protocol.ResourceSpec{{
			URI: "fixture://static/hello", Name: "hello", Title: "Hello",
			Description: "a greeting", MIMEType: "text/plain",
		}},
		ResourceTemplates: []protocol.ResourceTemplateSpec{{
			URITemplate: "fixture://echo/{word}", Name: "echo", Title: "Echo",
			Description: "echoes", MIMEType: "text/plain",
		}},
		Warnings:  []string{"discovery warning"},
		Decisions: []catalog.Decision{{Family: catalog.FamilyTools, Action: catalog.ActionFetched}},
	}
}

func ptr[T any](v T) *T { return &v }

func mustBuild(t *testing.T, b catalog.Builder) *catalog.Generation {
	t.Helper()
	g, err := b.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	return g
}

// TestDigestIsStableUnderInputOrder is the property the digest exists for: the
// same catalog content digests identically however it arrived. A server is free
// to paginate its tools in any order, and two clients that saw different orders
// must still agree on whether they are looking at the same catalog.
func TestDigestIsStableUnderInputOrder(t *testing.T) {
	t.Parallel()

	base := richBuilder()
	// Enough entries that a shuffle is very unlikely to be a no-op.
	for i := range 8 {
		base.Tools = append(base.Tools, protocol.ToolSpec{
			RawName:     fmt.Sprintf("tool_%d", i),
			Description: fmt.Sprintf("tool number %d", i),
			InputSchema: json.RawMessage(fmt.Sprintf(`{"type":"object","title":"t%d"}`, i)),
		})
		base.Prompts = append(base.Prompts, protocol.PromptSpec{
			RawName:     fmt.Sprintf("prompt_%d", i),
			Description: fmt.Sprintf("prompt number %d", i),
		})
		base.Resources = append(base.Resources, protocol.ResourceSpec{
			URI: fmt.Sprintf("fixture://r/%d", i), Name: fmt.Sprintf("r%d", i),
		})
		base.ResourceTemplates = append(base.ResourceTemplates, protocol.ResourceTemplateSpec{
			URITemplate: fmt.Sprintf("fixture://t/%d/{x}", i), Name: fmt.Sprintf("t%d", i),
		})
	}

	want := mustBuild(t, base).Digest()
	if want.IsZero() {
		t.Fatal("digest is zero; the encoding hashed nothing")
	}

	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 32 {
		shuffled := base
		shuffled.Tools = slices.Clone(base.Tools)
		shuffled.Prompts = slices.Clone(base.Prompts)
		shuffled.Resources = slices.Clone(base.Resources)
		shuffled.ResourceTemplates = slices.Clone(base.ResourceTemplates)
		rng.Shuffle(len(shuffled.Tools), reflect.Swapper(shuffled.Tools))
		rng.Shuffle(len(shuffled.Prompts), reflect.Swapper(shuffled.Prompts))
		rng.Shuffle(len(shuffled.Resources), reflect.Swapper(shuffled.Resources))
		rng.Shuffle(len(shuffled.ResourceTemplates), reflect.Swapper(shuffled.ResourceTemplates))

		if got := mustBuild(t, shuffled).Digest(); got != want {
			t.Fatalf("shuffle %d: digest = %s, want %s: the encoding depends on input order", i, got, want)
		}
	}
}

// TestDigestIgnoresNonContent pins the three exclusions computeDigest
// documents. Each is a field that must NOT move the digest, and each would
// break something real if it did: a generation number would make every
// generation differ from every other by construction, and warnings/decisions
// are derived from content the digest already covers.
func TestDigestIgnoresNonContent(t *testing.T) {
	t.Parallel()

	want := mustBuild(t, richBuilder()).Digest()

	tests := []struct {
		name   string
		mutate func(*catalog.Builder)
	}{
		{"generation number", func(b *catalog.Builder) { b.Number = 99 }},
		{"discovery warnings", func(b *catalog.Builder) { b.Warnings = []string{"totally different"} }},
		{"no warnings at all", func(b *catalog.Builder) { b.Warnings = nil }},
		{"compatibility decisions", func(b *catalog.Builder) {
			b.Decisions = []catalog.Decision{{Family: catalog.FamilyPrompts, Action: catalog.ActionSkippedNotAdvertised}}
		}},
		// Host policy, like a ToolFilter: two hosts with different
		// compatibility profiles must agree on whether they are looking at the
		// same server. What a tolerance *changed* is covered through the value
		// it changed — a normalized ModelName, an absent OutputSchema — so
		// nothing about the server's offering escapes by this exclusion.
		{"compatibility tolerances", func(b *catalog.Builder) {
			b.Tolerances = catalog.Tolerances{}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := richBuilder()
			tt.mutate(&b)
			if got := mustBuild(t, b).Digest(); got != want {
				t.Errorf("digest = %s, want %s: %s must not be part of the catalog digest", got, want, tt.name)
			}
		})
	}
}

// TestDigestIsSensitiveToEveryContentField sweeps the Builder reflectively and
// demands that mutating any field the digest is supposed to cover changes it.
//
// The sweep is the point. A hand-written list of cases only tests the fields
// someone remembered; this walks the struct, so a field added to Builder later
// and forgotten in computeDigest fails here rather than silently dropping out
// of the catalog's identity. The exclusion list is the inverse contract — a
// field named there is asserted NOT to matter (see TestDigestIgnoresNonContent)
// — so a new field is covered by default and can only escape the digest by
// someone deliberately naming it.
func TestDigestIsSensitiveToEveryContentField(t *testing.T) {
	t.Parallel()

	// The fields computeDigest deliberately excludes, with the reason. Anything
	// not named here must move the digest. Paths are matched with the "[0]"
	// element markers stripped, so naming a field covers it wherever it appears.
	excluded := map[string]string{
		"Number":                   "an ordinal, not content",
		"Warnings":                 "derived from content already covered",
		"Decisions":                "derived from capabilities already covered",
		"Tools.Warnings":           "derived: a tolerated defect is a function of what the server sent, and what survived it is already covered",
		"Tolerances":               "host policy, not server truth: see TestDigestIgnoresNonContent",
		"Tools.OutputSchemaDefect": "derived diagnostic: the schema it condemns is absent from the generation either way, which the OutputSchema presence flag already covers",
	}
	isExcluded := func(path string) bool {
		clean := strings.ReplaceAll(path, "[0]", "")
		for prefix := range excluded {
			if clean == prefix || strings.HasPrefix(clean, prefix+".") {
				return true
			}
		}
		return false
	}

	base := mustBuild(t, richBuilder()).Digest()

	swept := 0
	for _, path := range leafPaths(t, reflect.TypeOf(catalog.Builder{}), "") {
		if isExcluded(path) {
			continue
		}
		t.Run(path, func(t *testing.T) {
			b := richBuilder()
			if !mutateAt(reflect.ValueOf(&b).Elem(), path) {
				t.Fatalf("could not mutate %s: the sweep is not exercising this field", path)
			}
			got, err := b.Build()
			if err != nil {
				t.Fatalf("Build() after mutating %s: %v", path, err)
			}
			if got.Digest() == base {
				t.Errorf("mutating %s did not change the catalog digest: the field is missing from computeDigest", path)
			}
		})
		swept++
	}
	if swept == 0 {
		t.Fatal("the sweep covered no fields and would pass vacuously")
	}
	t.Logf("swept %d field path(s)", swept)
}

// leafPaths enumerates the mutable leaf field paths of a struct type, following
// nested structs, pointers, and the element type of slices. A slice leaf is
// reported both as the slice itself (so "the collection changed" is covered)
// and through its element type (so "one item's field changed" is covered).
func leafPaths(t *testing.T, typ reflect.Type, prefix string) []string {
	t.Helper()
	var paths []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		path := f.Name
		if prefix != "" {
			path = prefix + "." + f.Name
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch ft.Kind() {
		case reflect.Struct:
			paths = append(paths, leafPaths(t, ft, path)...)
		case reflect.Slice:
			// The slice itself: shrinking it must be visible.
			paths = append(paths, path)
			elem := ft.Elem()
			for elem.Kind() == reflect.Pointer {
				elem = elem.Elem()
			}
			if elem.Kind() == reflect.Struct {
				paths = append(paths, leafPaths(t, elem, path+"[0]")...)
			}
		default:
			paths = append(paths, path)
		}
	}
	return paths
}

// mutateAt changes the value at a dotted path within v, reporting whether it
// managed to. A "[0]" component steps into a slice's first element, which is
// why richBuilder must populate every collection.
func mutateAt(v reflect.Value, path string) bool {
	head, rest, _ := strings.Cut(path, ".")
	name, isElem := strings.CutSuffix(head, "[0]")

	f := v.FieldByName(name)
	if !f.IsValid() || !f.CanSet() {
		return false
	}
	for f.Kind() == reflect.Pointer {
		if f.IsNil() {
			return false
		}
		f = f.Elem()
	}
	if isElem {
		if f.Kind() != reflect.Slice || f.Len() == 0 {
			return false
		}
		elem := f.Index(0)
		for elem.Kind() == reflect.Pointer {
			if elem.IsNil() {
				return false
			}
			elem = elem.Elem()
		}
		return mutateAt(elem, rest)
	}
	if rest != "" {
		if f.Kind() != reflect.Struct {
			return false
		}
		return mutateAt(f, rest)
	}
	return setDistinct(f)
}

// setDistinct writes a value different from whatever is there now.
func setDistinct(f reflect.Value) bool {
	switch f.Kind() {
	case reflect.String:
		f.SetString(f.String() + "-mutated")
		return true
	case reflect.Bool:
		f.SetBool(!f.Bool())
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		f.SetUint(f.Uint() + 1)
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		f.SetInt(f.Int() + 1)
		return true
	case reflect.Slice:
		// json.RawMessage and []string alike: truncating a populated slice is a
		// content change whatever the element type.
		if f.Type() == reflect.TypeOf(json.RawMessage(nil)) {
			f.SetBytes([]byte(`{"type":"object","title":"mutated"}`))
			return true
		}
		if f.Len() == 0 {
			return false
		}
		f.Set(f.Slice(0, f.Len()-1))
		return true
	default:
		return false
	}
}

// TestDigestBytesIsDomainSeparated proves the schema digest and the catalog
// digest cannot be confused, and that a schema digest tracks its bytes.
func TestDigestBytesIsDomainSeparated(t *testing.T) {
	t.Parallel()

	a := catalog.DigestBytes([]byte(`{"type":"object"}`))
	b := catalog.DigestBytes([]byte(`{"type":"array"}`))
	if a == b {
		t.Error("DigestBytes returned the same digest for different bytes")
	}
	if a.IsZero() {
		t.Error("DigestBytes returned the zero digest, which means 'absent' elsewhere")
	}
	// A catalog whose only content is those bytes must not share the digest.
	g := mustBuild(t, catalog.Builder{Binding: "b"})
	if g.Digest() == catalog.DigestBytes(nil) {
		t.Error("an empty catalog digests to the same value as an empty schema: the domains are not separated")
	}
}

// TestDigestString checks the rendering used in logs and status.
func TestDigestString(t *testing.T) {
	t.Parallel()

	d := catalog.DigestBytes([]byte("x"))
	s := d.String()
	if len(s) != 64 {
		t.Errorf("String() = %q (%d chars), want 64 hex chars", s, len(s))
	}
	if strings.ToLower(s) != s {
		t.Errorf("String() = %q, want lowercase hex", s)
	}
	if short := d.Short(); !strings.HasPrefix(s, short) || len(short) != 8 {
		t.Errorf("Short() = %q, want the first 8 chars of %q", short, s)
	}
	if !(catalog.Digest{}).IsZero() {
		t.Error("the zero Digest does not report IsZero")
	}
	if d.IsZero() {
		t.Error("a real digest reports IsZero")
	}
}

// TestDigestHasNoCollisions is the unambiguity half of the digest's contract:
// no two *different* catalogs may encode to the same bytes.
//
// It is a table of PAIRS because that property cannot be tested one field at a
// time. TestDigestIsSensitiveToEveryContentField mutates a single field and
// demands the digest move, which it does under any framing at all — change a
// byte and some byte changes. The bug class this test exists for is the
// opposite shape: the framing itself. Drop the length prefix from str and
// {Title:"ab", Description:""} and {Title:"a", Description:"b"} become the same
// bytes; collapse a presence flag and "the server said nothing" becomes "the
// server said no". Every pair below is content two catalogs genuinely differ
// on, chosen so that the *only* thing keeping their encodings apart is a
// delimiter or a presence marker.
//
// The pairs are deliberately adjacent-field slides. A slide across a fixed-width
// field (a bool, a count) cannot collide however the strings are framed, so
// those are not the interesting cases and are not here.
func TestDigestHasNoCollisions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// why records the framing property the pair pins, so a failure says
		// which guarantee was dropped rather than only that two digests met.
		why  string
		a, b func(*catalog.Builder)
	}{
		{
			name: "tool title and description slide",
			why:  "str is length-delimited, so a tool's title cannot borrow its description's first byte",
			a:    func(b *catalog.Builder) { b.Tools[0].Title, b.Tools[0].Description = "ab", "c" },
			b:    func(b *catalog.Builder) { b.Tools[0].Title, b.Tools[0].Description = "a", "bc" },
		},
		{
			name: "tool title empty versus description empty",
			why:  "an empty string is a distinct encoding, not an absence that lets the next field slide up",
			a:    func(b *catalog.Builder) { b.Tools[0].Title, b.Tools[0].Description = "", "x" },
			b:    func(b *catalog.Builder) { b.Tools[0].Title, b.Tools[0].Description = "x", "" },
		},
		{
			name: "server name and version slide",
			why:  "the server identity's three fields are separately delimited",
			a: func(b *catalog.Builder) {
				b.Server = protocol.ServerIdentity{Name: "srv", Version: "1.2.3", Title: "T"}
			},
			b: func(b *catalog.Builder) {
				b.Server = protocol.ServerIdentity{Name: "srv1", Version: ".2.3", Title: "T"}
			},
		},
		{
			name: "server version and title slide",
			why:  "the version/title boundary is a delimiter, not a convention",
			a: func(b *catalog.Builder) {
				b.Server = protocol.ServerIdentity{Name: "srv", Version: "1.0", Title: "X"}
			},
			b: func(b *catalog.Builder) {
				b.Server = protocol.ServerIdentity{Name: "srv", Version: "1.0X", Title: ""}
			},
		},
		{
			name: "prompt name and title slide",
			why:  "a prompt's raw name cannot be extended into its title",
			a:    func(b *catalog.Builder) { b.Prompts[0].RawName, b.Prompts[0].Title = "ab", "c" },
			b:    func(b *catalog.Builder) { b.Prompts[0].RawName, b.Prompts[0].Title = "a", "bc" },
		},
		{
			name: "prompt title and description slide",
			why:  "the prompt title/description boundary is a delimiter",
			a:    func(b *catalog.Builder) { b.Prompts[0].Title, b.Prompts[0].Description = "ab", "c" },
			b:    func(b *catalog.Builder) { b.Prompts[0].Title, b.Prompts[0].Description = "a", "bc" },
		},
		{
			name: "prompt argument name and title slide",
			why:  "an argument's name cannot borrow bytes from its title",
			a:    func(b *catalog.Builder) { b.Prompts[0].Arguments[0].Name, b.Prompts[0].Arguments[0].Title = "ab", "c" },
			b:    func(b *catalog.Builder) { b.Prompts[0].Arguments[0].Name, b.Prompts[0].Arguments[0].Title = "a", "bc" },
		},
		{
			name: "prompt argument title and description slide",
			why:  "the argument list's strings are delimited within each argument",
			a: func(b *catalog.Builder) {
				b.Prompts[0].Arguments[1].Title, b.Prompts[0].Arguments[1].Description = "ab", "c"
			},
			b: func(b *catalog.Builder) {
				b.Prompts[0].Arguments[1].Title, b.Prompts[0].Arguments[1].Description = "a", "bc"
			},
		},
		{
			name: "resource uri and name slide",
			why:  "a resource's URI cannot run into its name",
			a:    func(b *catalog.Builder) { b.Resources[0].URI, b.Resources[0].Name = "fixture://ab", "c" },
			b:    func(b *catalog.Builder) { b.Resources[0].URI, b.Resources[0].Name = "fixture://a", "bc" },
		},
		{
			name: "resource description and mime type slide",
			why:  "the last two strings of a resource are separately delimited",
			a:    func(b *catalog.Builder) { b.Resources[0].Description, b.Resources[0].MIMEType = "ab", "c" },
			b:    func(b *catalog.Builder) { b.Resources[0].Description, b.Resources[0].MIMEType = "a", "bc" },
		},
		{
			name: "resource template uri template and name slide",
			why:  "a template's URI template cannot run into its name",
			a: func(b *catalog.Builder) {
				b.ResourceTemplates[0].URITemplate, b.ResourceTemplates[0].Name = "fixture://ab/{x}", "c"
			},
			b: func(b *catalog.Builder) {
				b.ResourceTemplates[0].URITemplate, b.ResourceTemplates[0].Name = "fixture://a", "b/{x}c"
			},
		},
		{
			name: "annotations absent versus all false",
			why:  "the presence flag keeps \"the server said nothing\" apart from \"the server said no to everything\"",
			a:    func(b *catalog.Builder) { b.Tools[0].Annotations = nil },
			b:    func(b *catalog.Builder) { b.Tools[0].Annotations = &protocol.ToolAnnotations{} },
		},
		{
			name: "annotation title and tool description slide",
			why:  "an annotation's title is delimited like any other string",
			a: func(b *catalog.Builder) {
				b.Tools[0].Annotations = &protocol.ToolAnnotations{Title: "ab"}
			},
			b: func(b *catalog.Builder) {
				b.Tools[0].Annotations = &protocol.ToolAnnotations{Title: "a"}
			},
		},
		{
			name: "destructive hint absent versus false",
			why:  "a tri-state hint is three values, not two: nil is why the SDK models it as a pointer",
			a:    func(b *catalog.Builder) { b.Tools[0].Annotations.DestructiveHint = nil },
			b:    func(b *catalog.Builder) { b.Tools[0].Annotations.DestructiveHint = ptr(false) },
		},
		{
			name: "destructive hint false versus true",
			why:  "the other two thirds of the tri-state stay apart",
			a:    func(b *catalog.Builder) { b.Tools[0].Annotations.DestructiveHint = ptr(false) },
			b:    func(b *catalog.Builder) { b.Tools[0].Annotations.DestructiveHint = ptr(true) },
		},
		{
			name: "open world hint absent versus false",
			why:  "every tri-state is encoded tri-state, not just the first one",
			a:    func(b *catalog.Builder) { b.Tools[0].Annotations.OpenWorldHint = nil },
			b:    func(b *catalog.Builder) { b.Tools[0].Annotations.OpenWorldHint = ptr(false) },
		},
		{
			name: "output schema absent versus present",
			why:  "presence is encoded explicitly, so \"no output schema\" is not any digest's encoding",
			a:    func(b *catalog.Builder) { b.Tools[0].OutputSchema = nil },
			b:    func(b *catalog.Builder) { b.Tools[0].OutputSchema = json.RawMessage(`{"type":"object"}`) },
		},
		{
			name: "capabilities absent versus one flag set",
			why:  "capability flags are fixed-width and positional; a server that advertises nothing is not one that advertises tools. A nil ServerCapabilities is not representable here — protocol reduces nil to the zero value on the way in — so all-false IS absent, and it must stay apart from every advertised flag",
			a:    func(b *catalog.Builder) { b.Capabilities = protocol.ServerCapabilities{} },
			b:    func(b *catalog.Builder) { b.Capabilities = protocol.ServerCapabilities{Tools: true} },
		},
		{
			name: "value equal to a field tag",
			why:  "a field tag is a length-delimited string like any other, so a value that spells one cannot impersonate it",
			a:    func(b *catalog.Builder) { b.Instructions = "tools" },
			b:    func(b *catalog.Builder) { b.Instructions = "" },
		},
		{
			name: "collection shrinks versus a member changing",
			why:  "the count is encoded, so dropping the last prompt is not the same catalog as blanking it",
			a:    func(b *catalog.Builder) { b.Prompts = nil },
			b:    func(b *catalog.Builder) { b.Prompts[0].Arguments = nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ba := richBuilder()
			tt.a(&ba)
			bb := richBuilder()
			tt.b(&bb)

			da := mustBuild(t, ba).Digest()
			db := mustBuild(t, bb).Digest()
			if da == db {
				t.Errorf("two different catalogs share digest %s: %s", da, tt.why)
			}
		})
	}
}

// goldenBuilder is a frozen catalog: the input half of the known-answer test
// below. It is deliberately separate from richBuilder, which the sweeps are
// free to grow — this one must never change, because changing it changes the
// answer and the whole point is that the answer cannot change by accident.
//
// It exercises every branch of the encoder: a tag, a string, an empty string, a
// count, an empty collection, a bool, a schema digest present and absent,
// annotations present and absent, and all three states of a tri-state.
func goldenBuilder() catalog.Builder {
	return catalog.Builder{
		Binding:         "golden",
		Number:          1,
		ProtocolVersion: "2025-06-18",
		Capabilities: protocol.ServerCapabilities{
			Tools: true, Prompts: true, Resources: true, Logging: true,
		},
		Server:       protocol.ServerIdentity{Name: "gold", Version: "0.1.0", Title: ""},
		Instructions: "hold still",
		Tools: []protocol.ToolSpec{
			{
				RawName:      "with_everything",
				Title:        "With everything",
				Description:  "has an output schema and annotations",
				InputSchema:  json.RawMessage(`{"type":"object"}`),
				OutputSchema: json.RawMessage(`{"type":"object"}`),
				Annotations: &protocol.ToolAnnotations{
					Title:           "Everything",
					ReadOnlyHint:    true,
					IdempotentHint:  false,
					DestructiveHint: ptr(false),
					OpenWorldHint:   ptr(true),
				},
			},
			{
				RawName:     "with_nothing",
				InputSchema: json.RawMessage(`{"type":"object"}`),
			},
		},
		Prompts: []protocol.PromptSpec{{
			RawName: "p",
			Arguments: []protocol.PromptArgSpec{
				{Name: "a", Title: "A", Description: "first", Required: true},
			},
		}},
		Resources:         []protocol.ResourceSpec{{URI: "golden://r", Name: "r"}},
		ResourceTemplates: nil,
	}
}

// TestDigestIsGolden pins the canonical encoding to a known answer.
//
// This is the guard the pairwise test structurally cannot be: with every value
// length-delimited, the encoding is already unambiguous, so dropping the field
// tags — or reordering fields, or changing a domain string — makes no two
// catalogs collide and no sensitivity or collision test can see it. What it
// does do is silently give existing content a new digest, or worse, let two
// builds disagree about the same content while digestSchemaVersion says they
// agree.
//
// So this test enforces the contract digestSchemaVersion states: if this fails,
// the encoding changed. That is allowed — but it costs a version bump and this
// constant, together, deliberately. It is not a test to "just update".
func TestDigestIsGolden(t *testing.T) {
	t.Parallel()

	const want = "28a3791f06547176ac6d39a18628782043c3061a2e6c55c15dc21736cd6a763f"
	got := mustBuild(t, goldenBuilder()).Digest().String()
	if got != want {
		t.Errorf("catalog digest = %s, want %s\n"+
			"The canonical encoding changed. If that was deliberate, bump "+
			"digestSchemaVersion and update this constant in the same change; "+
			"if it was not, the encoding has drifted and every digest an older "+
			"build computed is now wrong.", got, want)
	}
}
