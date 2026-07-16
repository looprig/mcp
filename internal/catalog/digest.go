// This file defines the catalog's content addressing: the Digest type and the
// canonical encoding the catalog digest is computed over.
//
// The encoding exists to make one question cheap and exact: is this catalog the
// same catalog as that one? Everything about it is in service of two properties
// that a naive hash of a struct does not have.
//
//   - Determinism. The same catalog content must produce the same digest
//     however it arrived — whatever order the server paginated its tools in,
//     whatever order a map happened to iterate. Collections are therefore
//     ordered canonically before they are encoded (see catalog.go), and no map
//     is ever ranged over here.
//   - Unambiguity. No two *different* catalogs may encode to the same bytes.
//     Every value is length-delimited and preceded by a field tag, so the
//     fields cannot be slid into one another: {Name:"ab", Title:""} and
//     {Name:"a", Title:"b"} are distinct encodings, where a naive
//     concatenation would render both as "ab".
//
// The scheme follows the fingerprint guidance in the session-versioning design:
// explicit domain, explicit schema version, stable field ordering,
// length-delimited values, deterministic collection ordering.

package catalog

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// Digest is a SHA-256 digest. It is a value type, so it can be compared with
// ==, used as a map key, and copied out of an immutable Generation without a
// clone.
type Digest [sha256.Size]byte

// String renders the digest as lowercase hex.
func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// IsZero reports whether d is the zero digest, which this package uses to mean
// "absent" (see Tool.OutputSchemaDigest). It is not a digest any input can
// produce in practice: a preimage for the zero digest is not known.
func (d Digest) IsZero() bool { return d == Digest{} }

// Short renders the first ShortDigestBytes bytes as hex. It is for a name
// suffix and a human-readable label — never for an equality check, which must
// always compare the whole digest.
func (d Digest) Short() string { return hex.EncodeToString(d[:ShortDigestBytes]) }

// ShortDigestBytes is how much of a digest Short renders. Four bytes (eight hex
// characters) is a disambiguation suffix, not a security boundary: it only has
// to separate a handful of tool names that already collide within one server,
// where the alternative is an arbitrary winner.
const ShortDigestBytes = 4

// DigestBytes returns the digest of a raw byte string, domain-separated from
// the catalog encoding so that a schema document can never be confused with a
// catalog that happens to contain the same bytes.
func DigestBytes(b []byte) Digest {
	h := sha256.New()
	e := encoder{h: h}
	e.str(domainSchema)
	e.uint(digestSchemaVersion)
	e.bytes(b)
	return sum(h)
}

// digestName returns the digest of a raw tool name, for the disambiguation
// suffix in identity.go. It has its own domain: a name and a schema that happen
// to share bytes must not share a digest.
func digestName(binding, rawName string) Digest {
	h := sha256.New()
	e := encoder{h: h}
	e.str(domainName)
	e.uint(digestSchemaVersion)
	e.str(binding)
	e.str(rawName)
	return sum(h)
}

// The domain tags. Each names one kind of thing that gets digested, so that two
// different kinds can never produce the same digest from the same bytes.
const (
	domainCatalog = "looprig.mcp.catalog"
	domainSchema  = "looprig.mcp.catalog.schema"
	domainName    = "looprig.mcp.catalog.name"
)

// digestSchemaVersion is the version of the encoding below. Bump it whenever
// the encoding changes in a way that would give existing content a new digest,
// so that a digest computed by an old build is never mistaken for one computed
// by a new one.
const digestSchemaVersion = 1

// Field tags. Each is written before its value, so that adding, removing or
// reordering a field changes the encoding rather than silently re-interpreting
// a neighbour's bytes. The strings are part of the digest's definition: change
// one and every digest changes, so bump digestSchemaVersion with it.
const (
	tagBinding         = "binding"
	tagProtocolVersion = "protocol_version"
	tagCapabilities    = "capabilities"
	tagServer          = "server"
	tagInstructions    = "instructions"
	tagTools           = "tools"
	tagPrompts         = "prompts"
	tagResources       = "resources"
	tagTemplates       = "resource_templates"
	tagAnnotations     = "annotations"
	tagArguments       = "arguments"
	tagEnd             = "end"
)

// computeDigest returns the canonical catalog digest.
//
// What it covers is what makes two catalogs the same catalog: the binding, the
// negotiated protocol and capabilities, the server's identity, the instructions,
// and every advertised tool, prompt, resource and template — tools by their
// schema *digests* rather than their schema bytes, per the design's catalog
// model.
//
// Three things are deliberately excluded, each because including it would make
// the digest answer a different question than the one it is asked:
//
//   - Generation.number is an ordinal, not content. Including it would make
//     every generation differ from every other by construction, which is
//     exactly the comparison the digest exists to perform (design §Change
//     notifications step 5: compare the candidate with the current generation).
//   - Warnings and decisions are derived: they are a deterministic function of
//     the content and the capabilities, both already covered. Including them
//     could not distinguish two catalogs that the content does not already
//     distinguish. This covers a tool's own Warnings as well as the
//     generation's. Two servers can produce identical catalog content with
//     different warnings — one dropped an oversized output schema, the other
//     never sent one — but a dropped schema is absent either way, so the tools
//     in force are the same tools and a model would see no difference. The
//     warning explains the catalog; it is not part of its identity.
//   - Host policy — a ToolFilter — is not in a Generation at all (see the
//     package doc). Two hosts with different filters see the same server and
//     must agree on its digest.
//
// Schema digests rather than schema bytes means the digest is byte-level, not
// semantic: a server that re-serializes an identical schema with different key
// order produces a new digest. That is the conservative direction — a spurious
// change costs a re-validation, where a missed one would silently apply an old
// schema to a new tool.
func (g *Generation) computeDigest() Digest {
	h := sha256.New()
	e := encoder{h: h}

	e.str(domainCatalog)
	e.uint(digestSchemaVersion)

	e.field(tagBinding)
	e.str(g.binding)

	e.field(tagProtocolVersion)
	e.str(string(g.protocolVersion))

	e.field(tagCapabilities)
	c := g.capabilities
	e.bool(c.Tools)
	e.bool(c.Prompts)
	e.bool(c.Resources)
	e.bool(c.ResourcesSubscribe)
	e.bool(c.Logging)
	e.bool(c.Completions)

	e.field(tagServer)
	e.str(g.server.Name)
	e.str(g.server.Version)
	e.str(g.server.Title)

	e.field(tagInstructions)
	e.str(g.instructions)

	e.field(tagTools)
	e.count(len(g.tools))
	for _, t := range g.tools {
		e.str(t.RawName)
		e.str(t.ModelName)
		e.str(t.Title)
		e.str(t.Description)
		e.bytes(t.InputSchemaDigest[:])
		// Presence is encoded explicitly rather than implied by a zero digest,
		// so that "no output schema" is a distinct encoding from any digest.
		e.bool(!t.OutputSchemaDigest.IsZero())
		e.bytes(t.OutputSchemaDigest[:])
		e.field(tagAnnotations)
		e.annotations(t)
	}

	e.field(tagPrompts)
	e.count(len(g.prompts))
	for _, p := range g.prompts {
		e.str(p.RawName)
		e.str(p.Title)
		e.str(p.Description)
		e.field(tagArguments)
		// Argument order is content, not incidental ordering: it comes from one
		// prompt object the server sent, so a server that reorders its
		// arguments has changed the prompt. It is encoded as sent.
		e.count(len(p.Arguments))
		for _, a := range p.Arguments {
			e.str(a.Name)
			e.str(a.Title)
			e.str(a.Description)
			e.bool(a.Required)
		}
	}

	e.field(tagResources)
	e.count(len(g.resources))
	for _, r := range g.resources {
		e.str(r.URI)
		e.str(r.Name)
		e.str(r.Title)
		e.str(r.Description)
		e.str(r.MIMEType)
	}

	e.field(tagTemplates)
	e.count(len(g.templates))
	for _, t := range g.templates {
		e.str(t.URITemplate)
		e.str(t.Name)
		e.str(t.Title)
		e.str(t.Description)
		e.str(t.MIMEType)
	}

	e.field(tagEnd)
	return sum(h)
}

// annotations encodes a tool's hints. A nil Annotations is encoded as a
// distinct absence rather than as an all-false struct: "the server said
// nothing" and "the server said no to everything" are different claims.
func (e *encoder) annotations(t Tool) {
	if t.Annotations == nil {
		e.bool(false)
		return
	}
	e.bool(true)
	a := t.Annotations
	e.str(a.Title)
	e.bool(a.ReadOnlyHint)
	e.bool(a.IdempotentHint)
	e.triState(a.DestructiveHint)
	e.triState(a.OpenWorldHint)
}

// sum finalizes a hash into a Digest.
func sum(h hash.Hash) Digest {
	var d Digest
	// Sum appends to its argument; a zero-length slice of the array's own
	// backing store writes the digest straight into d.
	h.Sum(d[:0])
	return d
}

// encoder writes the canonical encoding into a hash. Every method is
// length-delimited or fixed-width, so the concatenation of any sequence of
// calls is unambiguous.
//
// It writes to a hash.Hash, which never errors (hash.Hash's Write contract
// forbids it), so no method here returns one. That is the reason the encoder
// is not an io.Writer wrapper with error plumbing nobody could act on.
type encoder struct {
	h hash.Hash
}

// field writes a field tag. It is a length-delimited string like any other,
// which is enough to separate fields: a tag can never be confused with a value
// because the reader (there is none — this is one-way) would need the same
// framing either way, and the hash sees a different byte sequence regardless.
func (e *encoder) field(tag string) { e.str(tag) }

// str writes a length-delimited string.
func (e *encoder) str(s string) {
	e.length(len(s))
	_, _ = e.h.Write([]byte(s))
}

// bytes writes a length-delimited byte string.
func (e *encoder) bytes(b []byte) {
	e.length(len(b))
	_, _ = e.h.Write(b)
}

// uint writes a fixed-width unsigned integer. Fixed-width rather than varint:
// the width is then never a function of the value, so no encoding of one
// integer can be a prefix of the encoding of another.
func (e *encoder) uint(u uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], u)
	_, _ = e.h.Write(buf[:])
}

// count writes a collection's length.
func (e *encoder) count(n int) { e.length(n) }

// length writes a value's byte length: the delimiter every str and bytes call
// depends on, and the collection size every loop depends on.
//
// Every caller passes a len(), which is never negative, so the guard below is
// unreachable. It is written as a guard rather than asserted in a comment
// because the conversion to uint64 is the one place a negative would not fail
// loudly — it would wrap to an enormous length and silently produce a digest
// for a framing that never existed.
func (e *encoder) length(n int) {
	if n < 0 {
		n = 0
	}
	e.uint(uint64(n))
}

// bool writes a single byte.
func (e *encoder) bool(b bool) {
	var v byte
	if b {
		v = 1
	}
	_, _ = e.h.Write([]byte{v})
}

// triState writes an optional bool in one byte, keeping "absent" distinct from
// "false" — which is the whole reason the SDK models these hints as pointers.
func (e *encoder) triState(p *bool) {
	switch {
	case p == nil:
		_, _ = e.h.Write([]byte{0})
	case *p:
		_, _ = e.h.Write([]byte{2})
	default:
		_, _ = e.h.Write([]byte{1})
	}
}
