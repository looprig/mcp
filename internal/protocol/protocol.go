// Package protocol is the module-internal boundary between transports and the
// client. It is the only package (besides pkg/transport/*) allowed to import
// the MCP go-sdk.
//
// Its job is to convert SDK values into the module-neutral types declared
// here, so that no SDK type ever reaches a pkg/... exported API. Everything
// crossing this boundary comes from an untrusted server: conversions bound it
// (see Bounds) before retaining it, copy every slice and map they keep, and
// never panic on a malformed or nil input.
//
// This package must not import pkg/client: the client maps its own Limits into
// the narrow Bounds view below and passes it down.
package protocol

import (
	"context"
	"encoding/json"
)

// Conn is an established connection to an MCP server. A Conn is transport-
// agnostic: everything it returns has already been converted to the neutral,
// bounded types in this package, so no caller above it ever names an SDK type.
//
// A Conn is single-use for Initialize: the MCP handshake happens once per
// connection. Close is idempotent from the caller's point of view — the client
// guarantees it calls it at most once — and must never panic on a connection
// that was never initialized.
type Conn interface {
	// Initialize performs the MCP handshake and reports what the server said
	// about itself. Everything in the result is server-supplied and untrusted;
	// implementations bound it against the ConnectConfig Bounds before
	// returning it.
	Initialize(ctx context.Context) (InitializeResult, error)
	// Close releases the connection's resources.
	Close(ctx context.Context) error
}

// ClientIdentity is what this client tells a server it is. It is cosmetic and
// carries no authority; it must never carry a credential.
type ClientIdentity struct {
	Name    string
	Version string
	Title   string
}

// ClientCapabilities are the optional client-side capabilities to advertise on
// a connection. The client only sets a field when the application both asked
// for the capability and installed a handler able to serve it, so a transport
// may advertise these verbatim.
type ClientCapabilities struct {
	Elicitation bool
	Sampling    bool
	Roots       bool
}

// ConnectConfig carries the client-side connection parameters a transport
// needs. It is secret-free by construction: credentials reach a transport
// through its own configuration, never through this struct.
type ConnectConfig struct {
	// Client identifies this client to the server.
	Client ClientIdentity
	// Capabilities are the client capabilities to advertise.
	Capabilities ClientCapabilities
	// Bounds caps everything the connection converts from server data. The
	// client passes a normalized (all-positive) value.
	Bounds Bounds
}

// ServerCapabilities is what a server advertised at initialize, reduced to the
// presence flags this module acts on. The SDK models each capability as a
// nillable struct whose only members are listChanged-style notification flags;
// those are not modelled here until a task consumes them.
type ServerCapabilities struct {
	// Tools reports whether the server exposes tools.
	Tools bool
	// Prompts reports whether the server exposes prompts.
	Prompts bool
	// Resources reports whether the server exposes resources.
	Resources bool
	// ResourcesSubscribe reports whether the server supports subscribing to
	// resource updates. It is only meaningful when Resources is set.
	ResourcesSubscribe bool
	// Logging reports whether the server sends log messages.
	Logging bool
	// Completions reports whether the server supports argument autocompletion.
	Completions bool
}

// InitializeResult is the outcome of the MCP handshake, bounded and detached
// from SDK memory. Every field is server-supplied: it describes a peer, it
// never authorizes one.
type InitializeResult struct {
	// Server is what the server claims to be.
	Server ServerIdentity
	// ProtocolVersion is the version the server wants to speak.
	ProtocolVersion ProtocolVersion
	// Instructions is the server's usage hint, truncated to
	// Bounds.MaxTextBytes.
	Instructions string
	// Capabilities is what the server advertised.
	Capabilities ServerCapabilities
}

// ProtocolVersion is an MCP protocol version string as negotiated during
// initialize (e.g. "2025-06-18"). It is server-supplied and untrusted.
type ProtocolVersion string

// ServerIdentity is what a server claims to be. Every field is server-supplied
// and cosmetic: it names a peer, it never authorizes one.
type ServerIdentity struct {
	Name    string
	Version string
	Title   string
}

// Bounds is the narrow limit view this package needs — the subset of the
// client's Limits that applies to converting SDK values. The client passes a
// normalized (all-positive) value; a non-positive field is not "unbounded" but
// fails closed, rejecting or truncating everything it governs.
type Bounds struct {
	// MaxSchemaBytes caps one marshaled tool schema document.
	MaxSchemaBytes int
	// MaxSchemaDepth caps schema nesting.
	MaxSchemaDepth int
	// MaxTextBytes caps one text (or embedded-resource text) payload before
	// it is truncated.
	MaxTextBytes int
	// MaxStructuredBytes caps one structured-content document. Not read by
	// any converter yet: structured content arrives on CallToolResult, whose
	// conversion lands in a later task and enforces this. It is carried here
	// so the client's Limits map onto one complete Bounds view.
	MaxStructuredBytes int
	// MaxBinaryItemBytes caps one binary (image/audio/blob) item.
	MaxBinaryItemBytes int
	// MaxBinaryItems caps how many binary items one content list may carry.
	MaxBinaryItems int
}

// MaxWarnings caps the Warnings a single conversion may report, so a hostile
// server cannot turn tolerated defects into unbounded memory. Warnings beyond
// the cap are discarded.
const MaxWarnings = 8

// ToolSpec is a tool as advertised by a server, bounded and detached from SDK
// memory. RawName is exactly what the server sent — unvalidated, unnamespaced,
// and not safe to use as an identifier until the client has qualified it.
type ToolSpec struct {
	RawName      string
	Title        string
	Description  string
	InputSchema  json.RawMessage
	OutputSchema json.RawMessage
	// Annotations are server-declared behavioural hints. They are untrusted
	// policy *input* and never authority: a server claiming ReadOnlyHint does
	// not make a tool read-only. Nil when the server sent none.
	Annotations *ToolAnnotations
	// Warnings records defects tolerated during conversion (e.g. a dropped
	// output schema). Bounded by MaxWarnings.
	Warnings []string
}

// ToolAnnotations mirrors the server's behavioural hints. The tri-state hints
// are pointers because "unspecified" differs from "false": absent means the
// server said nothing, and the caller applies its own default.
type ToolAnnotations struct {
	Title           string
	ReadOnlyHint    bool
	IdempotentHint  bool
	DestructiveHint *bool
	OpenWorldHint   *bool
}

// copyBool returns a copy of a tri-state hint, preserving nil.
func copyBool(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// PromptSpec is a prompt as advertised by a server. RawName carries the same
// caveat as ToolSpec.RawName.
type PromptSpec struct {
	RawName     string
	Title       string
	Description string
	Arguments   []PromptArgSpec
}

// PromptArgSpec is one argument a prompt accepts.
type PromptArgSpec struct {
	Name        string
	Title       string
	Description string
	Required    bool
}

// ResourceSpec is a concrete resource a server exposes.
type ResourceSpec struct {
	URI         string
	Name        string
	Title       string
	Description string
	MIMEType    string
}

// ResourceTemplateSpec is an RFC 6570 template for a family of resources.
type ResourceTemplateSpec struct {
	URITemplate string
	Name        string
	Title       string
	Description string
	MIMEType    string
}

// Content is a sealed union of the neutral content kinds. Only this package
// can add a member; callers exhaust it with a type switch and must handle
// UnsupportedContent, which is the default for anything else.
type Content interface {
	content()
}

// TextContent is a text payload, truncated to Bounds.MaxTextBytes. Truncation
// is normal, not an error: Truncated says whether it happened.
type TextContent struct {
	Text      string
	Truncated bool
}

// ImageContent is an image payload within Bounds.MaxBinaryItemBytes.
type ImageContent struct {
	Data     []byte
	MIMEType string
}

// AudioContent is an audio payload within Bounds.MaxBinaryItemBytes.
type AudioContent struct {
	Data     []byte
	MIMEType string
}

// EmbeddedResourceContent is resource content inlined in a result. Exactly one
// of Text or Data is meaningful, per what the server sent.
type EmbeddedResourceContent struct {
	URI       string
	MIMEType  string
	Text      string
	Data      []byte
	Truncated bool
}

// UnsupportedContent stands in for content this boundary will not retain: a
// kind the module does not model, or a payload over a bound. It records only
// bounded metadata, so an unusable item is always visible to the caller rather
// than silently disappearing.
type UnsupportedContent struct {
	// Kind is one of the Kind* constants.
	Kind string
	// Bytes is the size of the payload that was refused. It is exact for an
	// item dropped on a size bound (image, audio, embedded blob), and a
	// diagnostic lower bound for a kind dropped as unsupported, whose size is
	// summed from its known fields rather than by marshalling data we are
	// refusing. Treat it as a diagnostic, never as an accounting figure.
	Bytes int
}

// Values for UnsupportedContent.Kind. They mirror the MCP wire "type"
// discriminator, with KindUnknown for a content type this SDK version returns
// but this module does not know.
const (
	KindText         = "text"
	KindImage        = "image"
	KindAudio        = "audio"
	KindResource     = "resource"
	KindResourceLink = "resource_link"
	KindToolUse      = "tool_use"
	KindToolResult   = "tool_result"
	KindUnknown      = "unknown"
)

func (TextContent) content()             {}
func (ImageContent) content()            {}
func (AudioContent) content()            {}
func (EmbeddedResourceContent) content() {}
func (UnsupportedContent) content()      {}
