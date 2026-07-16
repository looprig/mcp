// This file holds the SDK -> neutral conversions. Every function here treats
// its input as hostile: nil-checked, bounded before retention, and deep-copied
// so no neutral value ever aliases SDK memory.

package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/limits"
)

// WhatSchemaBytes is the limits.OverLimitError.What reported when a schema
// document exceeds Bounds.MaxSchemaBytes.
const WhatSchemaBytes = "schema_bytes"

// errNilInput is the class of "the server sent nothing where the protocol
// requires something". Callers classify with errors.Is.
var errNilInput = errors.New("protocol: nil input")

// isNilContent reports whether c is nil or a non-nil interface holding a nil
// pointer. The latter cannot be caught by `c == nil`, and every mcp.Content
// implementation has pointer-receiver methods that would dereference it.
func isNilContent(c mcp.Content) bool {
	if c == nil {
		return true
	}
	v := reflect.ValueOf(c)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// FromSDKTool converts an SDK tool, enforcing the schema bounds before
// retaining anything.
//
// The two schemas are deliberately asymmetric. An input schema is load-bearing
// — it is what constrains the arguments a model may send — so a missing,
// malformed, non-object, or over-bound one is an error: the tool is rejected
// rather than exposed with unconstrained arguments. An output schema only
// describes what comes back, so a malformed one is tolerated: it is dropped,
// OutputSchema is left nil, and the defect is reported in Warnings. An
// over-bound output schema is still an error — a bound is a bound.
func FromSDKTool(t *mcp.Tool, b Bounds) (ToolSpec, error) {
	if t == nil {
		return ToolSpec{}, fmt.Errorf("%w: tool", errNilInput)
	}
	if t.Name == "" {
		return ToolSpec{}, errors.New("protocol: tool has no name")
	}

	spec := ToolSpec{
		RawName:     t.Name,
		Title:       t.Title,
		Description: t.Description,
		Annotations: fromSDKToolAnnotations(t.Annotations),
	}

	in, err := marshalSchema(t.InputSchema)
	if err != nil {
		return ToolSpec{}, fmt.Errorf("protocol: tool %q input schema: %w", t.Name, err)
	}
	if err := checkSchemaBounds(in, b); err != nil {
		return ToolSpec{}, fmt.Errorf("protocol: tool %q input schema: %w", t.Name, err)
	}
	spec.InputSchema = in

	// An absent output schema is the norm, not a defect: no warning.
	if !isAbsentSchema(t.OutputSchema) {
		out, err := marshalSchema(t.OutputSchema)
		if err != nil {
			spec.warn(fmt.Sprintf("output schema dropped: %v", err))
			return spec, nil
		}
		if err := checkSchemaBounds(out, b); err != nil {
			return ToolSpec{}, fmt.Errorf("protocol: tool %q output schema: %w", t.Name, err)
		}
		spec.OutputSchema = out
	}
	return spec, nil
}

// warn appends a bounded warning, dropping anything past MaxWarnings.
func (s *ToolSpec) warn(msg string) {
	if len(s.Warnings) >= MaxWarnings {
		return
	}
	s.Warnings = append(s.Warnings, msg)
}

// isAbsentSchema reports whether the SDK's `any` schema field carries nothing
// at all. The SDK types both schema fields as `any`: a server that omitted the
// field leaves it nil, and one that sent JSON null leaves a RawMessage of
// "null". Neither is a schema.
func isAbsentSchema(schema any) bool {
	if schema == nil {
		return true
	}
	raw, ok := schema.(json.RawMessage)
	return ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// marshalSchema renders the SDK's `any`-typed schema field to raw JSON and
// verifies it is a JSON object, as MCP requires. The result is freshly
// allocated by json.Marshal and so never aliases SDK memory.
func marshalSchema(schema any) (json.RawMessage, error) {
	if isAbsentSchema(schema) {
		return nil, errors.New("missing")
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		// A json.RawMessage holding malformed bytes lands here, as does any
		// value that cannot be represented as JSON.
		return nil, fmt.Errorf("not marshalable: %w", err)
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("not a JSON object")
	}
	return raw, nil
}

// checkSchemaBounds enforces the byte and depth bounds on an already-marshaled
// schema.
func checkSchemaBounds(raw json.RawMessage, b Bounds) error {
	if len(raw) > b.MaxSchemaBytes {
		return fmt.Errorf("%d bytes: %w", len(raw),
			&limits.OverLimitError{What: WhatSchemaBytes, Limit: b.MaxSchemaBytes})
	}
	if err := limits.CheckJSONDepth(raw, b.MaxSchemaDepth); err != nil {
		return err
	}
	return nil
}

func fromSDKToolAnnotations(a *mcp.ToolAnnotations) *ToolAnnotations {
	if a == nil {
		return nil
	}
	// The pointer hints are copied, never aliased: the SDK value stays the
	// SDK's to mutate.
	return &ToolAnnotations{
		Title:           a.Title,
		ReadOnlyHint:    a.ReadOnlyHint,
		IdempotentHint:  a.IdempotentHint,
		DestructiveHint: copyBool(a.DestructiveHint),
		OpenWorldHint:   copyBool(a.OpenWorldHint),
	}
}

// FromSDKPrompt converts an SDK prompt, copying the argument list.
func FromSDKPrompt(p *mcp.Prompt, _ Bounds) (PromptSpec, error) {
	if p == nil {
		return PromptSpec{}, fmt.Errorf("%w: prompt", errNilInput)
	}
	if p.Name == "" {
		return PromptSpec{}, errors.New("protocol: prompt has no name")
	}
	spec := PromptSpec{
		RawName:     p.Name,
		Title:       p.Title,
		Description: p.Description,
	}
	if len(p.Arguments) > 0 {
		spec.Arguments = make([]PromptArgSpec, 0, len(p.Arguments))
		for i, a := range p.Arguments {
			if a == nil {
				return PromptSpec{}, fmt.Errorf("%w: prompt %q argument %d", errNilInput, p.Name, i)
			}
			if a.Name == "" {
				return PromptSpec{}, fmt.Errorf("protocol: prompt %q argument %d has no name", p.Name, i)
			}
			spec.Arguments = append(spec.Arguments, PromptArgSpec{
				Name:        a.Name,
				Title:       a.Title,
				Description: a.Description,
				Required:    a.Required,
			})
		}
	}
	return spec, nil
}

// FromSDKResource converts an SDK resource. A resource without a URI cannot be
// read and is rejected.
func FromSDKResource(r *mcp.Resource, _ Bounds) (ResourceSpec, error) {
	if r == nil {
		return ResourceSpec{}, fmt.Errorf("%w: resource", errNilInput)
	}
	if r.URI == "" {
		return ResourceSpec{}, errors.New("protocol: resource has no URI")
	}
	return ResourceSpec{
		URI:         r.URI,
		Name:        r.Name,
		Title:       r.Title,
		Description: r.Description,
		MIMEType:    r.MIMEType,
	}, nil
}

// FromSDKResourceTemplate converts an SDK resource template. The URI template
// is carried verbatim; expanding it safely is the caller's problem.
func FromSDKResourceTemplate(rt *mcp.ResourceTemplate, _ Bounds) (ResourceTemplateSpec, error) {
	if rt == nil {
		return ResourceTemplateSpec{}, fmt.Errorf("%w: resource template", errNilInput)
	}
	if rt.URITemplate == "" {
		return ResourceTemplateSpec{}, errors.New("protocol: resource template has no URI template")
	}
	return ResourceTemplateSpec{
		URITemplate: rt.URITemplate,
		Name:        rt.Name,
		Title:       rt.Title,
		Description: rt.Description,
		MIMEType:    rt.MIMEType,
	}, nil
}

// FromSDKContent converts one content item.
//
// A content kind this module does not model — resource links and the
// sampling-only tool_use/tool_result kinds today, anything new the SDK grows
// tomorrow — converts to UnsupportedContent rather than an error: one exotic
// item must not fail a whole result, and it must not vanish silently either.
// Errors are reserved for content that is structurally broken (nil, or an
// embedded resource with no contents).
//
// Binary items over Bounds.MaxBinaryItemBytes also become UnsupportedContent,
// carrying the size that was refused. The oversized bytes are never retained.
func FromSDKContent(c mcp.Content, b Bounds) (Content, error) {
	// Every SDK content kind is a pointer type whose methods dereference the
	// receiver, so a typed nil is checked once here rather than per case: the
	// kinds that fall through to unsupported() would otherwise panic while
	// measuring one, as would any kind a future SDK adds.
	if isNilContent(c) {
		return nil, fmt.Errorf("%w: content", errNilInput)
	}
	switch v := c.(type) {
	case *mcp.TextContent:
		text, truncated := limits.TruncateText(v.Text, b.MaxTextBytes)
		return TextContent{Text: text, Truncated: truncated}, nil

	case *mcp.ImageContent:
		if len(v.Data) > b.MaxBinaryItemBytes {
			return UnsupportedContent{Kind: KindImage, Bytes: len(v.Data)}, nil
		}
		return ImageContent{Data: bytes.Clone(v.Data), MIMEType: v.MIMEType}, nil

	case *mcp.AudioContent:
		if len(v.Data) > b.MaxBinaryItemBytes {
			return UnsupportedContent{Kind: KindAudio, Bytes: len(v.Data)}, nil
		}
		return AudioContent{Data: bytes.Clone(v.Data), MIMEType: v.MIMEType}, nil

	case *mcp.EmbeddedResource:
		return fromSDKEmbeddedResource(v, b)

	case *mcp.ResourceLink:
		return unsupported(KindResourceLink, c), nil
	case *mcp.ToolUseContent:
		return unsupported(KindToolUse, c), nil
	case *mcp.ToolResultContent:
		return unsupported(KindToolResult, c), nil
	default:
		return unsupported(KindUnknown, c), nil
	}
}

func fromSDKEmbeddedResource(v *mcp.EmbeddedResource, b Bounds) (Content, error) {
	if v.Resource == nil {
		return nil, fmt.Errorf("%w: embedded resource contents", errNilInput)
	}
	r := v.Resource
	// A blob is bounded like any other binary item; text is truncated.
	if len(r.Blob) > b.MaxBinaryItemBytes {
		return UnsupportedContent{Kind: KindResource, Bytes: len(r.Blob)}, nil
	}
	text, truncated := limits.TruncateText(r.Text, b.MaxTextBytes)
	return EmbeddedResourceContent{
		URI:       r.URI,
		MIMEType:  r.MIMEType,
		Text:      text,
		Data:      bytes.Clone(r.Blob),
		Truncated: truncated,
	}, nil
}

// unsupported measures a content item we will not retain. The size is its
// marshaled form, which is the only thing we can report generically; a kind
// that refuses to marshal reports 0 rather than failing.
func unsupported(kind string, c mcp.Content) UnsupportedContent {
	n := 0
	if raw, err := c.MarshalJSON(); err == nil {
		n = len(raw)
	}
	return UnsupportedContent{Kind: kind, Bytes: n}
}

// FromSDKContents converts a content list, additionally enforcing
// Bounds.MaxBinaryItems across the binary items in it. Items past the budget
// become UnsupportedContent, so the list keeps its length and position: a
// caller can always tell which item it lost.
//
// Only items actually retained spend the budget. An item already refused on
// size does not, or a single oversized image would evict a later good one.
func FromSDKContents(cs []mcp.Content, b Bounds) ([]Content, error) {
	if len(cs) == 0 {
		return nil, nil
	}
	out := make([]Content, 0, len(cs))
	binary := 0
	for i, c := range cs {
		conv, err := FromSDKContent(c, b)
		if err != nil {
			return nil, fmt.Errorf("protocol: content item %d: %w", i, err)
		}
		if kind, isBinary := binaryKind(conv); isBinary {
			if binary >= b.MaxBinaryItems {
				conv = UnsupportedContent{Kind: kind, Bytes: binarySize(conv)}
			} else {
				binary++
			}
		}
		out = append(out, conv)
	}
	return out, nil
}

// binaryKind reports whether a converted item counts against MaxBinaryItems,
// and under which kind. An embedded resource counts only when it actually
// carries a blob — a text one is not a binary item.
func binaryKind(c Content) (string, bool) {
	switch v := c.(type) {
	case ImageContent:
		return KindImage, true
	case AudioContent:
		return KindAudio, true
	case EmbeddedResourceContent:
		return KindResource, len(v.Data) > 0
	default:
		return "", false
	}
}

// binarySize is the payload size of a binary item, for reporting once it is
// refused.
func binarySize(c Content) int {
	switch v := c.(type) {
	case ImageContent:
		return len(v.Data)
	case AudioContent:
		return len(v.Data)
	case EmbeddedResourceContent:
		return len(v.Data)
	default:
		return 0
	}
}

// FromSDKServerIdentity converts the server's self-description. A nil
// Implementation yields the zero identity rather than an error: identity here
// is cosmetic, and an anonymous server is not a protocol violation.
func FromSDKServerIdentity(impl *mcp.Implementation) ServerIdentity {
	if impl == nil {
		return ServerIdentity{}
	}
	return ServerIdentity{
		Name:    impl.Name,
		Version: impl.Version,
		Title:   impl.Title,
	}
}
