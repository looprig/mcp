// This file defines the per-connection timeouts and resource limits carried
// by a Definition. Every limit and timeout has a non-zero default: a zero
// field in Timeouts or Limits means "use the default" (filled in by
// Definition.normalized), never "unbounded". Negative values are invalid.
package client

import (
	"fmt"
	"time"
)

// Default timeouts applied when the corresponding Timeouts field is zero.
const (
	// DefaultStartupTimeout bounds transport connect plus MCP initialize.
	DefaultStartupTimeout = 30 * time.Second
	// DefaultRequestTimeout bounds a single request/response exchange.
	DefaultRequestTimeout = 60 * time.Second
	// DefaultElicitationTimeout bounds how long a server-initiated
	// elicitation may wait for a human answer; generous because a person,
	// not a machine, is on the other end.
	DefaultElicitationTimeout = 5 * time.Minute
)

// Timeouts holds the per-connection deadlines. The zero value of any field
// selects the corresponding default; negative values fail validation.
type Timeouts struct {
	// Startup bounds connect plus initialize. Zero means
	// DefaultStartupTimeout.
	Startup time.Duration
	// Request bounds one request/response exchange. Zero means
	// DefaultRequestTimeout.
	Request time.Duration
	// Elicitation bounds a server-initiated elicitation round trip. Zero
	// means DefaultElicitationTimeout.
	Elicitation time.Duration
}

// validate reports the first negative field, naming it. Zero is valid (it
// means "use the default").
func (t Timeouts) validate() error {
	for _, f := range []struct {
		name  string
		value time.Duration
	}{
		{"Timeouts.Startup", t.Startup},
		{"Timeouts.Request", t.Request},
		{"Timeouts.Elicitation", t.Elicitation},
	} {
		if f.value < 0 {
			return fmt.Errorf("%s: negative duration %v", f.name, f.value)
		}
	}
	return nil
}

// withDefaults returns a copy with every zero field replaced by its default.
func (t Timeouts) withDefaults() Timeouts {
	if t.Startup == 0 {
		t.Startup = DefaultStartupTimeout
	}
	if t.Request == 0 {
		t.Request = DefaultRequestTimeout
	}
	if t.Elicitation == 0 {
		t.Elicitation = DefaultElicitationTimeout
	}
	return t
}

// Limits bounds every resource an MCP server (or a runaway client caller) can
// consume on one connection. The zero value of any field selects the
// corresponding DefaultLimits value; negative values fail validation. There
// is deliberately no "unlimited" setting: a bound can be raised, never
// removed.
type Limits struct {
	// MaxConcurrentRequests caps in-flight requests on one connection.
	MaxConcurrentRequests int
	// MaxCatalogPages caps list-pagination round trips per catalog fetch.
	MaxCatalogPages int
	// MaxCatalogItems caps total tools accepted from one server.
	MaxCatalogItems int

	// MaxFrameBytes caps a single wire frame (one JSON-RPC message).
	MaxFrameBytes int
	// MaxBodyBytes caps a whole HTTP response body.
	MaxBodyBytes int
	// MaxSchemaBytes caps one tool's input/output schema document.
	MaxSchemaBytes int
	// MaxSchemaDepth caps schema nesting to bound recursive traversal.
	MaxSchemaDepth int

	// MaxTextResultBytes caps the text content of one tool result.
	MaxTextResultBytes int
	// MaxStructuredBytes caps the structured content of one tool result.
	MaxStructuredBytes int
	// MaxBinaryItemBytes caps one binary (image/audio/blob) result item.
	MaxBinaryItemBytes int
	// MaxBinaryItems caps how many binary items one result may carry.
	MaxBinaryItems int

	// MaxLogMessageBytes caps one server log notification's payload.
	MaxLogMessageBytes int
	// MaxPromptCount caps prompts accepted from one server.
	MaxPromptCount int
	// MaxResourceCount caps resources accepted from one server.
	MaxResourceCount int

	// MaxSamplingDepth caps nested sampling (sampling issued while serving
	// a sampling request).
	MaxSamplingDepth int
	// MaxSamplingConcurrency caps concurrent sampling requests.
	MaxSamplingConcurrency int
	// MaxSamplingTokens caps tokens per sampling completion.
	MaxSamplingTokens int
}

// DefaultLimits returns the module defaults. Every field is non-zero (a test
// enforces this by reflection): defaults exist so that forgetting to
// configure a limit can never mean "unbounded".
func DefaultLimits() Limits {
	return Limits{
		// 8 in-flight requests: enough for tool-call parallelism without
		// letting one binding monopolize a server.
		MaxConcurrentRequests: 8,
		// 64 pages x 1024 items comfortably covers real catalogs while
		// stopping a malicious server from paginating forever.
		MaxCatalogPages: 64,
		MaxCatalogItems: 1024,

		// 4 MiB per frame / 16 MiB per body: large results fit, memory
		// stays bounded per connection.
		MaxFrameBytes: 4 << 20,
		MaxBodyBytes:  16 << 20,
		// 256 KiB and depth 32 admit any reasonable JSON schema while
		// bounding parse cost and recursion.
		MaxSchemaBytes: 256 << 10,
		MaxSchemaDepth: 32,

		// 1 MiB of text or structured output is far beyond what a model
		// consumes per tool call.
		MaxTextResultBytes: 1 << 20,
		MaxStructuredBytes: 1 << 20,
		// 8 MiB x 16 items bounds binary payloads (images, audio) to
		// 128 MiB worst case per result.
		MaxBinaryItemBytes: 8 << 20,
		MaxBinaryItems:     16,

		// 8 KiB per log line: diagnostics, not a data channel.
		MaxLogMessageBytes: 8 << 10,
		// Generous catalog caps; servers exceeding these are misbehaving.
		MaxPromptCount:   256,
		MaxResourceCount: 4096,

		// Sampling is expensive and recursive by nature: keep depth and
		// concurrency at 2 and cap spend at 8192 tokens per completion.
		MaxSamplingDepth:       2,
		MaxSamplingConcurrency: 2,
		MaxSamplingTokens:      8192,
	}
}

// validate reports the first negative field, naming it. Zero is valid (it
// means "use the default"). Keep this table in sync with the struct; the
// reflection sweep in tests fails if a field is missing here.
func (l Limits) validate() error {
	for _, f := range []struct {
		name  string
		value int
	}{
		{"Limits.MaxConcurrentRequests", l.MaxConcurrentRequests},
		{"Limits.MaxCatalogPages", l.MaxCatalogPages},
		{"Limits.MaxCatalogItems", l.MaxCatalogItems},
		{"Limits.MaxFrameBytes", l.MaxFrameBytes},
		{"Limits.MaxBodyBytes", l.MaxBodyBytes},
		{"Limits.MaxSchemaBytes", l.MaxSchemaBytes},
		{"Limits.MaxSchemaDepth", l.MaxSchemaDepth},
		{"Limits.MaxTextResultBytes", l.MaxTextResultBytes},
		{"Limits.MaxStructuredBytes", l.MaxStructuredBytes},
		{"Limits.MaxBinaryItemBytes", l.MaxBinaryItemBytes},
		{"Limits.MaxBinaryItems", l.MaxBinaryItems},
		{"Limits.MaxLogMessageBytes", l.MaxLogMessageBytes},
		{"Limits.MaxPromptCount", l.MaxPromptCount},
		{"Limits.MaxResourceCount", l.MaxResourceCount},
		{"Limits.MaxSamplingDepth", l.MaxSamplingDepth},
		{"Limits.MaxSamplingConcurrency", l.MaxSamplingConcurrency},
		{"Limits.MaxSamplingTokens", l.MaxSamplingTokens},
	} {
		if f.value < 0 {
			return fmt.Errorf("%s: negative limit %d", f.name, f.value)
		}
	}
	return nil
}

// withDefaults returns a copy with every zero field replaced by its default.
// Keep in sync with the struct; the reflection sweep in tests fails if a
// field is missing here (its normalized value would stay zero).
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	pick := func(v, def int) int {
		if v == 0 {
			return def
		}
		return v
	}
	return Limits{
		MaxConcurrentRequests:  pick(l.MaxConcurrentRequests, d.MaxConcurrentRequests),
		MaxCatalogPages:        pick(l.MaxCatalogPages, d.MaxCatalogPages),
		MaxCatalogItems:        pick(l.MaxCatalogItems, d.MaxCatalogItems),
		MaxFrameBytes:          pick(l.MaxFrameBytes, d.MaxFrameBytes),
		MaxBodyBytes:           pick(l.MaxBodyBytes, d.MaxBodyBytes),
		MaxSchemaBytes:         pick(l.MaxSchemaBytes, d.MaxSchemaBytes),
		MaxSchemaDepth:         pick(l.MaxSchemaDepth, d.MaxSchemaDepth),
		MaxTextResultBytes:     pick(l.MaxTextResultBytes, d.MaxTextResultBytes),
		MaxStructuredBytes:     pick(l.MaxStructuredBytes, d.MaxStructuredBytes),
		MaxBinaryItemBytes:     pick(l.MaxBinaryItemBytes, d.MaxBinaryItemBytes),
		MaxBinaryItems:         pick(l.MaxBinaryItems, d.MaxBinaryItems),
		MaxLogMessageBytes:     pick(l.MaxLogMessageBytes, d.MaxLogMessageBytes),
		MaxPromptCount:         pick(l.MaxPromptCount, d.MaxPromptCount),
		MaxResourceCount:       pick(l.MaxResourceCount, d.MaxResourceCount),
		MaxSamplingDepth:       pick(l.MaxSamplingDepth, d.MaxSamplingDepth),
		MaxSamplingConcurrency: pick(l.MaxSamplingConcurrency, d.MaxSamplingConcurrency),
		MaxSamplingTokens:      pick(l.MaxSamplingTokens, d.MaxSamplingTokens),
	}
}
