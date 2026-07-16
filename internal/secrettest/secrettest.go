// Package secrettest provides the adversary that the module's secret-hiding
// design is measured against: a reflection walker that reads unexported fields
// and follows pointers, in the manner of go-spew and of the structured loggers
// and debug dumpers built the same way.
//
// It lives here, in a normal package rather than in a _test.go file, because
// two test packages need it and neither can import the other's tests:
// pkg/auth's external tests (package auth_test) exercise the exported
// secret-bearing types, while its internal tests (package auth) exercise the
// unexported ones — the PKCE verifier, the CSRF state, the authorization code —
// which no external test can name. One adversary, tested against from both
// sides, beats two that can drift apart. internal/mcptest is the precedent for
// a test-only helper living in a normal internal package.
//
// Nothing outside a test may import this. It is in internal/ so nothing outside
// the module can, and it does nothing useful except attack our own types.
package secrettest

import (
	"fmt"
	"reflect"
	"strings"
	"time"
	"unsafe"
)

// maxDepth bounds the walk. The structures under test are shallow; the bound is
// what keeps a cyclic one from hanging a test run.
const maxDepth = 8

// Dump renders everything reachable in v, defeating the protections a
// well-behaved printer respects.
//
// It is deliberately hostile in three specific ways, each mirroring something a
// real reflection-based dumper does:
//
//   - it uses unsafe.Pointer + reflect.NewAt to rebuild unexported fields as
//     readable values, which defeats reflect.Value.CanInterface — this is the
//     move that makes "the field is unexported" insufficient on its own;
//   - it follows pointers at any depth, unlike fmt, which follows one only at
//     depth 0 and only into a composite — this is what makes a *string field
//     insufficient;
//   - it ignores String, GoString and Format entirely, because a dumper's whole
//     purpose is to show what a value *is* rather than what it says it is.
//
// What it cannot do is call a function. That is the entire thesis of the
// secret-in-a-closure design: a closure's captured environment is not a field,
// so the only route to the bytes is to call the func, and a walker cannot know
// to. A secret held this way renders as "func@0x...".
func Dump(v any) string {
	// Address the value so the walker can rebuild unexported fields, which is
	// what it would do to a field it found inside a real struct.
	holder := reflect.New(reflect.TypeOf(v))
	holder.Elem().Set(reflect.ValueOf(v))
	return dump(holder.Elem(), 0)
}

// ReachedSecret reports whether a Dump result shows the walker actually got as
// far as a secret's hiding place, rather than stopping short.
//
// Without this, a redaction assertion is worthless: a walker that reached
// nothing also leaks nothing, and would pass. "func@" is a secret's closure;
// "keys:" is a MemoryStore, which renders its own summary.
func ReachedSecret(dumped string) bool {
	return strings.Contains(dumped, "func@") || strings.Contains(dumped, "keys:")
}

func dump(v reflect.Value, depth int) string {
	if depth > maxDepth || !v.IsValid() {
		return "<stop>"
	}
	// Stop at time.Time. Not for tidiness: a timestamp cannot hold a canary, so
	// walking in proves nothing, and walking in is actively unsafe — a
	// time.Time carries a *time.Location whose fields the standard library
	// initializes lazily under a sync.Once. Reading them by reflection races
	// with any parallel test that formats a time (slog stamps every record),
	// which -race duly reports. The walker's business is our own layout.
	if v.Type() == reflect.TypeOf(time.Time{}) {
		return "<time.Time>"
	}
	// The move that defeats CanInterface: re-create the value at its address.
	if !v.CanInterface() && v.CanAddr() {
		// #nosec G103 -- reproducing the threat IS the point: this package is
		// the adversary the secret design is measured against, it is internal
		// and imported only by tests, and the unsafe read is what a real
		// reflection-based dumper does. Auditing it is exactly what the reader
		// should do, and the file comment is that audit.
		v = reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		var b strings.Builder
		b.WriteString(v.Type().String() + "{")
		for i := range v.NumField() {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(v.Type().Field(i).Name + ":" + dump(v.Field(i), depth+1))
		}
		b.WriteString("}")
		return b.String()
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return "<nil>"
		}
		return "&" + dump(v.Elem(), depth+1)
	case reflect.Slice, reflect.Array:
		var b strings.Builder
		b.WriteString("[")
		for i := range v.Len() {
			if i > 0 {
				b.WriteString(" ")
			}
			b.WriteString(dump(v.Index(i), depth+1))
		}
		b.WriteString("]")
		return b.String()
	case reflect.Map:
		var b strings.Builder
		b.WriteString("map[")
		for _, key := range v.MapKeys() {
			b.WriteString(dump(key, depth+1) + ":" + dump(v.MapIndex(key), depth+1) + " ")
		}
		b.WriteString("]")
		return b.String()
	case reflect.String:
		return v.String()
	case reflect.Func:
		// All a walker can do with a closure: report that it exists. This is
		// the design working.
		return fmt.Sprintf("func@%v", v.Pointer())
	default:
		return fmt.Sprintf("%v", v)
	}
}
