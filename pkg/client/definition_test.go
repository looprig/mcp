package client

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// validDefinition returns a minimal Definition that passes Validate; tests
// mutate single fields from this base. The transport double lives in
// fake_test.go, shared with the Connect tests.
func validDefinition() Definition {
	return Definition{
		Name:      "srv-1",
		Transport: newFakeTransport(okConn()),
	}
}

func TestNameValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   Name
		wantErr bool
	}{
		{name: "single lowercase letter", value: "a", wantErr: false},
		{name: "single digit", value: "7", wantErr: false},
		{name: "mixed with dash and underscore", value: "abc-123_x", wantErr: false},
		{name: "max length 64 bytes", value: Name(strings.Repeat("a", 64)), wantErr: false},
		{name: "empty", value: "", wantErr: true},
		{name: "65 bytes", value: Name(strings.Repeat("a", 65)), wantErr: true},
		{name: "uppercase", value: "Abc", wantErr: true},
		{name: "leading dash", value: "-abc", wantErr: true},
		{name: "leading underscore", value: "_abc", wantErr: true},
		{name: "space", value: "a b", wantErr: true},
		{name: "dot", value: "a.b", wantErr: true},
		{name: "slash", value: "a/b", wantErr: true},
		{name: "non-ascii", value: "sérver", wantErr: true},
		{name: "control character", value: "a\x00b", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.value.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Name(%q).Validate() error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if !tt.wantErr {
				return
			}
			class, ok := ClassOf(err)
			if !ok || class != FailureInvalidConfig {
				t.Errorf("ClassOf = %v, %v; want %v, true", class, ok, FailureInvalidConfig)
			}
		})
	}
}

func TestTimeoutsDefaultsApplied(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   Timeouts
		want Timeouts
	}{
		{
			name: "all zero gets all defaults",
			in:   Timeouts{},
			want: Timeouts{
				Startup:     DefaultStartupTimeout,
				Request:     DefaultRequestTimeout,
				Elicitation: DefaultElicitationTimeout,
			},
		},
		{
			name: "set fields preserved, zero fields defaulted",
			in:   Timeouts{Request: 5 * time.Second},
			want: Timeouts{
				Startup:     DefaultStartupTimeout,
				Request:     5 * time.Second,
				Elicitation: DefaultElicitationTimeout,
			},
		},
		{
			name: "all set preserved",
			in:   Timeouts{Startup: time.Second, Request: 2 * time.Second, Elicitation: 3 * time.Second},
			want: Timeouts{Startup: time.Second, Request: 2 * time.Second, Elicitation: 3 * time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			def := validDefinition()
			def.Timeouts = tt.in
			got := def.normalized().Timeouts
			if got != tt.want {
				t.Errorf("normalized().Timeouts = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestTimeoutsNegativeRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		in    Timeouts
		field string
	}{
		{name: "negative startup", in: Timeouts{Startup: -time.Second}, field: "Timeouts.Startup"},
		{name: "negative request", in: Timeouts{Request: -time.Second}, field: "Timeouts.Request"},
		{name: "negative elicitation", in: Timeouts{Elicitation: -time.Second}, field: "Timeouts.Elicitation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			def := validDefinition()
			def.Timeouts = tt.in
			assertInvalidConfig(t, def.Validate(), def.Name, tt.field)
		})
	}
}

// TestDefaultLimitsAllNonZero proves by reflection that every Limits field has
// a non-zero default, both in DefaultLimits and after normalizing a zero-value
// Definition. A zero field here means a limit silently became "unbounded".
func TestDefaultLimitsAllNonZero(t *testing.T) {
	t.Parallel()

	check := func(t *testing.T, l Limits, label string) {
		t.Helper()
		v := reflect.ValueOf(l)
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).Int() <= 0 {
				t.Errorf("%s: field %s = %d, want > 0", label, v.Type().Field(i).Name, v.Field(i).Int())
			}
		}
	}
	check(t, DefaultLimits(), "DefaultLimits()")
	check(t, validDefinition().normalized().Limits, "normalized().Limits")
}

// TestLimitsNegativeRejected sweeps every Limits field by reflection: a
// negative value in any single field must fail Validate with an error that
// names that field. The sweep also guards against a field added to Limits but
// forgotten in the validation table.
func TestLimitsNegativeRejected(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeOf(Limits{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i).Name
		index := i
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			def := validDefinition()
			limits := reflect.ValueOf(&def.Limits).Elem()
			limits.Field(index).SetInt(-1)
			assertInvalidConfig(t, def.Validate(), def.Name, "Limits."+field)
		})
	}
}

// TestLimitsPositivePreserved sets every Limits field to a distinct positive
// sentinel and asserts normalization returns each field's own sentinel. A
// shared sentinel would miss a crossed mapping in withDefaults (for example
// `MaxFrameBytes: pick(l.MaxBodyBytes, ...)`); distinct values catch it and
// name the miswired field. It also asserts an all-zero Limits normalizes to
// exactly DefaultLimits.
func TestLimitsPositivePreserved(t *testing.T) {
	t.Parallel()

	def := validDefinition()
	limits := reflect.ValueOf(&def.Limits).Elem()
	for i := 0; i < limits.NumField(); i++ {
		limits.Field(i).SetInt(int64(1000 + i))
	}
	got := reflect.ValueOf(def.normalized().Limits)
	for i := 0; i < got.NumField(); i++ {
		if want := int64(1000 + i); got.Field(i).Int() != want {
			t.Errorf("field %s = %d, want sentinel %d (withDefaults maps it to the wrong source field)",
				got.Type().Field(i).Name, got.Field(i).Int(), want)
		}
	}

	if got := validDefinition().normalized().Limits; got != DefaultLimits() {
		t.Errorf("normalized zero Limits = %+v, want DefaultLimits() %+v", got, DefaultLimits())
	}
}

func TestToolFilterPermits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		filter ToolFilter
		raw    string
		want   bool
	}{
		{name: "empty filter allows all", filter: ToolFilter{}, raw: "anything", want: true},
		{name: "empty allow permits unlisted", filter: ToolFilter{Deny: []string{"rm"}}, raw: "ls", want: true},
		{name: "deny wins with empty allow", filter: ToolFilter{Deny: []string{"rm"}}, raw: "rm", want: false},
		{name: "allow list permits member", filter: ToolFilter{Allow: []string{"ls", "cat"}}, raw: "cat", want: true},
		{name: "allow list blocks non-member", filter: ToolFilter{Allow: []string{"ls", "cat"}}, raw: "rm", want: false},
		{name: "deny wins over allow", filter: ToolFilter{Allow: []string{"rm"}, Deny: []string{"rm"}}, raw: "rm", want: false},
		{name: "exact match only, not prefix", filter: ToolFilter{Allow: []string{"ls"}}, raw: "ls-extra", want: false},
		{name: "exact match only, case sensitive", filter: ToolFilter{Allow: []string{"ls"}}, raw: "LS", want: false},
		{name: "deny exact match only", filter: ToolFilter{Deny: []string{"rm"}}, raw: "rm ", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.filter.Permits(tt.raw); got != tt.want {
				t.Errorf("Permits(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestToolFilterValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		filter  ToolFilter
		wantErr bool
		field   string
	}{
		{name: "empty filter valid", filter: ToolFilter{}, wantErr: false},
		{name: "distinct entries valid", filter: ToolFilter{Allow: []string{"a", "b"}, Deny: []string{"c"}}, wantErr: false},
		{name: "same entry across sets valid", filter: ToolFilter{Allow: []string{"a"}, Deny: []string{"a"}}, wantErr: false},
		{name: "empty allow entry", filter: ToolFilter{Allow: []string{""}}, wantErr: true, field: "ToolFilter.Allow"},
		{name: "empty deny entry", filter: ToolFilter{Deny: []string{""}}, wantErr: true, field: "ToolFilter.Deny"},
		{name: "duplicate allow entry", filter: ToolFilter{Allow: []string{"a", "a"}}, wantErr: true, field: "ToolFilter.Allow"},
		{name: "duplicate deny entry", filter: ToolFilter{Deny: []string{"b", "c", "b"}}, wantErr: true, field: "ToolFilter.Deny"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			def := validDefinition()
			def.ToolFilter = tt.filter
			err := def.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				assertInvalidConfig(t, err, def.Name, tt.field)
			}
		})
	}
}

func TestDefinitionValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Definition)
		wantErr bool
		field   string
	}{
		{name: "valid definition passes", mutate: func(*Definition) {}, wantErr: false},
		{name: "nil transport", mutate: func(d *Definition) { d.Transport = nil }, wantErr: true, field: "Transport"},
		{name: "invalid name", mutate: func(d *Definition) { d.Name = "-bad" }, wantErr: true, field: "name"},
		{name: "negative timeout propagates", mutate: func(d *Definition) { d.Timeouts.Request = -1 }, wantErr: true, field: "Timeouts.Request"},
		{name: "negative limit propagates", mutate: func(d *Definition) { d.Limits.MaxSchemaDepth = -1 }, wantErr: true, field: "Limits.MaxSchemaDepth"},
		{name: "bad filter propagates", mutate: func(d *Definition) { d.ToolFilter.Allow = []string{""} }, wantErr: true, field: "ToolFilter.Allow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			def := validDefinition()
			tt.mutate(&def)
			err := def.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				assertInvalidConfig(t, err, def.Name, tt.field)
			}
		})
	}
}

// TestNormalizedDeepCopiesFilter proves normalized() detaches the ToolFilter
// slices: mutating the original after normalization must not leak into the
// copy, and vice versa.
func TestNormalizedDeepCopiesFilter(t *testing.T) {
	t.Parallel()

	def := validDefinition()
	def.ToolFilter = ToolFilter{Allow: []string{"ls", "cat"}, Deny: []string{"rm"}}
	norm := def.normalized()

	def.ToolFilter.Allow[0] = "mutated"
	def.ToolFilter.Deny[0] = "mutated"

	if norm.ToolFilter.Allow[0] != "ls" {
		t.Errorf("normalized Allow[0] = %q, want %q (slice shared with original)", norm.ToolFilter.Allow[0], "ls")
	}
	if norm.ToolFilter.Deny[0] != "rm" {
		t.Errorf("normalized Deny[0] = %q, want %q (slice shared with original)", norm.ToolFilter.Deny[0], "rm")
	}
}

func TestValidateDoesNotMutate(t *testing.T) {
	t.Parallel()

	def := validDefinition()
	if err := def.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if def.Timeouts != (Timeouts{}) {
		t.Errorf("Validate mutated Timeouts to %+v, want zero value", def.Timeouts)
	}
	if def.Limits != (Limits{}) {
		t.Errorf("Validate mutated Limits to %+v, want zero value", def.Limits)
	}
}

// assertInvalidConfig checks err is a *Error with class FailureInvalidConfig,
// op "validate", the expected binding, and a message naming wantField.
func assertInvalidConfig(t *testing.T, err error, binding Name, wantField string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	class, ok := ClassOf(err)
	if !ok || class != FailureInvalidConfig {
		t.Fatalf("ClassOf(%v) = %v, %v; want %v, true", err, class, ok, FailureInvalidConfig)
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not *Error", err)
	}
	if e.Op != "validate" {
		t.Errorf("Op = %q, want %q", e.Op, "validate")
	}
	if e.Binding != binding {
		t.Errorf("Binding = %q, want %q", e.Binding, binding)
	}
	if !strings.Contains(e.Msg, wantField) {
		t.Errorf("Msg = %q, want it to name field %q", e.Msg, wantField)
	}
}
