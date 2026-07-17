package mcpharness

import (
	"strings"
	"testing"

	"github.com/looprig/core/uuid"
	"github.com/looprig/mcp/pkg/client"
)

func TestScopeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		scope Scope
		want  string
	}{
		{name: "session", scope: ScopeSession, want: "session"},
		{name: "loop", scope: ScopeLoop, want: "loop"},
		{name: "zero", scope: Scope(0), want: "unknown"},
		{name: "out of range", scope: Scope(200), want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.scope.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBindingValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		binding Binding
		wantErr string // a substring of the expected error; empty means no error
	}{
		{
			name: "session scope with a selector",
			binding: Binding{
				Name:       "github",
				Server:     testDefinition("github"),
				Scope:      ScopeSession,
				Visibility: AllLoops(),
			},
		},
		{
			name: "loop scope with an owner",
			binding: Binding{
				Name:   "browser",
				Server: testDefinition("browser"),
				Scope:  ScopeLoop,
				Loop:   loopA,
			},
		},
		{
			name: "required is orthogonal to scope",
			binding: Binding{
				Name:     "database",
				Server:   testDefinition("database"),
				Scope:    ScopeLoop,
				Loop:     loopA,
				Required: true,
			},
		},
		{
			name:    "empty name",
			binding: Binding{Name: "", Server: testDefinition(""), Scope: ScopeSession, Visibility: AllLoops()},
			wantErr: "Binding.Name",
		},
		{
			name: "over-long name",
			binding: Binding{
				Name:       strings.Repeat("a", client.MaxNameBytes+1),
				Server:     testDefinition(strings.Repeat("a", client.MaxNameBytes+1)),
				Scope:      ScopeSession,
				Visibility: AllLoops(),
			},
			wantErr: "Binding.Name",
		},
		{
			name:    "zero scope",
			binding: Binding{Name: "github", Server: testDefinition("github"), Visibility: AllLoops()},
			wantErr: "is not session or loop",
		},
		{
			name:    "unknown scope",
			binding: Binding{Name: "github", Server: testDefinition("github"), Scope: Scope(200), Visibility: AllLoops()},
			wantErr: "is not session or loop",
		},
		// The binding name qualifies the model-facing tool names while the
		// connection name goes out on the wire. A disagreement makes the
		// reverse mapping a lie, so it is a configuration error.
		{
			name:    "name disagrees with the connection",
			binding: Binding{Name: "github", Server: testDefinition("gitlab"), Scope: ScopeSession, Visibility: AllLoops()},
			wantErr: "must agree on the name",
		},
		{
			name:    "invalid connection",
			binding: Binding{Name: "github", Server: client.Definition{Name: "github"}, Scope: ScopeSession, Visibility: AllLoops()},
			wantErr: "Transport is nil",
		},
		// Scope-shaped rules. Each is a claim the runtime would not honor.
		{
			name: "session scope naming a Loop",
			binding: Binding{
				Name:       "github",
				Server:     testDefinition("github"),
				Scope:      ScopeSession,
				Loop:       loopA,
				Visibility: AllLoops(),
			},
			wantErr: "must not name a Loop",
		},
		{
			name:    "session scope without a selector",
			binding: Binding{Name: "github", Server: testDefinition("github"), Scope: ScopeSession},
			wantErr: "no selector was built",
		},
		{
			name:    "session scope with an empty selector",
			binding: Binding{Name: "github", Server: testDefinition("github"), Scope: ScopeSession, Visibility: Named()},
			wantErr: "selects no Loop",
		},
		{
			name:    "loop scope without an owner",
			binding: Binding{Name: "browser", Server: testDefinition("browser"), Scope: ScopeLoop},
			wantErr: "must name its owning Loop",
		},
		{
			name: "loop scope with a selector",
			binding: Binding{
				Name:       "browser",
				Server:     testDefinition("browser"),
				Scope:      ScopeLoop,
				Loop:       loopA,
				Visibility: AllLoops(),
			},
			wantErr: "must not set Visibility",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.binding.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestBindingPermits(t *testing.T) {
	t.Parallel()

	sessionAll := Binding{Name: "docs", Server: testDefinition("docs"), Scope: ScopeSession, Visibility: AllLoops()}
	sessionNamed := Binding{Name: "docs", Server: testDefinition("docs"), Scope: ScopeSession, Visibility: Named("researcher")}
	loopOwned := Binding{Name: "browser", Server: testDefinition("browser"), Scope: ScopeLoop, Loop: loopA}

	tests := []struct {
		name     string
		binding  Binding
		loopID   uuid.UUID
		loopName string
		want     bool
	}{
		{name: "session all reaches any loop", binding: sessionAll, loopID: loopB, loopName: "operator", want: true},
		{name: "session named reaches its loop", binding: sessionNamed, loopID: loopB, loopName: "researcher", want: true},
		{name: "session named denies another loop", binding: sessionNamed, loopID: loopB, loopName: "operator", want: false},

		{name: "loop scope reaches its owner", binding: loopOwned, loopID: loopA, loopName: "parent", want: true},
		// The delegation rule in miniature: a Loop-scoped binding is its
		// owner's alone. A delegate that shares its parent's name — or any
		// name at all — must not inherit the parent's private server.
		{name: "loop scope denies a delegate", binding: loopOwned, loopID: loopB, loopName: "parent", want: false},
		{name: "loop scope denies the zero loop", binding: loopOwned, loopName: "parent", want: false},
		{name: "unknown scope denies", binding: Binding{Scope: Scope(200)}, loopID: loopA, loopName: "researcher", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.binding.permits(tt.loopID, tt.loopName); got != tt.want {
				t.Errorf("permits(%v, %q) = %v, want %v", tt.loopID, tt.loopName, got, tt.want)
			}
		})
	}
}
