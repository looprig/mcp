package mcpharness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/event"
)

// unboundDeps is a Deps for the discover-then-create flow: everything the
// application already owns, and no Session, because there is not one yet.
func unboundDeps(events EventPublisher) Deps {
	return Deps{Gates: stubGates{}, Events: events}
}

// fingerprintedBinding is a binding with the startup posture a binding whose
// identity reaches a config fingerprint must have.
//
// Required is not decoration here, it is the precondition ConfigIdentity
// documents: Start returns once the REQUIRED bindings have settled and leaves the
// optional ones connecting, so a digest taken over an optional binding may be
// taken before its catalog exists and differ from one taken a moment later. An
// application that stamps a fingerprint from a binding is an application that
// cannot come up without it, which is what Required already means.
func fingerprintedBinding(name string, t *scriptedTransport) Binding {
	return requiredBinding(scriptedBinding(name, ScopeSession, t))
}

// TestConfigDigestIsRealBeforeAnySessionExists is the claim the whole seam is for.
//
// It is the ordering 2026-07-16-session-versioning-migration-design.md
// §Configuration freeze and adoption mandates — discover, THEN create — and until
// BindSession existed it was unreachable: Deps.SessionID was required, so the
// Manager whose digest a Session needs could not be built before that Session.
// A first run therefore stamped an empty rev while every later run computed a real
// one, which is a permanent spurious mismatch for every application that uses MCP.
//
// The assertion is deliberately about the digest being REAL, not merely non-empty
// and not merely equal to itself: it must be the same digest a bound Manager over
// the same configuration reports, or the pre-session value would be a different
// thing wearing the same field.
func TestConfigDigestIsRealBeforeAnySessionExists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	unbound, err := NewManager(
		[]Binding{fingerprintedBinding("github", okTransport("github-server", "search"))},
		unboundDeps(&capturingEvents{}),
	)
	if err != nil {
		t.Fatalf("NewManager without a Session: %v", err)
	}
	t.Cleanup(func() { _ = unbound.Close(ctx) })
	if err := unbound.Start(ctx); err != nil {
		t.Fatalf("Start without a Session: %v", err)
	}

	rev := unbound.ConfigDigest()
	if rev == "" {
		t.Fatal("ConfigDigest before a Session is empty: an application would stamp \"no external capability\" into the fingerprint of a Session that has MCP servers, and mismatch against itself forever")
	}

	// The negotiated half is real, not just the configuration half: a digest that
	// only covered what was declared would be computable without connecting and
	// would not be the thing a restore compares.
	ids := unbound.ConfigIdentity()
	if len(ids) != 1 {
		t.Fatalf("ConfigIdentity() = %d bindings, want 1", len(ids))
	}
	if ids[0].Server.Name == "" || ids[0].CatalogDigest == "" {
		t.Errorf("ConfigIdentity() before a Session = %+v, want a negotiated server identity and an adopted catalog: discovery must really have happened", ids[0])
	}

	// And it is the same configuration a bound Manager reports, so the value an
	// application stamps at creation is the value it recomputes at restore.
	bound, err := NewManager(
		[]Binding{fingerprintedBinding("github", okTransport("github-server", "search"))},
		testDeps(),
	)
	if err != nil {
		t.Fatalf("NewManager with a Session: %v", err)
	}
	t.Cleanup(func() { _ = bound.Close(ctx) })
	if err := bound.Start(ctx); err != nil {
		t.Fatalf("Start with a Session: %v", err)
	}
	if got := bound.ConfigDigest(); got != rev {
		t.Errorf("ConfigDigest() = %q bound and %q unbound; the Session must not be part of the MCP configuration's identity", got, rev)
	}
}

// TestBindSessionRepublishesEveryBindingsStatus is the repair for the window the
// seam opens: statuses raised before there is a Session are dropped, so the
// Session's stream must open knowing what its servers are anyway.
func TestBindSessionRepublishesEveryBindingsStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	events := &capturingEvents{}

	m, err := NewManager(
		[]Binding{
			fingerprintedBinding("github", okTransport("github-server", "search")),
			fingerprintedBinding("docs", okTransport("docs-server", "lookup")),
		},
		unboundDeps(events),
	)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(ctx) })
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Nothing was published: there was no Session to publish to, and a
	// session-scoped event without one is refused by ValidateEvent anyway.
	if got := events.statuses(); len(got) != 0 {
		t.Fatalf("an unbound Manager published %d status(es), want 0: they have no Session to belong to", len(got))
	}

	if err := m.BindSession(sessionID); err != nil {
		t.Fatalf("BindSession: %v", err)
	}

	// Both bindings report, addressed to the Session, at the state they are
	// actually in — not replayed history.
	ready := map[string]bool{}
	for _, s := range events.statuses() {
		if s.Coordinates.SessionID != sessionID {
			t.Errorf("a republished status is addressed to %v, want the bound Session %v", s.Coordinates.SessionID, sessionID)
		}
		if s.State == event.IntegrationReady {
			ready[s.Name] = true
		}
	}
	for _, name := range []string{"github", "docs"} {
		if !ready[name] {
			t.Errorf("binding %q never reported ready to the Session it serves; its status was lost to the pre-Session window", name)
		}
	}
}

// TestStatusesFlowAfterBindSession proves the seam does not merely replay once and
// then go quiet: a Manager bound late must publish live events like any other.
func TestStatusesFlowAfterBindSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	events := &capturingEvents{}

	m, err := NewManager(nil, unboundDeps(events))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(ctx) })
	if err := m.BindSession(sessionID); err != nil {
		t.Fatalf("BindSession: %v", err)
	}
	m.publish(m.status("github", event.IntegrationDegraded, "detail"))

	got := events.statuses()
	if len(got) != 1 {
		t.Fatalf("statuses after BindSession = %d, want 1", len(got))
	}
	if got[0].Coordinates.SessionID != sessionID {
		t.Errorf("status addressed to %v, want %v", got[0].Coordinates.SessionID, sessionID)
	}
}

func TestBindSessionRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// setup returns a Manager and the ID to bind.
		setup   func(t *testing.T) (*Manager, uuid.UUID)
		wantErr error
		wantMsg string
	}{
		{
			// The zero ID is exactly the value the required-SessionID check used
			// to catch. Moving the check does not mean dropping it.
			name: "zero session id",
			setup: func(t *testing.T) (*Manager, uuid.UUID) {
				return newUnbound(t), uuid.UUID{}
			},
			wantMsg: "sessionID is zero",
		},
		{
			// A Manager's connections, elicitation routes and Session-breadth
			// approvals belong to one Session.
			name: "second bind",
			setup: func(t *testing.T) (*Manager, uuid.UUID) {
				m := newUnbound(t)
				if err := m.BindSession(sessionID); err != nil {
					t.Fatalf("first BindSession: %v", err)
				}
				return m, uuid.MustParse("66666666-6666-4666-8666-666666666666")
			},
			wantErr: ErrAlreadyBound,
		},
		{
			name: "manager built with a session id is already bound",
			setup: func(t *testing.T) (*Manager, uuid.UUID) {
				m, err := NewManager(nil, testDeps())
				if err != nil {
					t.Fatalf("NewManager: %v", err)
				}
				t.Cleanup(func() { _ = m.Close(context.Background()) })
				return m, sessionID
			},
			wantErr: ErrAlreadyBound,
		},
		{
			name: "closed manager",
			setup: func(t *testing.T) (*Manager, uuid.UUID) {
				m := newUnbound(t)
				if err := m.Close(context.Background()); err != nil {
					t.Fatalf("Close: %v", err)
				}
				return m, sessionID
			},
			wantErr: ErrManagerClosed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, id := tt.setup(t)
			err := m.BindSession(id)
			if err == nil {
				t.Fatalf("BindSession() = nil, want an error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("BindSession() = %v, want %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("BindSession() = %v, want an error containing %q", err, tt.wantMsg)
			}
		})
	}
}

// TestStartAdoptionRefusesAnUnboundManager is where a forgotten BindSession is
// caught. It has to be caught somewhere: an unbound Manager silently drops every
// integration status for the life of the Session, which is the kind of defect that
// is invisible until an operator needs it.
func TestStartAdoptionRefusesAnUnboundManager(t *testing.T) {
	t.Parallel()
	m := newUnbound(t)
	source := &fakeSource{sub: &fakeSubscription{events: make(chan event.Delivery, 1)}}
	_, err := m.StartAdoption(source, &fakeLoops{})
	if !errors.Is(err, ErrNotBound) {
		t.Fatalf("StartAdoption on an unbound Manager = %v, want ErrNotBound", err)
	}
}

func newUnbound(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(nil, unboundDeps(&capturingEvents{}))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	return m
}
