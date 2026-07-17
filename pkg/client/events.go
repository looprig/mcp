// This file defines the catalog members of the Event union and the client's
// event emitter.
//
// Every event is safe metadata by construction, which is a property of what the
// types can hold rather than of what the emitters remember to put in them: there
// is no field on any event here that can carry a credential, a tool argument, a
// resource body, or an unbounded string. The one free-text field an event has
// (Message, on the failure-shaped events) is filled from an *Error's already
// bounded Msg. See events_test.go, which sweeps the union by reflection and
// fails on a field that could hold anything else.
//
// The sealed Event interface and StateChanged live in handlers.go, next to the
// EventHandler that receives them.

package client

import "time"

// CatalogStale reports that a server announced a change to one of its catalog
// families. It means a refresh has been scheduled, not that anything has been
// fetched, validated, or adopted.
//
// It carries no delta: MCP's list-change notifications say only that a list
// changed, and a server's own account of how it changed would be untrusted
// input. What changed is knowable only from the candidate that follows.
type CatalogStale struct {
	// Binding names the binding whose catalog went stale.
	Binding Name
	// Family is the catalog family the server says changed: "tools",
	// "prompts", or "resources".
	Family string
	// At is when the notification was observed.
	At time.Time
}

// CatalogCandidate reports that a complete, validated generation was fetched and
// differs from the adopted one. It is the event a caller waits for before
// choosing a safe boundary at which to Adopt.
//
// The candidate is not adopted by this event. Nothing a Loop can see has changed
// yet — that is the point of the candidate/adopted split.
type CatalogCandidate struct {
	// Binding names the binding.
	Binding Name
	// Generation is the candidate's ordinal, and the value Adopt takes.
	Generation uint64
	// Digest is the candidate's hex catalog digest.
	Digest string
	// Adopted is the ordinal of the generation still in force.
	Adopted uint64
	// At is when the candidate was published.
	At time.Time
}

// CatalogRefreshed reports that a refresh completed and produced a catalog
// identical to the adopted one — the server announced a change that, once
// refetched and digested, turned out not to change what this binding sees.
//
// It is a distinct event from CatalogCandidate rather than a candidate nobody
// need adopt, because the two ask different things of a caller: a candidate
// needs a safe boundary and an Adopt, and this needs nothing at all. Publishing
// a no-op candidate would make every caller re-derive that distinction, and some
// would get it wrong by adopting — churning a toolset generation for a catalog
// that did not change.
type CatalogRefreshed struct {
	// Binding names the binding.
	Binding Name
	// Generation is the ordinal of the generation still in force.
	Generation uint64
	// Digest is its hex catalog digest.
	Digest string
	// At is when the refresh completed.
	At time.Time
}

// CatalogAdopted reports that a candidate became the binding's adopted
// generation, at the caller's request. It is the completion of the sequence
// CatalogStale -> CatalogCandidate -> (caller's safe boundary) -> Adopt.
type CatalogAdopted struct {
	// Binding names the binding.
	Binding Name
	// Generation is the newly adopted ordinal.
	Generation uint64
	// Digest is its hex catalog digest.
	Digest string
	// Previous is the ordinal it replaced, or 0 if there was none.
	Previous uint64
	// At is when adoption happened.
	At time.Time
}

// CatalogRejected reports that a refresh failed to produce a usable candidate:
// the server was unreachable, its catalog was defective, or it exceeded a bound.
//
// The prior adopted generation remains in force. A rejection never blanks a
// catalog that was valid — a server that starts answering badly makes its
// *changes* unavailable, not its existing tools.
type CatalogRejected struct {
	// Binding names the binding.
	Binding Name
	// Class classifies why the refresh failed.
	Class FailureClass
	// Message is the failure's bounded, normalized text.
	Message string
	// Adopted is the ordinal of the generation still in force.
	Adopted uint64
	// Retrying reports whether the binding will try again under its policy.
	Retrying bool
	// At is when the refresh failed.
	At time.Time
}

func (CatalogStale) event()     {}
func (CatalogCandidate) event() {}
func (CatalogRefreshed) event() {}
func (CatalogAdopted) event()   {}
func (CatalogRejected) event()  {}

// emit delivers e to the application's event handler, if it installed one.
//
// It is a method on Client rather than a bare call so that every emitter goes
// through one place: the handler is captured once at construction and read
// without a lock (it is immutable for the Client's life), and a nil handler is
// dropped here rather than at each of a dozen call sites.
//
// The handler runs on the emitting goroutine and blocks it, per EventHandler's
// contract. It is foreign code, so nothing this client guards may be held across
// this call — every caller here emits with c.mu released.
func (c *Client) emit(e Event) {
	if c.eventHandler == nil {
		return
	}
	c.eventHandler(e)
}
