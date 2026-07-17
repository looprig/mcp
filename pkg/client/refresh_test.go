package client

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
)

// notify delivers a list-change notification the way a real one arrives: through
// the OnListChanged callback the client installed on the ConnectConfig it handed
// the transport. Nothing in the test reaches into the client to trigger a
// refresh — a client that failed to install the callback fails these tests.
func notify(t *testing.T, tr *fakeTransport, f protocol.ListFamily) {
	t.Helper()
	cb := tr.lastConfig().OnListChanged
	if cb == nil {
		t.Fatal("the client installed no OnListChanged callback: no notification can reach it")
	}
	cb(protocol.ListChange{Family: f})
}

// waitFor polls until cond holds, failing the test if it never does. Refresh is
// asynchronous by design — the notification returns before the fetch starts —
// so a test either polls or races.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fastRefresh gives a definition a refresh policy with no real delays, so a
// bounded-retry test costs milliseconds rather than seconds. Attempts is left at
// the caller's choice; everything else is as small as it can be while remaining
// a legal policy.
func fastRefresh(d Definition, attempts int) Definition {
	d.Refresh = RetryPolicy{
		Attempts:  attempts,
		BaseDelay: time.Millisecond,
		MaxDelay:  time.Millisecond,
		MaxTotal:  time.Minute,
	}
	return d
}

// eventsOf returns every event of type E the recorder saw, in order.
func eventsOf[E Event](r *eventRecorder) []E {
	var out []E
	for _, e := range r.snapshot() {
		if typed, ok := e.(E); ok {
			out = append(out, typed)
		}
	}
	return out
}

// TestRefreshPublishesCandidateWithoutAdopting is the core of the design's
// change-notification sequence: a server that changes its tools produces a
// candidate, and the binding keeps serving the generation it already adopted
// until the caller says otherwise.
func TestRefreshPublishesCandidateWithoutAdopting(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)
	rec := &eventRecorder{}

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	if got := c.Catalog().Generation; got != 1 {
		t.Fatalf("adopted generation = %d, want 1 after startup", got)
	}
	if _, ok := c.Candidate(); ok {
		t.Fatal("Candidate() reports one before any notification")
	}

	// The server grows a tool and says so.
	conn.setTools(fakeTool("echo"), fakeTool("echo2"))
	notify(t, tr, protocol.ListFamilyTools)

	waitFor(t, "a candidate", func() bool { _, ok := c.Candidate(); return ok })

	cand, _ := c.Candidate()
	if cand.Generation != 2 {
		t.Errorf("candidate generation = %d, want 2", cand.Generation)
	}
	if _, ok := cand.ToolByRawName("echo2"); !ok {
		t.Error("the candidate does not carry the tool the server added")
	}

	// The load-bearing assertion: the client did not adopt. A client that
	// self-adopted would change what a model sees mid-turn, which is the one
	// thing the candidate/adopted split exists to prevent.
	adopted := c.Catalog()
	if adopted.Generation != 1 {
		t.Errorf("adopted generation = %d after a notification, want 1: the client adopted by itself", adopted.Generation)
	}
	if _, ok := adopted.ToolByRawName("echo2"); ok {
		t.Error("the adopted catalog gained a tool without Adopt being called")
	}

	// Status reports both, which is how an application sees an adoption is due.
	st := c.Status()
	if st.CandidateGeneration != 2 || st.CandidateDigest != cand.Digest {
		t.Errorf("Status() candidate = (%d, %q), want (2, %q)", st.CandidateGeneration, st.CandidateDigest, cand.Digest)
	}
	if st.CatalogGeneration != 1 {
		t.Errorf("Status().CatalogGeneration = %d, want 1", st.CatalogGeneration)
	}

	// The candidate event carries the facts a caller schedules adoption from.
	cands := eventsOf[CatalogCandidate](rec)
	if len(cands) != 1 {
		t.Fatalf("CatalogCandidate events = %d, want 1", len(cands))
	}
	if cands[0].Generation != 2 || cands[0].Adopted != 1 || cands[0].Digest != cand.Digest {
		t.Errorf("CatalogCandidate = %+v, want generation 2 over adopted 1 with digest %q", cands[0], cand.Digest)
	}
	// And the family that went stale was reported when it went stale.
	stales := eventsOf[CatalogStale](rec)
	if len(stales) != 1 || stales[0].Family != "tools" {
		t.Errorf("CatalogStale events = %+v, want one for the tools family", stales)
	}

	// Now the caller adopts, at a boundary only it knows is safe.
	if err := c.Adopt(2); err != nil {
		t.Fatalf("Adopt(2) error = %v", err)
	}
	adopted = c.Catalog()
	if adopted.Generation != 2 {
		t.Errorf("adopted generation = %d after Adopt(2), want 2", adopted.Generation)
	}
	if _, ok := adopted.ToolByRawName("echo2"); !ok {
		t.Error("the adopted catalog does not carry the new tool after Adopt")
	}
	if _, ok := c.Candidate(); ok {
		t.Error("Candidate() still reports one after it was adopted")
	}

	adopts := eventsOf[CatalogAdopted](rec)
	if len(adopts) != 1 {
		t.Fatalf("CatalogAdopted events = %d, want 1", len(adopts))
	}
	if adopts[0].Generation != 2 || adopts[0].Previous != 1 {
		t.Errorf("CatalogAdopted = %+v, want generation 2 replacing 1", adopts[0])
	}
}

// TestRefreshUnchangedCatalogPublishesNoCandidate covers the design's compare
// step. A server may announce a change that changes nothing this binding sees —
// the design calls this out for prompts and resources refreshing without
// touching model-facing tools — and a candidate for it would ask the caller to
// swap a toolset for an identical toolset.
func TestRefreshUnchangedCatalogPublishesNoCandidate(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)
	rec := &eventRecorder{}

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	before := conn.toolLists.Load()
	notify(t, tr, protocol.ListFamilyTools) // the tools did not actually change

	waitFor(t, "the refetch", func() bool { return conn.toolLists.Load() > before })
	waitFor(t, "a refreshed event", func() bool { return len(eventsOf[CatalogRefreshed](rec)) == 1 })

	if _, ok := c.Candidate(); ok {
		t.Error("Candidate() reports one for a catalog that did not change")
	}
	if len(eventsOf[CatalogCandidate](rec)) != 0 {
		t.Error("a CatalogCandidate was published for a catalog that did not change")
	}
	refreshed := eventsOf[CatalogRefreshed](rec)[0]
	if refreshed.Generation != 1 {
		t.Errorf("CatalogRefreshed.Generation = %d, want the adopted 1", refreshed.Generation)
	}
	if c.Catalog().Generation != 1 {
		t.Errorf("adopted generation = %d, want an unchanged 1", c.Catalog().Generation)
	}
}

// TestRefreshRevertedChangeWithdrawsCandidate: a candidate that describes a
// change the server has since undone is not stale, it is wrong. Leaving it
// adoptable would let a caller install a catalog the server no longer serves.
func TestRefreshRevertedChangeWithdrawsCandidate(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	conn.setTools(fakeTool("echo"), fakeTool("echo2"))
	notify(t, tr, protocol.ListFamilyTools)
	waitFor(t, "a candidate", func() bool { _, ok := c.Candidate(); return ok })

	// The server puts it back.
	conn.setTools(fakeTool("echo"))
	notify(t, tr, protocol.ListFamilyTools)

	waitFor(t, "the candidate to be withdrawn", func() bool { _, ok := c.Candidate(); return !ok })
	if st := c.Status(); st.CandidateGeneration != 0 || st.CandidateDigest != "" {
		t.Errorf("Status() still reports candidate (%d, %q) after the change was reverted", st.CandidateGeneration, st.CandidateDigest)
	}
}

// TestAdoptRejectsUnvalidatedGenerations is the other half of the client's
// contract: the caller decides when, the client decides what. Every value that
// is not the outstanding candidate's ordinal is refused, so a caller cannot
// adopt a generation it never saw.
func TestAdoptRejectsUnvalidatedGenerations(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	// No candidate at all: nothing is adoptable, not even the adopted one.
	for _, gen := range []uint64{0, 1, 2, 99} {
		err := c.Adopt(gen)
		if class, ok := ClassOf(err); !ok || class != FailureCatalogStale {
			t.Errorf("Adopt(%d) with no candidate: error = %v (class %v), want FailureCatalogStale", gen, err, class)
		}
	}

	conn.setTools(fakeTool("echo"), fakeTool("echo2"))
	notify(t, tr, protocol.ListFamilyTools)
	waitFor(t, "a candidate", func() bool { _, ok := c.Candidate(); return ok })

	// A candidate exists, but only its own ordinal names it.
	for _, gen := range []uint64{0, 1, 3, 99} {
		err := c.Adopt(gen)
		if class, ok := ClassOf(err); !ok || class != FailureCatalogStale {
			t.Errorf("Adopt(%d) against candidate 2: error = %v (class %v), want FailureCatalogStale", gen, err, class)
		}
	}
	if c.Catalog().Generation != 1 {
		t.Fatal("a refused Adopt changed the adopted generation")
	}

	if err := c.Adopt(2); err != nil {
		t.Fatalf("Adopt(2) error = %v", err)
	}
	// A generation is adopted once: the candidate is consumed, so a duplicate
	// or late Adopt — a retry, a second caller — cannot re-run it.
	err = c.Adopt(2)
	if class, ok := ClassOf(err); !ok || class != FailureCatalogStale {
		t.Errorf("second Adopt(2): error = %v (class %v), want FailureCatalogStale", err, class)
	}
}

// TestAdoptSupersededCandidate is the race the design's step 7 implies: a caller
// reads a candidate, takes time to reach a safe boundary, and a second
// notification supersedes it in the meantime. Adopting by ordinal is what makes
// that safe — the caller's decision was about the catalog it read, and a client
// that resolved "adopt" to "whatever is current" would silently install a
// catalog nobody approved.
func TestAdoptSupersededCandidate(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	conn.setTools(fakeTool("echo"), fakeTool("echo2"))
	notify(t, tr, protocol.ListFamilyTools)
	waitFor(t, "the first candidate", func() bool {
		cand, ok := c.Candidate()
		return ok && cand.Generation == 2
	})

	// The caller is now on its way to Adopt(2). The server changes again first.
	conn.setTools(fakeTool("echo"), fakeTool("echo2"), fakeTool("echo3"))
	notify(t, tr, protocol.ListFamilyTools)
	waitFor(t, "the superseding candidate", func() bool {
		cand, ok := c.Candidate()
		return ok && cand.Generation == 3
	})

	err = c.Adopt(2)
	if class, ok := ClassOf(err); !ok || class != FailureCatalogStale {
		t.Fatalf("Adopt(2) after being superseded: error = %v (class %v), want FailureCatalogStale", err, class)
	}
	if c.Catalog().Generation != 1 {
		t.Error("a superseded Adopt changed the adopted generation")
	}
	// The error must name the candidate that is actually outstanding, so the
	// caller can re-decide rather than guess.
	if got := err.Error(); !strings.Contains(got, "generation 3") {
		t.Errorf("Adopt error = %q, want it to name the outstanding candidate (generation 3)", got)
	}

	if err := c.Adopt(3); err != nil {
		t.Fatalf("Adopt(3) error = %v", err)
	}
	if got := c.Catalog().Generation; got != 3 {
		t.Errorf("adopted generation = %d, want 3", got)
	}
}

// TestRefreshFailureKeepsAdoptedGeneration is the design's rule that a failed
// refresh changes nothing: the prior generation stays adopted, the binding
// reports degraded rather than failed, and the retry is bounded.
func TestRefreshFailureKeepsAdoptedGeneration(t *testing.T) {
	t.Parallel()

	const attempts = 3

	conn := okConn()
	tr := newFakeTransport(conn)
	rec := &eventRecorder{}

	c, err := Connect(context.Background(), fastRefresh(okDefinition(tr), attempts), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	digestBefore := c.Catalog().Digest
	listsBefore := conn.toolLists.Load()

	// The server changes its tools and then stops answering list calls.
	conn.setTools(fakeTool("echo"), fakeTool("echo2"))
	conn.setListErr(errors.New("server is having a bad day"))
	notify(t, tr, protocol.ListFamilyTools)

	waitFor(t, "the retries to be exhausted", func() bool {
		return len(eventsOf[CatalogRejected](rec)) == attempts
	})

	// Bounded: exactly the policy's attempts, no more. A poll for a moment
	// longer proves the loop stopped rather than merely being observed early.
	time.Sleep(50 * time.Millisecond)
	rejected := eventsOf[CatalogRejected](rec)
	if len(rejected) != attempts {
		t.Errorf("CatalogRejected events = %d, want exactly the policy's %d attempts", len(rejected), attempts)
	}
	if got := int(conn.toolLists.Load() - listsBefore); got != attempts {
		t.Errorf("tools/list calls = %d, want exactly the policy's %d attempts", got, attempts)
	}
	// Every attempt but the last says it will try again; the last says it will
	// not. That is what tells an operator the difference between "retrying" and
	// "given up".
	for i, ev := range rejected {
		want := i < attempts-1
		if ev.Retrying != want {
			t.Errorf("CatalogRejected[%d].Retrying = %v, want %v", i, ev.Retrying, want)
		}
		if ev.Adopted != 1 {
			t.Errorf("CatalogRejected[%d].Adopted = %d, want the still-adopted 1", i, ev.Adopted)
		}
		if ev.Message == "" {
			t.Errorf("CatalogRejected[%d] carries no message", i)
		}
	}

	// The adopted catalog is untouched, and the binding still serves it.
	got := c.Catalog()
	if got.Generation != 1 || got.Digest != digestBefore {
		t.Errorf("adopted catalog = (gen %d, %q), want the unchanged (gen 1, %q)", got.Generation, got.Digest, digestBefore)
	}
	if _, ok := c.Candidate(); ok {
		t.Error("Candidate() reports one after every refresh failed")
	}
	st := c.Status()
	if st.State != StateDegraded {
		t.Errorf("State = %v, want %v: a binding whose refresh failed still serves its adopted catalog", st.State, StateDegraded)
	}
	if !slices.Equal(st.StaleFamilies, []string{"tools"}) {
		t.Errorf("Status().StaleFamilies = %v, want [tools]: the announced change was never fetched", st.StaleFamilies)
	}
	if _, err := c.CallTool(context.Background(), "echo", nil, CallOpts{}); err != nil {
		t.Errorf("CallTool on a degraded binding: error = %v, want it to still serve", err)
	}

	// And it recovers: the server starts answering, a later notification lands,
	// and the binding returns to ready with a candidate.
	conn.setListErr(nil)
	notify(t, tr, protocol.ListFamilyTools)
	waitFor(t, "recovery", func() bool {
		_, ok := c.Candidate()
		return ok && c.Status().State == StateReady
	})
	if fams := c.Status().StaleFamilies; len(fams) != 0 {
		t.Errorf("Status().StaleFamilies = %v after a successful refresh, want none", fams)
	}
}

// TestRefreshCoalescesNotifications covers the design's step 2. A server that
// announces ten changes in a burst is describing one eventual catalog: what must
// hold is that a fetch starts after the last notification, not that ten fetches
// run.
func TestRefreshCoalescesNotifications(t *testing.T) {
	t.Parallel()

	const burst = 10

	conn := okConn()
	// A gate on tools/list, so the first refresh can be held open for the whole
	// burst. Without it the test would be a race between the notifications and
	// the worker, and would pass for the wrong reason.
	conn.listEntered = make(chan struct{})
	conn.listGate = make(chan struct{})
	tr := newFakeTransport(conn)

	// Startup discovers too, so let its fetch through first.
	go func() {
		<-conn.listEntered
		conn.listGate <- struct{}{}
	}()

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	conn.setTools(fakeTool("echo"), fakeTool("echo2"))

	// Every notification of the burst lands while the first refresh is held
	// inside its fetch. They can only be answered by a pass that has not started
	// yet — which is exactly one pass, because a pass carries no information and
	// two of them would do identical work.
	notify(t, tr, protocol.ListFamilyTools)
	<-conn.listEntered // the first refresh is now inside tools/list
	for range burst - 1 {
		notify(t, tr, protocol.ListFamilyTools)
	}

	listsAtBurst := conn.toolLists.Load()
	conn.listGate <- struct{}{} // release the first refresh
	<-conn.listEntered          // the coalesced pass starts
	conn.listGate <- struct{}{} // release it too

	waitFor(t, "a candidate", func() bool { _, ok := c.Candidate(); return ok })
	// Settle: if a third pass were queued it would enter tools/list here and
	// block on the gate, which the count below would catch.
	time.Sleep(50 * time.Millisecond)

	passes := conn.toolLists.Load() - listsAtBurst + 1
	if passes != 2 {
		t.Errorf("refresh passes for a burst of %d notifications = %d, want 2 (the one in flight, plus one coalesced)", burst, passes)
	}
}

// TestRefreshIgnoresUnknownFamily: the family on a notification is this module's
// own enum, but the mapping from it is exhaustive-by-default rather than
// permissive. A value outside the declared range marks nothing stale and starts
// no fetch, instead of being guessed at.
func TestRefreshIgnoresUnknownFamily(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)
	rec := &eventRecorder{}

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{Event: rec.handle})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	before := conn.toolLists.Load()
	tr.lastConfig().OnListChanged(protocol.ListChange{Family: protocol.ListFamily(200)})
	tr.lastConfig().OnListChanged(protocol.ListChange{}) // the zero value is not a family either

	time.Sleep(50 * time.Millisecond)
	if got := conn.toolLists.Load(); got != before {
		t.Errorf("tools/list calls = %d after an unknown family, want an unchanged %d", got, before)
	}
	if evs := eventsOf[CatalogStale](rec); len(evs) != 0 {
		t.Errorf("CatalogStale events = %+v, want none for an unknown family", evs)
	}
	if fams := c.Status().StaleFamilies; len(fams) != 0 {
		t.Errorf("Status().StaleFamilies = %v, want none for an unknown family", fams)
	}
}

// TestRefreshFamiliesAllMarkStale sweeps the declared families: each one a
// server can announce must reach the client as its own stale family, so a
// prompts change is not silently read as a tools change (or as nothing).
func TestRefreshFamiliesAllMarkStale(t *testing.T) {
	t.Parallel()

	tests := []struct {
		family protocol.ListFamily
		want   string
	}{
		{protocol.ListFamilyTools, "tools"},
		{protocol.ListFamilyPrompts, "prompts"},
		{protocol.ListFamilyResources, "resources"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			conn := okConn()
			tr := newFakeTransport(conn)
			rec := &eventRecorder{}

			c, err := Connect(context.Background(), fastRefresh(okDefinition(tr), 1), Handlers{Event: rec.handle})
			if err != nil {
				t.Fatalf("Connect() error = %v", err)
			}
			defer func() { _ = c.Close(context.Background()) }()

			// A failing list keeps the family stale, so the mark stays
			// observable rather than being erased by the refetch that answers
			// it. It goes on after startup, which needs a working list.
			conn.setListErr(errors.New("no lists today"))

			notify(t, tr, tt.family)
			waitFor(t, "the stale mark", func() bool {
				return slices.Equal(c.Status().StaleFamilies, []string{tt.want})
			})
			stales := eventsOf[CatalogStale](rec)
			if len(stales) != 1 || stales[0].Family != tt.want {
				t.Errorf("CatalogStale events = %+v, want one for %q", stales, tt.want)
			}
		})
	}
}

// TestAdoptAfterCloseIsRefused: adoption is a live-binding operation. A closed
// binding has no boundary to be safe at and nothing to serve the catalog with.
func TestAdoptAfterCloseIsRefused(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	conn.setTools(fakeTool("echo"), fakeTool("echo2"))
	notify(t, tr, protocol.ListFamilyTools)
	waitFor(t, "a candidate", func() bool { _, ok := c.Candidate(); return ok })

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	err = c.Adopt(2)
	if class, ok := ClassOf(err); !ok || class != FailureShutdown {
		t.Errorf("Adopt after Close: error = %v (class %v), want FailureShutdown", err, class)
	}
	if c.Catalog().Generation != 1 {
		t.Error("Adopt on a closed binding changed its catalog")
	}
}

// TestCloseStopsRefreshing proves the worker is bound to the client's lifetime:
// after Close, a notification that arrives late (a straggler on the connection's
// notification goroutine) starts no fetch.
func TestCloseStopsRefreshing(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	before := conn.toolLists.Load()
	conn.setTools(fakeTool("echo"), fakeTool("echo2"))
	notify(t, tr, protocol.ListFamilyTools)

	time.Sleep(50 * time.Millisecond)
	if got := conn.toolLists.Load(); got != before {
		t.Errorf("tools/list calls = %d after Close, want an unchanged %d", got, before)
	}
	if _, ok := c.Candidate(); ok {
		t.Error("a closed binding produced a candidate")
	}
}

// TestRefreshConcurrentWithAdopt drives the two racing paths at once under -race:
// the refresher writing candidates and a caller adopting them. Whatever the
// interleaving, the invariants hold — the adopted generation only ever moves
// forward, and only ever to a generation the client validated.
func TestRefreshConcurrentWithAdopt(t *testing.T) {
	t.Parallel()

	conn := okConn()
	tr := newFakeTransport(conn)

	c, err := Connect(context.Background(), okDefinition(tr), Handlers{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer func() { _ = c.Close(context.Background()) }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 30 {
			tools := []protocol.ToolSpec{fakeTool("echo")}
			for j := range i % 5 {
				tools = append(tools, fakeTool(fmt.Sprintf("tool%d", j)))
			}
			conn.setTools(tools...)
			notify(t, tr, protocol.ListFamilyTools)
			time.Sleep(time.Millisecond)
		}
	}()

	var last uint64 = 1
	for {
		select {
		case <-done:
			return
		default:
		}
		cand, ok := c.Candidate()
		if !ok {
			continue
		}
		// A refresh may supersede the candidate between the read and the adopt;
		// that is the race, and a stale error is its correct outcome.
		if err := c.Adopt(cand.Generation); err != nil {
			if class, _ := ClassOf(err); class != FailureCatalogStale {
				t.Errorf("Adopt(%d) error = %v, want nil or FailureCatalogStale", cand.Generation, err)
			}
			continue
		}
		got := c.Catalog().Generation
		if got != cand.Generation {
			t.Fatalf("adopted generation = %d after Adopt(%d)", got, cand.Generation)
		}
		if got < last {
			t.Fatalf("adopted generation went backwards: %d after %d", got, last)
		}
		last = got
	}
}
