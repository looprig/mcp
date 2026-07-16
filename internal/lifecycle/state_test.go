package lifecycle

import (
	"errors"
	"regexp"
	"sync"
	"testing"
)

// allStates lists every declared State exactly once. Keep in sync with the
// const block in state.go; TestStateSentinelExhaustive proves it is exhaustive
// by comparing its length against stateSentinel, the unexported marker that
// must remain the final const in the block — any state appended before the
// sentinel bumps its value and fails the guard until it is listed here.
var allStates = []State{
	StateConfigured,
	StateStarting,
	StateAuthenticating,
	StateDiscovering,
	StateReady,
	StateDegraded,
	StateReconnecting,
	StateFailed,
	StateClosing,
	StateClosed,
}

// wantEdges is the expected transition table, declared independently of the
// implementation's own table so the two must agree. Keys are the source state;
// values are every legal destination from it. A state absent from the map (or
// present with an empty list) has no legal outgoing transition.
var wantEdges = map[State][]State{
	StateConfigured:     {StateStarting, StateClosing},
	StateStarting:       {StateAuthenticating, StateDiscovering, StateReady, StateFailed, StateClosing},
	StateAuthenticating: {StateDiscovering, StateReady, StateFailed, StateClosing},
	StateDiscovering:    {StateReady, StateFailed, StateClosing},
	StateReady:          {StateDegraded, StateReconnecting, StateFailed, StateClosing},
	StateDegraded:       {StateReady, StateReconnecting, StateFailed, StateClosing},
	StateReconnecting:   {StateAuthenticating, StateDiscovering, StateReady, StateDegraded, StateFailed, StateClosing},
	StateFailed:         {StateReconnecting, StateClosing},
	StateClosing:        {StateClosed},
	StateClosed:         nil,
}

func wantCanTransition(from, to State) bool {
	for _, dst := range wantEdges[from] {
		if dst == to {
			return true
		}
	}
	return false
}

func TestStateSentinelExhaustive(t *testing.T) {
	t.Parallel()

	if got, want := int(stateSentinel)-1, len(allStates); got != want {
		t.Fatalf("declared state count = %d, want %d (allStates out of sync with const block)", got, want)
	}
	if got, want := len(wantEdges), len(allStates); got != want {
		t.Fatalf("wantEdges covers %d states, want %d (a new state needs an expected edge list)", got, want)
	}
	for _, s := range allStates {
		if _, ok := wantEdges[s]; !ok {
			t.Errorf("state %v missing from wantEdges", s)
		}
	}
}

// TestCanTransitionExhaustive is the core test: it walks every (from, to) pair
// across all declared states — enumerated via the sentinel, so a newly declared
// state cannot slip past — and asserts CanTransition matches wantEdges.
func TestCanTransitionExhaustive(t *testing.T) {
	t.Parallel()

	for from := State(1); from < stateSentinel; from++ {
		for to := State(1); to < stateSentinel; to++ {
			want := wantCanTransition(from, to)
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%v, %v) = %v, want %v", from, to, got, want)
			}
		}
	}
}

func TestCanTransitionRejectsSelf(t *testing.T) {
	t.Parallel()

	for _, s := range allStates {
		if CanTransition(s, s) {
			t.Errorf("CanTransition(%v, %v) = true, want false (self-transition)", s, s)
		}
	}
}

func TestCanTransitionOutOfRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		from, to State
	}{
		{name: "zero from", from: State(0), to: StateStarting},
		{name: "zero to", from: StateConfigured, to: State(0)},
		{name: "zero both", from: State(0), to: State(0)},
		{name: "sentinel from", from: stateSentinel, to: StateStarting},
		{name: "sentinel to", from: StateConfigured, to: stateSentinel},
		{name: "max uint8 from", from: State(255), to: StateStarting},
		{name: "max uint8 to", from: StateConfigured, to: State(255)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if CanTransition(tt.from, tt.to) {
				t.Errorf("CanTransition(%d, %d) = true, want false", tt.from, tt.to)
			}
		})
	}
}

func TestCanTransitionClosedAbsorbing(t *testing.T) {
	t.Parallel()

	for to := State(1); to < stateSentinel; to++ {
		if CanTransition(StateClosed, to) {
			t.Errorf("CanTransition(closed, %v) = true, want false (closed is absorbing)", to)
		}
	}
}

// TestCanTransitionClosingReachable pins the shutdown-always-wins rule: every
// non-terminal state except closing itself may transition to closing.
func TestCanTransitionClosingReachable(t *testing.T) {
	t.Parallel()

	for _, s := range allStates {
		if s == StateClosing || s == StateClosed {
			continue
		}
		if !CanTransition(s, StateClosing) {
			t.Errorf("CanTransition(%v, closing) = false, want true", s)
		}
	}
}

func TestStateString(t *testing.T) {
	t.Parallel()

	snake := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	seenValues := make(map[State]bool, len(allStates))
	seenStrings := make(map[string]State, len(allStates))
	for _, s := range allStates {
		if s == 0 {
			t.Fatalf("declared state has zero value")
		}
		if seenValues[s] {
			t.Errorf("state value %d declared twice", s)
		}
		seenValues[s] = true

		str := s.String()
		if str == "unknown" {
			t.Errorf("state %d: String() = %q, want a declared identifier", s, str)
		}
		if !snake.MatchString(str) {
			t.Errorf("state %d: String() = %q, want lowercase identifier", s, str)
		}
		if prev, dup := seenStrings[str]; dup {
			t.Errorf("states %d and %d share String() %q", prev, s, str)
		}
		seenStrings[str] = s
	}
}

func TestStateStringUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state State
	}{
		{name: "zero value", state: State(0)},
		{name: "sentinel", state: stateSentinel},
		{name: "past sentinel", state: stateSentinel + 1},
		{name: "max uint8", state: State(255)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != "unknown" {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, "unknown")
			}
		})
	}
}

func TestStateTerminal(t *testing.T) {
	t.Parallel()

	for _, s := range allStates {
		want := s == StateClosed
		if got := s.Terminal(); got != want {
			t.Errorf("%v.Terminal() = %v, want %v", s, got, want)
		}
	}
	if State(0).Terminal() {
		t.Errorf("State(0).Terminal() = true, want false")
	}
	if stateSentinel.Terminal() {
		t.Errorf("stateSentinel.Terminal() = true, want false")
	}
}

func TestTransitionErrorMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *TransitionError
		want string
	}{
		{
			name: "declared states",
			err:  &TransitionError{From: StateReady, To: StateStarting},
			want: "illegal lifecycle transition ready -> starting",
		},
		{
			name: "zero to renders unknown",
			err:  &TransitionError{From: StateConfigured, To: State(0)},
			want: "illegal lifecycle transition configured -> unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMachineInitialState(t *testing.T) {
	t.Parallel()

	m := NewMachine()
	if got := m.State(); got != StateConfigured {
		t.Errorf("NewMachine().State() = %v, want %v", got, StateConfigured)
	}
}

func TestMachineTo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		steps   []State // applied in order; all but the last must be legal
		next    State
		wantErr bool
		wantEnd State
	}{
		{
			name: "legal first step",
			next: StateStarting, wantEnd: StateStarting,
		},
		{
			name:  "legal path to ready",
			steps: []State{StateStarting, StateAuthenticating, StateDiscovering},
			next:  StateReady, wantEnd: StateReady,
		},
		{
			name:  "startup skipping auth",
			steps: []State{StateStarting},
			next:  StateDiscovering, wantEnd: StateDiscovering,
		},
		{
			name: "illegal skip leaves state unchanged",
			next: StateReady, wantErr: true, wantEnd: StateConfigured,
		},
		{
			name: "self transition illegal",
			next: StateConfigured, wantErr: true, wantEnd: StateConfigured,
		},
		{
			name: "zero value illegal",
			next: State(0), wantErr: true, wantEnd: StateConfigured,
		},
		{
			name: "sentinel illegal",
			next: stateSentinel, wantErr: true, wantEnd: StateConfigured,
		},
		{
			name:  "closed is absorbing",
			steps: []State{StateClosing, StateClosed},
			next:  StateReconnecting, wantErr: true, wantEnd: StateClosed,
		},
		{
			name:  "failed retried via reconnecting",
			steps: []State{StateStarting, StateFailed},
			next:  StateReconnecting, wantEnd: StateReconnecting,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMachine()
			for _, s := range tt.steps {
				if err := m.To(s); err != nil {
					t.Fatalf("setup To(%v) = %v, want nil", s, err)
				}
			}
			from := m.State()

			err := m.To(tt.next)
			if (err != nil) != tt.wantErr {
				t.Fatalf("To(%v) error = %v, wantErr %v", tt.next, err, tt.wantErr)
			}
			if tt.wantErr {
				var te *TransitionError
				if !errors.As(err, &te) {
					t.Fatalf("To(%v) error type = %T, want *TransitionError", tt.next, err)
				}
				if te.From != from || te.To != tt.next {
					t.Errorf("TransitionError = {From: %v, To: %v}, want {From: %v, To: %v}", te.From, te.To, from, tt.next)
				}
			}
			if got := m.State(); got != tt.wantEnd {
				t.Errorf("State() = %v, want %v", got, tt.wantEnd)
			}
		})
	}
}

func TestMachineWatch(t *testing.T) {
	t.Parallel()

	type change struct{ from, to State }

	m := NewMachine()
	var first, second []change
	cancelFirst := m.Watch(func(from, to State) { first = append(first, change{from, to}) })
	m.Watch(func(from, to State) { second = append(second, change{from, to}) })

	if err := m.To(StateStarting); err != nil {
		t.Fatalf("To(starting) = %v", err)
	}
	// An illegal transition must not notify.
	if err := m.To(StateClosed); err == nil {
		t.Fatalf("To(closed) from starting = nil, want error")
	}
	cancelFirst()
	cancelFirst() // cancel is idempotent
	if err := m.To(StateReady); err != nil {
		t.Fatalf("To(ready) = %v", err)
	}

	wantFirst := []change{{StateConfigured, StateStarting}}
	wantSecond := []change{{StateConfigured, StateStarting}, {StateStarting, StateReady}}
	if !equalChanges(first, wantFirst) {
		t.Errorf("cancelled watcher saw %v, want %v", first, wantFirst)
	}
	if !equalChanges(second, wantSecond) {
		t.Errorf("live watcher saw %v, want %v", second, wantSecond)
	}
}

func TestMachineWatchOrder(t *testing.T) {
	t.Parallel()

	m := NewMachine()
	var order []int
	for i := range 5 {
		m.Watch(func(_, _ State) { order = append(order, i) })
	}
	if err := m.To(StateStarting); err != nil {
		t.Fatalf("To(starting) = %v", err)
	}
	for i, got := range order {
		if got != i {
			t.Fatalf("callbacks fired in order %v, want registration order", order)
		}
	}
	if len(order) != 5 {
		t.Errorf("fired %d callbacks, want 5", len(order))
	}
}

// TestMachineWatchReentrant proves the no-lock-held guarantee: a callback may
// call back into the machine without deadlocking.
func TestMachineWatchReentrant(t *testing.T) {
	t.Parallel()

	m := NewMachine()
	done := make(chan State, 1)
	m.Watch(func(_, _ State) {
		// Both reads take the machine's lock; holding it during the callback
		// would deadlock here rather than return.
		_ = m.State()
		done <- m.State()
	})

	if err := m.To(StateStarting); err != nil {
		t.Fatalf("To(starting) = %v", err)
	}
	select {
	case got := <-done:
		if got != StateStarting {
			t.Errorf("State() inside callback = %v, want %v (state committed before notify)", got, StateStarting)
		}
	default:
		t.Fatalf("callback did not complete")
	}
}

func TestMachineConcurrentTo(t *testing.T) {
	t.Parallel()

	const goroutines = 8
	for range 200 {
		m := NewMachine()
		m.Watch(func(_, _ State) {})
		if err := m.To(StateClosing); err != nil {
			t.Fatalf("setup To(closing) = %v", err)
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var wins int

		// Two goroutines race the same closing -> closed transition. Because
		// closed is absorbing, exactly one may win: the loser must observe the
		// committed state and be refused.
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := m.To(StateClosed); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = m.State()
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				cancel := m.Watch(func(_, _ State) {})
				cancel()
			}()
		}
		wg.Wait()

		if wins != 1 {
			t.Fatalf("competing transitions won %d times, want exactly 1", wins)
		}
		if got := m.State(); got != StateClosed {
			t.Fatalf("State() = %v, want %v", got, StateClosed)
		}
	}
}

func equalChanges[T comparable](got, want []T) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
