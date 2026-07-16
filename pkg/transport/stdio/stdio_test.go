// Unit tests for the stdio transport: everything that can be settled without a
// subprocess. The security-critical piece here is the environment builder —
// what a child does NOT inherit is the whole point of the allowlist, and it is
// checked at the ProcessSpec boundary (with a fake launcher) as well as on the
// builder itself, so an argv/env regression fails here rather than in an
// integration test that has to guess at what the child saw.
//
// The subprocess tests live in stdio_integration_test.go.

package stdio

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/mcp/internal/protocol"
	"github.com/looprig/mcp/pkg/client"
)

// secret is the value every redaction test hunts for. It is not a credential:
// it is a distinctive string that must never appear anywhere a credential
// would not be welcome.
const secret = "s3cr3t-do-not-leak-me"

// testExecutable writes an executable file into a temp dir and returns its
// absolute path. It is never run by the unit tests — New only has to resolve
// it — so its contents do not matter.
func testExecutable(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server")
	if err := os.WriteFile(path, []byte("#!/bin/false\n"), 0o700); err != nil { // #nosec G306 -- an executable fixture must be executable
		t.Fatalf("writing test executable: %v", err)
	}
	return path
}

// wantInvalidConfig asserts err is the module's typed configuration failure.
func wantInvalidConfig(t *testing.T, err error) *client.Error {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	var typed *client.Error
	if !errors.As(err, &typed) {
		t.Fatalf("want *client.Error, got %T: %v", err, err)
	}
	if typed.Class != client.FailureInvalidConfig {
		t.Errorf("class = %v, want %v", typed.Class, client.FailureInvalidConfig)
	}
	return typed
}

func TestNewValidation(t *testing.T) {
	t.Parallel()
	exe := testExecutable(t)

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "absolute command", cfg: Config{Command: exe}},
		{name: "command with args", cfg: Config{Command: exe, Args: []string{"-flag", "value"}}},
		{name: "absolute dir", cfg: Config{Command: exe, Dir: filepath.Dir(exe)}},
		{name: "explicit stderr limit", cfg: Config{Command: exe, StderrLimit: 1}},
		{name: "full env allowlist", cfg: Config{Command: exe, Env: EnvAllowlist{
			Vars:        []Var{{Name: "TOKEN", Value: secret}},
			PassThrough: []string{"PATH", "HOME"},
		}}},

		{name: "empty command", cfg: Config{}, wantErr: true},
		{name: "command with NUL", cfg: Config{Command: "serv\x00er"}, wantErr: true},
		{name: "relative path command", cfg: Config{Command: "./server"}, wantErr: true},
		{name: "relative nested path command", cfg: Config{Command: "bin/server"}, wantErr: true},
		{name: "nonexistent absolute command", cfg: Config{Command: filepath.Join(t.TempDir(), "nope")}, wantErr: true},
		{name: "unresolvable bare command", cfg: Config{Command: "looprig-no-such-command-anywhere"}, wantErr: true},
		{name: "directory as command", cfg: Config{Command: filepath.Dir(exe)}, wantErr: true},
		{name: "arg with NUL", cfg: Config{Command: exe, Args: []string{"ok", "b\x00d"}}, wantErr: true},
		{name: "relative dir", cfg: Config{Command: exe, Dir: "work"}, wantErr: true},
		{name: "negative stderr limit", cfg: Config{Command: exe, StderrLimit: -1}, wantErr: true},
		{name: "empty env name", cfg: Config{Command: exe, Env: EnvAllowlist{
			Vars: []Var{{Name: "", Value: "x"}},
		}}, wantErr: true},
		{name: "env name with equals", cfg: Config{Command: exe, Env: EnvAllowlist{
			Vars: []Var{{Name: "A=B", Value: "x"}},
		}}, wantErr: true},
		{name: "env name with NUL", cfg: Config{Command: exe, Env: EnvAllowlist{
			Vars: []Var{{Name: "A\x00B", Value: "x"}},
		}}, wantErr: true},
		{name: "env value with NUL", cfg: Config{Command: exe, Env: EnvAllowlist{
			Vars: []Var{{Name: "A", Value: "x\x00y"}},
		}}, wantErr: true},
		{name: "duplicate env var", cfg: Config{Command: exe, Env: EnvAllowlist{
			Vars: []Var{{Name: "A", Value: "1"}, {Name: "A", Value: "2"}},
		}}, wantErr: true},
		{name: "duplicate passthrough", cfg: Config{Command: exe, Env: EnvAllowlist{
			PassThrough: []string{"PATH", "PATH"},
		}}, wantErr: true},
		{name: "empty passthrough name", cfg: Config{Command: exe, Env: EnvAllowlist{
			PassThrough: []string{""},
		}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := New(tt.cfg)
			if tt.wantErr {
				wantInvalidConfig(t, err)
				if got != nil {
					t.Error("New returned a factory alongside an error; it must fail closed")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() error = %v, want nil", err)
			}
			if got == nil {
				t.Fatal("New returned a nil factory with no error")
			}
		})
	}
}

// TestNewResolvesBareCommandOnPath checks the PATH branch of resolveCommand
// with a command that is definitely present: the test binary is being run by
// the go tool, so the go tool is on PATH.
func TestNewResolvesBareCommandOnPath(t *testing.T) {
	t.Parallel()
	f, err := New(Config{Command: "go"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got := f.(*factory).path
	if !filepath.IsAbs(got) {
		t.Errorf("resolved path = %q, want an absolute path", got)
	}
}

func TestNewDefaults(t *testing.T) {
	t.Parallel()
	f, err := New(Config{Command: testExecutable(t)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got := f.(*factory)
	if got.stderrLimit != DefaultStderrLimit {
		t.Errorf("stderrLimit = %d, want the default %d", got.stderrLimit, DefaultStderrLimit)
	}
	if _, ok := got.launcher.(osLauncher); !ok {
		t.Errorf("launcher = %T, want the default osLauncher", got.launcher)
	}
	if got.times != defaultTimings() {
		t.Errorf("times = %+v, want %+v", got.times, defaultTimings())
	}
}

// TestNewDetachesConfigSlices proves a Definition stays immutable after
// validation: a caller mutating the slices it passed must not be able to change
// the argv the factory will exec.
func TestNewDetachesConfigSlices(t *testing.T) {
	t.Parallel()
	args := []string{"--safe"}
	pass := []string{"PATH"}
	vars := []Var{{Name: "A", Value: "1"}}
	f, err := New(Config{
		Command: testExecutable(t),
		Args:    args,
		Env:     EnvAllowlist{Vars: vars, PassThrough: pass},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	args[0] = "--pwned"
	pass[0] = "PWNED"
	vars[0] = Var{Name: "PWNED", Value: "x"}

	got := f.(*factory)
	if got.args[0] != "--safe" {
		t.Errorf("args[0] = %q, want %q: New did not copy Args", got.args[0], "--safe")
	}
	if got.env.PassThrough[0] != "PATH" {
		t.Errorf("PassThrough[0] = %q, want %q: New did not copy the allowlist", got.env.PassThrough[0], "PATH")
	}
	if got.env.Vars[0].Name != "A" {
		t.Errorf("Vars[0].Name = %q, want %q: New did not copy the allowlist", got.env.Vars[0].Name, "A")
	}
}

// TestNewErrorsWithholdSecrets checks that a configuration error names the
// field that is wrong without echoing a value that might be a credential.
func TestNewErrorsWithholdSecrets(t *testing.T) {
	t.Parallel()
	exe := testExecutable(t)

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "secret argument alongside a bad one",
			cfg:  Config{Command: exe, Args: []string{"--token", secret, "b\x00d"}},
		},
		{
			name: "secret env value that is malformed",
			cfg:  Config{Command: exe, Env: EnvAllowlist{Vars: []Var{{Name: "TOKEN", Value: secret + "\x00"}}}},
		},
		{
			name: "secret env value in a duplicate entry",
			cfg: Config{Command: exe, Env: EnvAllowlist{Vars: []Var{
				{Name: "TOKEN", Value: secret},
				{Name: "TOKEN", Value: secret},
			}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tt.cfg)
			typed := wantInvalidConfig(t, err)
			if strings.Contains(typed.Error(), secret) {
				t.Errorf("error text leaks a secret: %q", typed.Error())
			}
		})
	}
}

func TestKindAndRedactedOrigin(t *testing.T) {
	t.Parallel()
	exe := testExecutable(t)
	f, err := New(Config{
		Command: exe,
		Args:    []string{"--token", secret, "--url", "https://user:" + secret + "@example.test"},
		Env:     EnvAllowlist{Vars: []Var{{Name: "TOKEN", Value: secret}}},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if got := f.Kind(); got != "stdio" {
		t.Errorf("Kind() = %q, want %q", got, "stdio")
	}
	origin := f.RedactedOrigin()
	if strings.Contains(origin, secret) {
		t.Fatalf("RedactedOrigin() leaks a secret: %q", origin)
	}
	if want := "server (4 args)"; origin != want {
		t.Errorf("RedactedOrigin() = %q, want %q", origin, want)
	}
	if strings.Contains(origin, filepath.Dir(exe)) {
		t.Errorf("RedactedOrigin() = %q, want no directory component", origin)
	}
}

func TestBuildEnv(t *testing.T) {
	t.Parallel()

	parent := map[string]string{
		"PATH":         "/usr/bin",
		"HOME":         "/home/test",
		"PARENT_TOKEN": secret,
		"EMPTY":        "",
	}
	lookup := func(name string) (string, bool) {
		v, ok := parent[name]
		return v, ok
	}

	tests := []struct {
		name string
		env  EnvAllowlist
		want []string
	}{
		{
			name: "empty allowlist gives an empty environment",
			env:  EnvAllowlist{},
			want: []string{},
		},
		{
			name: "passthrough copies a set variable",
			env:  EnvAllowlist{PassThrough: []string{"PATH"}},
			want: []string{"PATH=/usr/bin"},
		},
		{
			name: "passthrough copies a set-but-empty variable",
			env:  EnvAllowlist{PassThrough: []string{"EMPTY"}},
			want: []string{"EMPTY="},
		},
		{
			name: "passthrough of an unset variable is absent, not an error",
			env:  EnvAllowlist{PassThrough: []string{"NOT_SET_ANYWHERE"}},
			want: []string{},
		},
		{
			name: "unlisted parent variables are absent",
			env:  EnvAllowlist{PassThrough: []string{"PATH"}},
			want: []string{"PATH=/usr/bin"},
		},
		{
			name: "explicit vars are set verbatim",
			env:  EnvAllowlist{Vars: []Var{{Name: "TOKEN", Value: secret}}},
			want: []string{"TOKEN=" + secret},
		},
		{
			name: "explicit var wins over a passthrough of the same name",
			env: EnvAllowlist{
				Vars:        []Var{{Name: "PATH", Value: "/opt/bin"}},
				PassThrough: []string{"PATH"},
			},
			want: []string{"PATH=/opt/bin"},
		},
		{
			name: "explicit var wins even when the parent does not set the name",
			env: EnvAllowlist{
				Vars:        []Var{{Name: "NOT_SET_ANYWHERE", Value: "x"}},
				PassThrough: []string{"NOT_SET_ANYWHERE"},
			},
			want: []string{"NOT_SET_ANYWHERE=x"},
		},
		{
			name: "order is passthrough then explicit",
			env: EnvAllowlist{
				Vars:        []Var{{Name: "A", Value: "1"}, {Name: "B", Value: "2"}},
				PassThrough: []string{"HOME", "PATH"},
			},
			want: []string{"HOME=/home/test", "PATH=/usr/bin", "A=1", "B=2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.env.build(lookup)
			if got == nil {
				t.Fatal("build returned nil: os/exec reads a nil Env as \"inherit the parent's\"")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("build() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("build() = %v, want %v", got, tt.want)
				}
			}
			assertNoDuplicateNames(t, got)
			// The parent's secret is only ever present when it was asked for.
			asked := false
			for _, n := range tt.env.PassThrough {
				asked = asked || n == "PARENT_TOKEN"
			}
			for _, v := range tt.env.Vars {
				asked = asked || v.Value == secret
			}
			if !asked {
				for _, entry := range got {
					if strings.Contains(entry, secret) {
						t.Errorf("build() leaked an unlisted parent secret: %q", entry)
					}
				}
			}
		})
	}
}

func assertNoDuplicateNames(t *testing.T, env []string) {
	t.Helper()
	seen := make(map[string]struct{}, len(env))
	for _, entry := range env {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			t.Errorf("environment entry %q has no '='", entry)
			continue
		}
		if _, dup := seen[name]; dup {
			t.Errorf("environment has a duplicate name %q: %v", name, env)
		}
		seen[name] = struct{}{}
	}
}

// TestBuildEnvAgainstRealEnvironment is the same guarantee against the process's
// actual environment: a secret this test process holds must not reach a child
// unless it was named.
func TestBuildEnvAgainstRealEnvironment(t *testing.T) {
	// No t.Parallel: t.Setenv forbids it.
	t.Setenv("LOOPRIG_STDIO_TEST_SECRET", secret)

	got := EnvAllowlist{PassThrough: []string{"PATH"}}.build(os.LookupEnv)
	for _, entry := range got {
		if strings.Contains(entry, secret) {
			t.Fatalf("an unlisted secret from this process reached the child environment: %q", entry)
		}
		if strings.HasPrefix(entry, "LOOPRIG_STDIO_TEST_SECRET=") {
			t.Fatalf("an unlisted variable reached the child environment: %q", entry)
		}
	}

	allowed := EnvAllowlist{PassThrough: []string{"LOOPRIG_STDIO_TEST_SECRET"}}.build(os.LookupEnv)
	if len(allowed) != 1 || allowed[0] != "LOOPRIG_STDIO_TEST_SECRET="+secret {
		t.Fatalf("allowlisted passthrough = %v, want the variable to be copied", allowed)
	}
}

// fakeProcess is a Process that never runs anything. It exits when the test
// says so — either straight away, or in response to a signal — so the shutdown
// escalation can be driven exactly.
type fakeProcess struct {
	// exitOn selects which step lets the process die.
	exitOnTerminate bool
	exitOnKill      bool
	status          ExitStatus

	done chan struct{}
	once sync.Once

	mu           sync.Mutex
	terminateErr error
	killErr      error
	terminated   int
	killed       int
}

func newFakeProcess() *fakeProcess {
	return &fakeProcess{done: make(chan struct{})}
}

func (p *fakeProcess) exit() { p.once.Do(func() { close(p.done) }) }

func (p *fakeProcess) Pid() int { return 4242 }

func (p *fakeProcess) Terminate() error {
	p.mu.Lock()
	p.terminated++
	err := p.terminateErr
	p.mu.Unlock()
	if err != nil {
		return err
	}
	if p.exitOnTerminate {
		p.exit()
	}
	return nil
}

func (p *fakeProcess) Kill() error {
	p.mu.Lock()
	p.killed++
	err := p.killErr
	p.mu.Unlock()
	if err != nil {
		return err
	}
	if p.exitOnKill {
		p.exit()
	}
	return nil
}

func (p *fakeProcess) Wait() (ExitStatus, error) {
	<-p.done
	return p.status, nil
}

func (p *fakeProcess) counts() (terminated, killed int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.terminated, p.killed
}

// fakeLauncher records the spec it was handed and hands back a fakeProcess. It
// is what lets the argv/env/dir contract be asserted without running anything.
type fakeLauncher struct {
	proc *fakeProcess
	err  error

	mu   sync.Mutex
	spec ProcessSpec
	n    int
}

func (l *fakeLauncher) Start(_ context.Context, spec ProcessSpec) (Process, error) {
	l.mu.Lock()
	l.spec = spec
	l.n++
	l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	return l.proc, nil
}

func (l *fakeLauncher) started() (ProcessSpec, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.spec, l.n
}

// fastTimings shrinks every grace period so a unit test can drive the whole
// shutdown escalation in milliseconds.
func fastTimings() timings {
	return timings{
		exit:        20 * time.Millisecond,
		terminate:   20 * time.Millisecond,
		reap:        20 * time.Millisecond,
		stderrDrain: 20 * time.Millisecond,
		exitObserve: 20 * time.Millisecond,
	}
}

// newFakeFactory builds a factory whose launcher is fake and whose waits are
// short.
func newFakeFactory(t *testing.T, cfg Config, l ProcessLauncher) *factory {
	t.Helper()
	if cfg.Command == "" {
		cfg.Command = testExecutable(t)
	}
	cfg.Launcher = l
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fac := f.(*factory)
	fac.times = fastTimings()
	return fac
}

// TestConnectPassesArgvAndAllowlistedEnvOnly is the argv/env contract at the
// boundary where it matters: what the launcher — and therefore execve — is
// actually handed.
func TestConnectPassesArgvAndAllowlistedEnvOnly(t *testing.T) {
	// No t.Parallel: t.Setenv forbids it.
	t.Setenv("LOOPRIG_STDIO_PARENT_SECRET", secret)
	t.Setenv("LOOPRIG_STDIO_ALLOWED", "allowed-value")

	proc := newFakeProcess()
	proc.exitOnTerminate = true
	l := &fakeLauncher{proc: proc}
	dir := t.TempDir()
	f := newFakeFactory(t, Config{
		Args: []string{"--config", "/etc/server.json", "; rm -rf /", "$(whoami)"},
		Dir:  dir,
		Env: EnvAllowlist{
			Vars:        []Var{{Name: "TOKEN", Value: secret}},
			PassThrough: []string{"LOOPRIG_STDIO_ALLOWED", "LOOPRIG_STDIO_NOT_SET"},
		},
	}, l)

	c, err := f.Connect(context.Background(), protocol.ConnectConfig{})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = c.Close(ctx)
	})

	spec, n := l.started()
	if n != 1 {
		t.Fatalf("launcher started %d processes, want 1", n)
	}
	if !filepath.IsAbs(spec.Path) {
		t.Errorf("spec.Path = %q, want an absolute executable", spec.Path)
	}
	// The metacharacters are arguments, not syntax: they arrive intact and
	// uninterpreted because there is no shell to interpret them.
	wantArgs := []string{"--config", "/etc/server.json", "; rm -rf /", "$(whoami)"}
	if len(spec.Args) != len(wantArgs) {
		t.Fatalf("spec.Args = %q, want %q", spec.Args, wantArgs)
	}
	for i := range wantArgs {
		if spec.Args[i] != wantArgs[i] {
			t.Fatalf("spec.Args = %q, want %q", spec.Args, wantArgs)
		}
	}
	if spec.Dir != dir {
		t.Errorf("spec.Dir = %q, want %q", spec.Dir, dir)
	}
	if spec.Stdin == nil || spec.Stdout == nil || spec.Stderr == nil {
		t.Error("spec must carry all three streams")
	}

	wantEnv := []string{"LOOPRIG_STDIO_ALLOWED=allowed-value", "TOKEN=" + secret}
	if len(spec.Env) != len(wantEnv) {
		t.Fatalf("spec.Env = %v, want exactly %v", spec.Env, wantEnv)
	}
	for i := range wantEnv {
		if spec.Env[i] != wantEnv[i] {
			t.Fatalf("spec.Env = %v, want %v", spec.Env, wantEnv)
		}
	}
	for _, entry := range spec.Env {
		if strings.HasPrefix(entry, "LOOPRIG_STDIO_PARENT_SECRET=") {
			t.Fatalf("an unlisted parent secret reached the child: %q", entry)
		}
	}
}

// TestConnectRejectsDoneContext checks that a caller who has already given up
// never gets a process started on their behalf.
func TestConnectRejectsDoneContext(t *testing.T) {
	t.Parallel()
	l := &fakeLauncher{proc: newFakeProcess()}
	f := newFakeFactory(t, Config{}, l)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c, err := f.Connect(ctx, protocol.ConnectConfig{})
	if c != nil {
		t.Error("Connect returned a conn for a cancelled context")
	}
	var typed *client.Error
	if !errors.As(err, &typed) {
		t.Fatalf("want *client.Error, got %T: %v", err, err)
	}
	if typed.Class != client.FailureCancelled {
		t.Errorf("class = %v, want %v", typed.Class, client.FailureCancelled)
	}
	if _, n := l.started(); n != 0 {
		t.Errorf("launcher started %d processes for a cancelled context, want 0", n)
	}
}

// TestConnectStartFailure checks a launcher that cannot start the server is a
// transport failure, not a panic or a half-built conn.
func TestConnectStartFailure(t *testing.T) {
	t.Parallel()
	l := &fakeLauncher{err: errors.New("no such confinement")}
	f := newFakeFactory(t, Config{}, l)

	c, err := f.Connect(context.Background(), protocol.ConnectConfig{})
	if c != nil {
		t.Error("Connect returned a conn alongside an error")
	}
	var typed *client.Error
	if !errors.As(err, &typed) {
		t.Fatalf("want *client.Error, got %T: %v", err, err)
	}
	if typed.Class != client.FailureTransportClosed {
		t.Errorf("class = %v, want %v", typed.Class, client.FailureTransportClosed)
	}
}

// TestConnectRejectsABrokenLauncher checks the defence against foreign code: a
// launcher that reports success with no process must produce an error, not a
// nil dereference on the reaper's goroutine — which would take the host's whole
// process down rather than this one connection.
func TestConnectRejectsABrokenLauncher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		launcher ProcessLauncher
	}{
		{name: "nil process and nil error", launcher: &nilLauncher{}},
		{name: "typed nil process", launcher: &typedNilLauncher{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeFactory(t, Config{}, tt.launcher)

			c, err := f.Connect(context.Background(), protocol.ConnectConfig{})
			if c != nil {
				t.Error("Connect returned a conn for a launcher that started nothing")
			}
			var typed *client.Error
			if !errors.As(err, &typed) {
				t.Fatalf("want *client.Error, got %T: %v", err, err)
			}
			if typed.Class != client.FailureTransportClosed {
				t.Errorf("class = %v, want %v", typed.Class, client.FailureTransportClosed)
			}
		})
	}
}

// nilLauncher reports success with no process at all.
type nilLauncher struct{}

func (*nilLauncher) Start(context.Context, ProcessSpec) (Process, error) { return nil, nil }

// typedNilLauncher reports success with a typed nil pointer, which is a non-nil
// interface holding nil — the shape a plain nil check misses.
type typedNilLauncher struct{}

func (*typedNilLauncher) Start(context.Context, ProcessSpec) (Process, error) {
	var p *fakeProcess
	return p, nil
}

// TestCloseEscalation drives the shutdown ladder: a child that will not go on
// its own is terminated, and one that ignores that is killed.
func TestCloseEscalation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		exitOn        func(*fakeProcess)
		wantTerminate int
		wantKill      int
		wantErr       bool
	}{
		{
			name:   "child exits on its own once stdin closes",
			exitOn: func(p *fakeProcess) { p.exit() },
		},
		{
			name:          "child needs SIGTERM",
			exitOn:        func(p *fakeProcess) { p.exitOnTerminate = true },
			wantTerminate: 1,
		},
		{
			name:          "child needs SIGKILL",
			exitOn:        func(p *fakeProcess) { p.exitOnKill = true },
			wantTerminate: 1,
			wantKill:      1,
		},
		{
			name:          "child survives everything",
			exitOn:        func(*fakeProcess) {},
			wantTerminate: 1,
			wantKill:      1,
			wantErr:       true,
		},
		{
			name: "terminate fails and is escalated straight to kill",
			exitOn: func(p *fakeProcess) {
				p.terminateErr = errors.New("operation not permitted")
				p.exitOnKill = true
			},
			wantTerminate: 1,
			wantKill:      1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proc := newFakeProcess()
			tt.exitOn(proc)
			f := newFakeFactory(t, Config{}, &fakeLauncher{proc: proc})

			c, err := f.Connect(context.Background(), protocol.ConnectConfig{})
			if err != nil {
				t.Fatalf("Connect() error = %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err = c.Close(ctx)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Close() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				var typed *client.Error
				if !errors.As(err, &typed) {
					t.Fatalf("want *client.Error, got %T: %v", err, err)
				}
				if typed.Class != client.FailureTransportClosed {
					t.Errorf("class = %v, want %v", typed.Class, client.FailureTransportClosed)
				}
				proc.exit() // release the reaper goroutine
			}
			terminated, killed := proc.counts()
			if terminated != tt.wantTerminate || killed != tt.wantKill {
				t.Errorf("terminate/kill = %d/%d, want %d/%d", terminated, killed, tt.wantTerminate, tt.wantKill)
			}

			// Close is idempotent: the second call neither re-signals nor
			// reports something different.
			if second := c.Close(ctx); (second != nil) != tt.wantErr {
				t.Errorf("second Close() error = %v, want the first verdict", second)
			}
			if t2, k2 := proc.counts(); t2 != terminated || k2 != killed {
				t.Errorf("second Close signalled again: %d/%d, want %d/%d", t2, k2, terminated, killed)
			}
		})
	}
}

// TestClassify covers the judgement this transport exists to make: telling a
// server that spoke badly from a server that is not there any more.
func TestClassify(t *testing.T) {
	t.Parallel()

	sessionErr := errors.New("mcp handshake: connection closed")

	tests := []struct {
		name  string
		ctx   func() (context.Context, context.CancelFunc)
		setup func(*conn)
		want  client.FailureClass
		// wantMsg, when set, must appear in the rendered error.
		wantMsg string
	}{
		{
			name: "cancelled caller",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			want: client.FailureCancelled,
		},
		{
			name: "expired deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				return ctx, cancel
			},
			want: client.FailureStartupTimeout,
		},
		{
			name: "live child that spoke badly",
			ctx:  backgroundCtx,
			want: client.FailureServerProtocol,
		},
		{
			name: "child exited",
			ctx:  backgroundCtx,
			setup: func(c *conn) {
				c.status = ExitStatus{Code: 7}
				close(c.exited)
			},
			want:    client.FailureTransportClosed,
			wantMsg: "exit status 7",
		},
		{
			name: "child killed by a signal",
			ctx:  backgroundCtx,
			setup: func(c *conn) {
				c.status = ExitStatus{Code: -1, Signal: "killed"}
				close(c.exited)
			},
			want:    client.FailureTransportClosed,
			wantMsg: "signal: killed",
		},
		{
			name: "child exited saying something on stderr",
			ctx:  backgroundCtx,
			setup: func(c *conn) {
				c.status = ExitStatus{Code: 2}
				if _, err := c.stderr.Write([]byte("fixture: flag provided but not defined\n")); err != nil {
					t.Fatalf("seeding stderr: %v", err)
				}
				close(c.stderrDrain)
				close(c.exited)
			},
			want:    client.FailureTransportClosed,
			wantMsg: "flag provided but not defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &conn{
				stderr:      newRing(64),
				times:       fastTimings(),
				exited:      make(chan struct{}),
				stderrDrain: make(chan struct{}),
			}
			if tt.setup != nil {
				tt.setup(c)
			}
			ctx, cancel := tt.ctx()
			defer cancel()

			err := c.classify(ctx, opInitialize, sessionErr)
			var typed *client.Error
			if !errors.As(err, &typed) {
				t.Fatalf("want *client.Error, got %T: %v", err, err)
			}
			if typed.Class != tt.want {
				t.Fatalf("class = %v, want %v (%v)", typed.Class, tt.want, err)
			}
			if !errors.Is(err, sessionErr) {
				t.Error("the underlying cause must stay in the chain")
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

func backgroundCtx() (context.Context, context.CancelFunc) {
	return context.Background(), func() {}
}

// TestStderrTailIsBounded checks that a hostile server cannot make an error
// message unbounded, and that the tail is what survives.
func TestStderrTailIsBounded(t *testing.T) {
	t.Parallel()
	const ringBytes = 128
	c := &conn{
		stderr:      newRing(ringBytes),
		times:       fastTimings(),
		exited:      make(chan struct{}),
		stderrDrain: make(chan struct{}),
	}
	if _, err := c.stderr.Write([]byte(strings.Repeat("A", 4096) + "the last thing it said")); err != nil {
		t.Fatalf("seeding stderr: %v", err)
	}
	close(c.stderrDrain)

	tail := c.stderrTail()
	if !strings.Contains(tail, "the last thing it said") {
		t.Errorf("tail = %q, want the end of stderr", tail)
	}

	// The message is a known prefix followed by the ring's contents, so the
	// bound is computed rather than allowed for: the prefix is built from the
	// drop count the ring actually reports, and the text after it is what has
	// to fit in the ring. An eyeballed fudge factor for the prefix would let
	// the assertion go slack by a digit every time the count grew one.
	wantPrefix := fmt.Sprintf(": stderr tail (%d earlier bytes dropped): ", c.stderr.Dropped())
	body, ok := strings.CutPrefix(tail, wantPrefix)
	if !ok {
		t.Fatalf("tail = %q, want it to start with %q: the message must admit that earlier bytes were dropped", tail, wantPrefix)
	}
	if len(body) > ringBytes {
		t.Errorf("the tail carries %d bytes of the server's chatter, want at most the ring's %d", len(body), ringBytes)
	}
}

func TestExitStatusString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   ExitStatus
		want string
	}{
		{name: "clean exit", in: ExitStatus{Code: 0}, want: "exit status 0"},
		{name: "failure exit", in: ExitStatus{Code: 7}, want: "exit status 7"},
		{name: "signalled", in: ExitStatus{Code: -1, Signal: "killed"}, want: "signal: killed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
