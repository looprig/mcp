package mcptest

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// fixturePkg is the command this helper builds.
const fixturePkg = "github.com/looprig/mcp/internal/mcptest/cmd/fixture"

// buildTimeout bounds the build. A cold build of the vendored SDK is a few
// seconds; anything near this is a hang, and a test that hangs reports nothing.
const buildTimeout = 3 * time.Minute

// TB is the slice of *testing.T this package needs. Declaring it here rather
// than importing "testing" keeps the testing package out of the fixture binary,
// which links this package.
type TB interface {
	Helper()
	TempDir() string
	Fatalf(format string, args ...any)
}

// BuildFixture builds the fixture command and returns the path to the binary.
// It fails the test, with the compiler's output, if the build fails.
//
// The binary goes in t.TempDir(), so it is removed when the test ends and no
// two tests can race over it. Each call is a fresh `go build`; after the first,
// Go's build cache makes that cheap, which is why there is no caching here to
// get wrong.
func BuildFixture(t TB) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	out := filepath.Join(t.TempDir(), "fixture")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}

	root, err := moduleRoot(ctx)
	if err != nil {
		t.Fatalf("mcptest: %v", err)
	}

	// Explicit argv, never a shell string. -trimpath per the module's build
	// rules; CGO off so the fixture is a static binary that cannot depend on
	// the host toolchain's C environment.
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, fixturePkg) // #nosec G204 -- fixed argv; out is under the test's own TempDir
	cmd.Dir = root
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")

	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mcptest: building %s: %v\n%s", fixturePkg, err, combined)
	}
	return out
}

// moduleRoot returns the directory holding this module's go.mod. It asks the go
// tool rather than walking up from a caller-relative path, which would depend
// on which package's test is running.
func moduleRoot(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "env", "GOMOD") // #nosec G204 -- fixed argv, no external input
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("locating module root: %w: %s", err, ee.Stderr)
		}
		return "", fmt.Errorf("locating module root: %w", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		return "", errors.New("locating module root: no go.mod found")
	}
	return filepath.Dir(gomod), nil
}
