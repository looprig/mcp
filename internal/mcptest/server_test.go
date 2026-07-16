// Unit tests for the fixture's pure parts: the config it validates and the
// noise it writes. Nothing here spawns anything, which is why nothing here is
// tagged.
//
// The fixture's real behavior — that it is a working MCP server — is only
// observable across a process boundary, so those tests live in
// server_integration_test.go behind the `integration` tag.
package mcptest_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/looprig/mcp/internal/mcptest"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     mcptest.Config
		wantErr bool
	}{
		{name: "zero value is valid", cfg: mcptest.Config{}},
		{
			name: "everything on",
			cfg: mcptest.Config{
				Instructions:       "hi",
				Prompts:            true,
				Resources:          true,
				Mutate:             true,
				Crash:              true,
				CrashExitCode:      mcptest.DefaultCrashExitCode,
				NoiseBytes:         1024,
				ElicitOnInitialize: true,
			},
		},
		{name: "crash exit code is ignored when crash is off", cfg: mcptest.Config{CrashExitCode: 0}},
		{name: "crash exit code zero", cfg: mcptest.Config{Crash: true, CrashExitCode: 0}, wantErr: true},
		{name: "crash exit code negative", cfg: mcptest.Config{Crash: true, CrashExitCode: -1}, wantErr: true},
		{name: "crash exit code at the low bound", cfg: mcptest.Config{Crash: true, CrashExitCode: 1}},
		{name: "crash exit code at the high bound", cfg: mcptest.Config{Crash: true, CrashExitCode: 125}},
		{name: "crash exit code above the bound", cfg: mcptest.Config{Crash: true, CrashExitCode: 126}, wantErr: true},
		{name: "noise bytes negative", cfg: mcptest.Config{NoiseBytes: -1}, wantErr: true},
		{name: "noise bytes at the bound", cfg: mcptest.Config{NoiseBytes: mcptest.MaxNoiseBytes}},
		{name: "noise bytes above the bound", cfg: mcptest.Config{NoiseBytes: mcptest.MaxNoiseBytes + 1}, wantErr: true},
		{
			name:    "instructions above the bound",
			cfg:     mcptest.Config{Instructions: strings.Repeat("a", mcptest.MaxInstructionsBytes+1)},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.cfg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			// NewServer must agree with Validate: a config that validates must
			// build, and one that does not must not.
			_, err := mcptest.NewServer(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWriteNoise(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		n       int
		wantErr bool
	}{
		{name: "zero writes nothing", n: 0},
		{name: "one byte", n: 1},
		{name: "less than one line", n: 10},
		{name: "exactly one line", n: 80},
		{name: "many lines", n: 10_000},
		{name: "at the bound", n: mcptest.MaxNoiseBytes},
		{name: "negative", n: -1, wantErr: true},
		{name: "above the bound", n: mcptest.MaxNoiseBytes + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := mcptest.WriteNoise(&buf, tt.n)
			if (err != nil) != tt.wantErr {
				t.Fatalf("WriteNoise(%d) error = %v, wantErr %v", tt.n, err, tt.wantErr)
			}
			if tt.wantErr {
				if buf.Len() != 0 {
					t.Errorf("WriteNoise wrote %d bytes on error, want 0", buf.Len())
				}
				return
			}
			if buf.Len() != tt.n {
				t.Errorf("WriteNoise wrote %d bytes, want exactly %d", buf.Len(), tt.n)
			}
		})
	}
}

// TestWriteNoiseReportsWriteErrors: the noise is a diagnostic, but a diagnostic
// that silently fails to be written is worse than none.
func TestWriteNoiseReportsWriteErrors(t *testing.T) {
	t.Parallel()
	if err := mcptest.WriteNoise(errWriter{}, 100); err == nil {
		t.Error("WriteNoise returned nil for a failing writer, want an error")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("no") }
