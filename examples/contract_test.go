package examples_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const offlineCommand = "GOWORK=off go test -race ./..."

type manifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Repository    string `json:"repository"`
	ProofSources  []struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Path   string `json:"path"`
		Symbol string `json:"symbol,omitempty"`
	} `json:"proofSources"`
	Examples []struct {
		ID             string            `json:"id"`
		Ecosystem      string            `json:"ecosystem"`
		Owner          string            `json:"owner"`
		SourcePath     string            `json:"sourcePath"`
		Availability   string            `json:"availability"`
		Versions       map[string]string `json:"versions"`
		OfflineCommand string            `json:"offlineCommand"`
		Assertion      string            `json:"assertion"`
		WorkflowPath   string            `json:"workflowPath"`
		JobID          string            `json:"jobId"`
		Cleanup        string            `json:"cleanup"`
		LiveGate       json.RawMessage   `json:"liveGate"`
		ProofIDs       []string          `json:"proofIds"`
	} `json:"examples"`
}

func TestDocsExamplesArtifacts(t *testing.T) {
	repositoryRoot := filepath.Clean("..")
	data, err := os.ReadFile(filepath.Join(repositoryRoot, "testdata/docs/examples.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var got manifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if got.SchemaVersion != 1 || got.Repository != "mcp" {
		t.Fatalf("manifest identity = (%d, %q)", got.SchemaVersion, got.Repository)
	}

	wantSources := map[string]string{
		"example-mcp-stdio-client-server-source":      "examples/stdio/main.go",
		"example-mcp-streamable-http-source":          "examples/streamable-http/main.go",
		"example-mcp-server-authoring-source":         "examples/server/main.go",
		"example-mcp-harness-adoption-source":         "examples/harness-adoption/main.go",
		"example-mcp-acp-passthrough-source":          "examples/acp-passthrough/main.go",
		"example-mcp-acp-passthrough-test":            "examples/acp-passthrough/main_test.go",
		"example-mcp-examples-contract-test":          "examples/contract_test.go",
		"example-mcp-stdio-transport-connect-source":  "pkg/transport/stdio/stdio.go",
		"example-mcp-http-transport-connect-source":   "pkg/transport/streamablehttp/streamablehttp.go",
		"example-mcp-server-register-tool-source":     "pkg/server/server.go",
		"example-mcp-harness-start-adoption-source":   "pkg/harness/adoption.go",
		"example-mcp-collab-protocol-boundary-source": "pkg/collab/protocol.go",
	}
	proofs := make(map[string]bool, len(got.ProofSources))
	for _, proof := range got.ProofSources {
		if wantSources[proof.ID] != proof.Path {
			t.Errorf("proof %q path = %q, want %q", proof.ID, proof.Path, wantSources[proof.ID])
		}
		if proof.Type != "source" && proof.Type != "test" {
			t.Errorf("proof %q type = %q", proof.ID, proof.Type)
		}
		if strings.Contains(proof.Path, "#") {
			t.Errorf("proof %q embeds a symbol in its path", proof.ID)
		}
		if _, err := os.Stat(filepath.Join(repositoryRoot, proof.Path)); err != nil {
			t.Errorf("proof %q: %v", proof.ID, err)
		}
		proofs[proof.ID] = true
	}
	if len(got.ProofSources) != len(wantSources) {
		t.Errorf("proof count = %d, want %d", len(got.ProofSources), len(wantSources))
	}
	if len(got.Examples) != 5 {
		t.Fatalf("example count = %d, want 5", len(got.Examples))
	}

	workflowData, err := os.ReadFile(filepath.Join(repositoryRoot, ".github/workflows/docs-examples.yml"))
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	workflow := string(workflowData)
	for _, literal := range []string{"docs-examples:", "GOWORK=off make test", offlineCommand} {
		if !strings.Contains(workflow, literal) {
			t.Errorf("workflow lacks %q", literal)
		}
	}

	seen := make(map[string]bool, len(got.Examples))
	for _, example := range got.Examples {
		if !strings.HasPrefix(example.ID, "example-mcp-") || seen[example.ID] {
			t.Errorf("invalid or duplicate example ID %q", example.ID)
		}
		seen[example.ID] = true
		if example.Ecosystem != "go" || example.Owner != "mcp" || example.Availability != "source-workspace" {
			t.Errorf("example %q classification is invalid", example.ID)
		}
		if len(example.Versions) != 1 || example.Versions["github.com/looprig/mcp"] != "source-workspace" {
			t.Errorf("example %q versions = %#v", example.ID, example.Versions)
		}
		if _, err := os.Stat(filepath.Join(repositoryRoot, example.SourcePath)); err != nil {
			t.Errorf("example %q source: %v", example.ID, err)
		}
		if example.OfflineCommand == "" || !strings.Contains(workflow, example.OfflineCommand) {
			t.Errorf("workflow lacks example %q command %q", example.ID, example.OfflineCommand)
		}
		if example.Assertion == "" || example.Cleanup == "" || example.WorkflowPath != ".github/workflows/docs-examples.yml" || example.JobID != "docs-examples" || string(example.LiveGate) != "null" {
			t.Errorf("example %q metadata is incomplete", example.ID)
		}
		if len(example.ProofIDs) < 2 {
			t.Errorf("example %q has too few proofs", example.ID)
		}
		for _, proofID := range example.ProofIDs {
			if !proofs[proofID] {
				t.Errorf("example %q references unknown proof %q", example.ID, proofID)
			}
		}
	}
}
