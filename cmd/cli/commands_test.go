package cli

import (
	"context"
	"domain-search/models"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestResultCommandCompactJSON(t *testing.T) {
	cmd := newResultCommand("result", "test result", func(context.Context, *cobra.Command) (models.CommandResult, error) {
		return textResult(struct {
			Value string `json:"value"`
		}{"ok"}, "human output"), nil
	})
	var output strings.Builder
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--compact"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var result map[string]string
	if err := json.Unmarshal([]byte(output.String()), &result); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if result["value"] != "ok" || strings.Contains(output.String(), "\n  ") {
		t.Fatalf("unexpected compact JSON output %q", output.String())
	}
}

func TestResultCommandWritesSelectedOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.jsonl")
	cmd := newResultCommand("result", "test result", func(context.Context, *cobra.Command) (models.CommandResult, error) {
		return textResult(map[string]string{"value": "ok"}, "human output"), nil
	})
	var stdout strings.Builder
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"--json", "--output", path})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want output redirected to file", stdout.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("output file is not JSON: %v", err)
	}
	if result["value"] != "ok" {
		t.Fatalf("output file result = %#v", result)
	}
}

func TestResultCommandRejectsNonpositiveTimeout(t *testing.T) {
	called := false
	cmd := newResultCommand("result", "test result", func(context.Context, *cobra.Command) (models.CommandResult, error) {
		called = true
		return models.CommandResult{}, nil
	})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--timeout", "0s"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "timeout must be greater than zero") {
		t.Fatalf("Execute() error = %v, want timeout validation error", err)
	}
	if called {
		t.Fatal("command callback ran with a nonpositive timeout")
	}
}
