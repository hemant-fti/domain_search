package cli

import (
	"context"
	cmdoutput "domain-search/cmd/output"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestResultCommandCompactJSON(t *testing.T) {
	cmd := newResultCommand("result", "test result", func(context.Context, *cobra.Command) (commandResult, error) {
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
	cmd := newResultCommand("result", "test result", func(context.Context, *cobra.Command) (commandResult, error) {
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

func TestScanOutputCannotOverwriteHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan-results.jsonl")
	original := cmdoutput.ScanResultsFile
	cmdoutput.ScanResultsFile = path
	t.Cleanup(func() { cmdoutput.ScanResultsFile = original })

	if err := ValidateScanOutputPath(path); err == nil {
		t.Fatal("ValidateScanOutputPath() accepted the history file path")
	}
}

func TestResultCommandRejectsNonpositiveTimeout(t *testing.T) {
	called := false
	cmd := newResultCommand("result", "test result", func(context.Context, *cobra.Command) (commandResult, error) {
		called = true
		return commandResult{}, nil
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

func TestCertificateDurationSupportsDays(t *testing.T) {
	duration, err := parseCertificateDuration("30d")
	if err != nil {
		t.Fatalf("parseCertificateDuration() error = %v", err)
	}
	if duration.Hours() != 24*30 {
		t.Fatalf("parsed duration = %s, want 720h", duration)
	}
	if _, err := parseCertificateDuration("invalid"); err == nil {
		t.Fatal("parseCertificateDuration() accepted invalid input")
	}
}

func TestRequestsJSONOutputMatchesCommandFlags(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{args: []string{"system", "cpu", "--json"}, want: true},
		{args: []string{"scan", "--compact=true"}, want: true},
		{args: []string{"system", "cpu", "--json=false"}, want: false},
		{args: []string{"scan", "--compact=false"}, want: false},
		{args: []string{"system", "info", "--pretty=false"}, want: true},
	}
	for _, test := range tests {
		if got := cmdoutput.RequestsJSONOutput(test.args); got != test.want {
			t.Errorf("RequestsJSONOutput(%v) = %t, want %t", test.args, got, test.want)
		}
	}
}

func TestServiceStatusRequiresExactlyOneArgument(t *testing.T) {
	cmd := NewServiceStatusCommand()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want argument validation error")
	}
	if !strings.Contains(err.Error(), "accepts 1 arg") {
		t.Fatalf("Execute() error = %v, want Cobra argument error", err)
	}
}
