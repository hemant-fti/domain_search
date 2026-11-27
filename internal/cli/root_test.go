package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootRegistersCommandHierarchy(t *testing.T) {
	paths := []string{
		"scan",
		"system", "system cpu", "system memory", "system disk", "system uptime",
		"domains list", "domains get-data-by-name",
		"tui", "version",
	}
	root := NewRootCommand()
	for _, path := range paths {
		t.Run(strings.ReplaceAll(path, " ", "_"), func(t *testing.T) {
			parts := strings.Fields(path)
			command, rest, err := root.Find(parts)
			if err != nil {
				t.Fatalf("Find(%q) error = %v", path, err)
			}
			if len(rest) != 0 || command.Name() != parts[len(parts)-1] {
				t.Fatalf("Find(%q) = %q with leftover %v; command not registered", path, command.CommandPath(), rest)
			}
		})
	}
}

func TestRemovedOutputFlagsAreRejected(t *testing.T) {
	for _, flag := range []string{"--json", "--pretty", "--compact", "--output=x.json"} {
		t.Run(flag, func(t *testing.T) {
			root := NewRootCommand()
			root.SetArgs([]string{"system", "cpu", flag})
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			err := root.Execute()
			if err == nil || !strings.Contains(err.Error(), "unknown flag") {
				t.Fatalf("Execute() error = %v, want unknown flag", err)
			}
		})
	}
}

func TestTimeoutMustBePositive(t *testing.T) {
	root := NewRootCommand()
	root.SetArgs([]string{"system", "cpu", "--timeout=0s"})
	root.SetOut(&bytes.Buffer{})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "timeout must be greater than zero") {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestVersionPrintsJSON(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"version": "`+version+`"`) {
		t.Fatalf("version output = %q", out.String())
	}
}

func TestDomainsGetDataByNameRequiresOneArgument(t *testing.T) {
	root := NewRootCommand()
	root.SetArgs([]string{"domains", "get-data-by-name"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err == nil {
		t.Fatal("Execute() succeeded without a domain argument")
	}
}

func TestRootHasNoDuplicateCommandNames(t *testing.T) {
	root := NewRootCommand()
	for _, parent := range root.Commands() {
		seen := make(map[string]bool)
		for _, child := range parent.Commands() {
			if seen[child.Name()] {
				t.Errorf("%s has duplicate child command %q", parent.Name(), child.Name())
			}
			seen[child.Name()] = true
		}
	}
}
