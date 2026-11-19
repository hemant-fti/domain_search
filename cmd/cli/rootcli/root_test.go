package rootcli

import (
	"strings"
	"testing"
)

func TestRootRegistersCommandHierarchy(t *testing.T) {
	root := NewRootCommand()
	paths := []string{
		"scan", "system info", "system cpu", "system memory", "system disk",
		"system network", "system uptime", "web list", "web nginx", "web apache",
		"web status", "domains list", "domains nginx", "domains apache", "domains dns",
		"ports list", "ports tcp", "ports udp", "services list", "services status",
		"ssl list", "ssl check", "config nginx", "config apache", "version",
	}
	for _, path := range paths {
		t.Run(strings.ReplaceAll(path, " ", "_"), func(t *testing.T) {
			parts := strings.Fields(path)
			command, _, err := root.Find(parts)
			if err != nil {
				t.Fatalf("Find(%q) error = %v", path, err)
			}
			if command == nil {
				t.Fatalf("Find(%q) returned no command", path)
			}
		})
	}
}

func TestDNSCommandRejectsUnsupportedRecordWithoutLookup(t *testing.T) {
	root := NewRootCommand()
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.SetArgs([]string{"domains", "dns", "--domain", "example.com", "--record", "CNAME"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "unsupported DNS record type") {
		t.Fatalf("Execute() error = %v, want unsupported record type", err)
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
