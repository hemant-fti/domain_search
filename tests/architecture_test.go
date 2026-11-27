// Package tests holds repository-wide checks that span several packages.
package tests

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const module = "domain-search/"

type pkgInfo struct {
	ImportPath string
	Imports    []string
}

// listPackages runs `go list -json ./...` for one target OS.
func listPackages(t *testing.T, goos string) []pkgInfo {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command not available")
	}
	cmd := exec.Command(goBin, "list", "-json", "../...")
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list (%s): %v", goos, err)
	}

	var pkgs []pkgInfo
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var p pkgInfo
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// TestDependencyRules enforces docs/dependency-rules.md.
func TestDependencyRules(t *testing.T) {
	// allowed lists, for each pkg/ package, the project packages it may import.
	allowed := map[string][]string{
		"pkg/models":                {},
		"pkg/logger":                {},
		"pkg/security":              {},
		"pkg/tui":                   {},
		"pkg/iis/config":            {},
		"pkg/iis/httpsys":           {},
		"pkg/ssl/inspect":           {},
		"pkg/ssl/store":             {},
		"pkg/ssl/internal/certtest": {},
		"pkg/ssl/certificate":       {"pkg/models"},
		"pkg/ssl/validate":          {"pkg/models", "pkg/ssl/certificate"},
		"pkg/dns":                   {"pkg/models"},
		"pkg/system":                {"pkg/models"},
		"pkg/apache":                {"pkg/models", "pkg/system"},
		"pkg/nginx":                 {"pkg/models", "pkg/system", "pkg/ssl/certificate", "pkg/ssl/validate"},
		"pkg/iis": {"pkg/models", "pkg/system", "pkg/iis/config", "pkg/iis/httpsys",
			"pkg/ssl/certificate", "pkg/ssl/store", "pkg/ssl/validate"},
	}

	for _, goos := range []string{"linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			for _, p := range listPackages(t, goos) {
				name := strings.TrimPrefix(p.ImportPath, module)
				if !strings.HasPrefix(name, "pkg/") {
					continue
				}
				rule, known := allowed[name]
				if !known {
					t.Errorf("%s has no dependency rule; add it to this test and docs/dependency-rules.md", name)
					continue
				}
				for _, imp := range p.Imports {
					if !strings.HasPrefix(imp, module) {
						continue
					}
					dep := strings.TrimPrefix(imp, module)
					if !slices.Contains(rule, dep) {
						t.Errorf("%s must not import %s", name, dep)
					}
				}
			}
		})
	}
}

// TestReusablePackagesDoNotLogGlobally keeps pkg/ free of the application's
// global logger: reusable packages return errors instead.
func TestReusablePackagesDoNotLogGlobally(t *testing.T) {
	for _, p := range listPackages(t, "linux") {
		name := strings.TrimPrefix(p.ImportPath, module)
		if !strings.HasPrefix(name, "pkg/") {
			continue
		}
		if slices.Contains(p.Imports, module+"pkg/logger") {
			t.Errorf("%s imports pkg/logger; return errors instead", name)
		}
	}
}
