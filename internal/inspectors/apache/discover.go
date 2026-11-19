package apache

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"domain-search/internal/inspectors"
)

func discoverApache(ctx context.Context) ([]inspectors.Domain, error) {
	type command struct {
		name string
		args []string
	}

	commands := []command{
		{name: "apachectl", args: []string{"-S"}},
		{name: "httpd", args: []string{"-S"}},
		{name: "sudo", args: []string{"-n", "apachectl", "-S"}},
		{name: "sudo", args: []string{"-n", "httpd", "-S"}},
	}

	var (
		out     string
		lastErr error
	)

	// Discover Apache virtual hosts.
	for _, command := range commands {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		cmd := exec.CommandContext(ctx, command.name, command.args...)

		output, err := cmd.CombinedOutput()

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if err == nil {
			out = string(output)
			lastErr = nil
			break
		}

		lastErr = fmt.Errorf("%s: %w", command.name, err)
	}

	if lastErr != nil {
		return nil, fmt.Errorf(
			"inspect Apache configuration: %w",
			lastErr,
		)
	}

	// Parse discovered virtual hosts.
	domains := Parse(out)

	// Collect unique configuration file paths.
	paths := make([]string, 0, len(domains))
	seen := make(map[string]bool)

	for _, domain := range domains {
		path := strings.TrimSpace(domain.ConfigPath)

		if path == "" || seen[path] {
			continue
		}

		seen[path] = true
		paths = append(paths, path)
	}

	if len(paths) == 0 {
		return domains, nil
	}

	// Read Apache configuration files.
	var (
		combinedConfig strings.Builder
		readErrors     []string
	)

	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		config, err := os.ReadFile(path)
		if err != nil {
			readErrors = append(
				readErrors,
				fmt.Sprintf("%s: %v", path, err),
			)
			continue
		}

		combinedConfig.WriteString("\n# DOMAIN_SCOUT_CONFIG:")
		combinedConfig.WriteString(path)
		combinedConfig.WriteString("\n")
		combinedConfig.Write(config)
		combinedConfig.WriteString("\n")
	}

	// Enrich discovered domains with document roots.
	applyDocumentRoots(domains, combinedConfig.String())

	if len(readErrors) > 0 {
		return domains, fmt.Errorf(
			"read Apache virtual host configuration: %s",
			strings.Join(readErrors, "; "),
		)
	}

	return domains, nil
}
