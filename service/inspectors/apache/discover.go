package apache

import (
	"context"
	"fmt"
	"strings"

	"domain-scout/service/inspectors"
	ssh "domain-scout/service/os"
)

func discoverApache(ctx context.Context, ex ssh.Executor) ([]inspectors.Domain, error) {
	// Try Apache discovery without sudo first.
	commands := []string{
		"apachectl -S 2>&1",
		"httpd -S 2>&1",
		"sudo -n apachectl -S 2>&1",
		"sudo -n httpd -S 2>&1",
	}

	var (
		out     string
		lastErr error
	)

	// Discover Apache virtual hosts.
	for _, command := range commands {
		out, lastErr = ex.Run(ctx, command)

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if lastErr == nil {
			break
		}
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

	// Read configuration files using the executor.
	configs, configErr := ex.ReadFiles(ctx, paths)

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Read configuration files and enrich discovered domains.
	if len(configs) > 0 {
		combinedConfig := ""

		for _, path := range paths {
			if config, exists := configs[path]; exists {
				combinedConfig += "\n# DOMAIN_SCOUT_CONFIG:" + path + "\n"
				combinedConfig += config + "\n"
			}
		}

		applyDocumentRoots(domains, combinedConfig)
	}

	if configErr != nil {
		return domains, fmt.Errorf(
			"read Apache virtual host configuration: %w",
			configErr,
		)
	}

	return domains, nil
}
