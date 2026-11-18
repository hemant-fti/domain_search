package apache

import (
	"context"
	"fmt"
	"strings"

	"domain-scout/service/inspectors"
	ssh "domain-scout/service/os"
)

func discoverApache(
	ctx context.Context,
	ex ssh.Executor,
) ([]inspectors.Domain, error) {

	// Try Apache discovery without sudo first.
	// Most Apache installations allow apachectl -S
	// to inspect virtual hosts without elevated privileges.
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

	domains := Parse(out)

	// Collect unique Apache configuration paths.
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

	// Read all discovered VirtualHost configuration files.
	script := "for f in " + shellPaths(paths) +
		"; do printf '\\n# DOMAIN_SCOUT_CONFIG:%s\\n' \"$f\"; cat -- \"$f\"; done"

	// Try without sudo first.
	configs, configErr := ex.Run(
		ctx,
		"sh -c "+shellQuote(script),
	)

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Retry with non-interactive sudo if necessary.
	if configErr != nil {
		configs, configErr = ex.Run(
			ctx,
			"sudo -n sh -c "+shellQuote(script),
		)
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Enrich discovered websites with configuration data.
	if configs != "" {
		applyDocumentRoots(domains, configs)
	}

	if configErr != nil {
		return domains, fmt.Errorf(
			"read Apache virtual host configuration: %w",
			configErr,
		)
	}

	return domains, nil
}
