package apache

import (
	"context"
	"fmt"

	"domain-scout/service/inspectors"
	ssh "domain-scout/service/os"
)

func discoverApache(
	ctx context.Context,
	ex ssh.Executor,
) ([]inspectors.Domain, error) {

	out, err := ex.Run(ctx, "sudo -n apachectl -S 2>&1")

	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		out, err = ex.Run(ctx, "sudo -n httpd -S 2>&1")
	}

	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return nil, fmt.Errorf("inspect Apache configuration: %w", err)
	}

	domains := Parse(out)

	paths := make([]string, 0, len(domains))
	seen := make(map[string]bool)

	for _, domain := range domains {
		if domain.ConfigPath == "" || seen[domain.ConfigPath] {
			continue
		}

		seen[domain.ConfigPath] = true
		paths = append(paths, domain.ConfigPath)
	}

	if len(paths) == 0 {
		return domains, nil
	}

	script := "for f in " + shellPaths(paths) +
		"; do printf '\\n# DOMAIN_SCOUT_CONFIG:%s\\n' \"$f\"; cat -- \"$f\"; done"

	configs, configErr := ex.Run(
		ctx,
		"sudo -n sh -c "+shellQuote(script),
	)

	if configErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		configs, configErr = ex.Run(
			ctx,
			"sh -c "+shellQuote(script),
		)
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

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
