package apache

import (
	"context"

	ssh "domain-search/internal/os"
)

func isApacheRunning(ctx context.Context, ex ssh.Executor) (bool, error) {
	services := []string{
		"apache2",
		"httpd",
	}

	for _, service := range services {
		_, err := ex.Run(ctx, "systemctl is-active --quiet "+service)

		if err == nil {
			return true, nil
		}

		if ctx.Err() != nil {
			return false, ctx.Err()
		}
	}

	_, err := ex.Run(
		ctx,
		"ps -eo comm= | grep -Eq '^(apache2|httpd)$'",
	)

	if err == nil {
		return true, nil
	}

	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	return false, nil
}
