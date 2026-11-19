package inspectors

import (
	"context"
	ssh "domain-search/internal/executor"
	"fmt"
	"strings"
)

func IsWebServerRunning(ctx context.Context, ex ssh.Executor, service string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	var services []string
	var processCheck string

	switch strings.ToLower(service) {
	case "nginx":
		services = []string{"nginx"}
		processCheck = "nginx"

	case "apache":
		services = []string{"apache2", "httpd"}
		processCheck = "apache2|httpd"

	default:
		return false, fmt.Errorf("unsupported web server: %s", service)
	}

	// Check systemd service status.
	for _, name := range services {
		_, err := ex.Run(
			ctx,
			"systemctl is-active --quiet "+name,
		)

		if err == nil {
			return true, nil
		}

		if err := ctx.Err(); err != nil {
			return false, err
		}
	}

	// Check running processes.
	cmd := fmt.Sprintf(
		"ps -eo comm= | grep -Eq '^(%s)$'",
		processCheck,
	)

	_, err := ex.Run(ctx, cmd)
	if err == nil {
		return true, nil
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}

	return false, nil
}
