package inspectors

import (
	"context"
	ssh "domain-search/internal/executor"
	"fmt"
	"strings"
)

func DetectWebServer(ctx context.Context, ex ssh.Executor, service string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	var commands []string

	switch strings.ToLower(service) {
	case "apache":
		commands = []string{
			"command -v apachectl",
			"command -v httpd",
		}

	case "nginx":
		commands = []string{
			"command -v nginx",
		}

	default:
		return false, fmt.Errorf("unsupported web server: %s", service)
	}

	for _, cmd := range commands {
		if _, err := ex.Run(ctx, cmd); err == nil {
			return true, nil
		}

		if err := ctx.Err(); err != nil {
			return false, err
		}
	}

	return false, nil
}
