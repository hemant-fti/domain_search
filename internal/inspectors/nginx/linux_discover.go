//go:build linux

package nginx

import (
	"context"
	"domain-search/models"
	"fmt"
	"os/exec"
	"strings"
)

func discoverNginx(ctx context.Context) ([]models.Domain, error) {
	nginxPath, err := exec.LookPath("nginx")
	if err != nil {
		return nil, fmt.Errorf("nginx executable not found: %w", err)
	}

	output, err := executeNginxConfig(ctx, nginxPath)
	if err != nil {
		return nil, fmt.Errorf("read nginx configuration: %w", err)
	}

	return Parse(output), nil
}

func executeNginxConfig(ctx context.Context, nginxPath string) (string, error) {
	cmd := exec.CommandContext(ctx, nginxPath, "-T")

	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), nil
	}

	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	sudoPath, sudoErr := exec.LookPath("sudo")
	if sudoErr != nil {
		return "", fmt.Errorf(
			"nginx -T failed: %w; sudo is unavailable",
			err,
		)
	}

	sudoCmd := exec.CommandContext(ctx, sudoPath, "-n", nginxPath, "-T")
	sudoOutput, sudoErr := sudoCmd.CombinedOutput()

	if sudoErr != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		return "", fmt.Errorf(
			"nginx -T failed: %s; sudo retry failed: %s",
			strings.TrimSpace(string(output)),
			strings.TrimSpace(string(sudoOutput)),
		)
	}

	return string(sudoOutput), nil
}
