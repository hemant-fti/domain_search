//go:build windows

package nginx

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"domain-search/internal/inspectors"
)

func discoverNginx(ctx context.Context) ([]inspectors.Domain, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	nginxPath, err := exec.LookPath("nginx.exe")
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
	if err := ctx.Err(); err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, nginxPath, "-T")

	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), nil
	}

	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	return "", fmt.Errorf(
		"nginx -T failed: %s: %w",
		strings.TrimSpace(string(output)),
		err,
	)
}
