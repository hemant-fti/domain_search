//go:build windows

package inspectors

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func DetectWebServer(ctx context.Context, service string) (bool, error) {
	windowsDir := os.Getenv("windir")
	if windowsDir == "" {
		windowsDir = `C:\Windows`
	}

	appcmd := filepath.Join(
		windowsDir,
		"System32",
		"inetsrv",
		"appcmd.exe",
	)

	if _, err := os.Stat(appcmd); err == nil {
		return true, nil
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	// Fallback: check IIS installation registry key.
	regPath, err := exec.LookPath("reg.exe")
	if err != nil {
		return false, nil
	}

	cmd := exec.CommandContext(
		ctx,
		regPath,
		"query",
		`HKLM\SOFTWARE\Microsoft\InetStp`,
	)

	output, err := cmd.CombinedOutput()

	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	if err == nil && strings.Contains(
		strings.ToLower(string(output)),
		"installpath",
	) {
		return true, nil
	}

	return false, nil
}

func IsWebServerRunning(ctx context.Context, service string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if !strings.EqualFold(service, "iis") {
		return false, fmt.Errorf(
			"unsupported Windows web server: %s",
			service,
		)
	}

	scPath, err := exec.LookPath("sc.exe")
	if err != nil {
		return false, fmt.Errorf("sc.exe not found: %w", err)
	}

	cmd := exec.CommandContext(ctx, scPath, "query", "W3SVC")

	output, err := cmd.CombinedOutput()

	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	result := strings.ToUpper(string(output))

	if strings.Contains(result, "RUNNING") {
		return true, nil
	}

	if strings.Contains(result, "STOPPED") ||
		strings.Contains(result, "1060") {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf(
			"failed to query IIS service: %w: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	return false, nil
}
