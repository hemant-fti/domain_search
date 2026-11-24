//go:build linux

package inspectors

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func DetectWebServer(ctx context.Context, service string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	var binaries []string

	switch strings.ToLower(service) {
	case "apache":
		binaries = []string{"apachectl", "httpd"}
	case "nginx":
		binaries = []string{"nginx"}
	default:
		return false, fmt.Errorf("unsupported web server: %s", service)
	}

	for _, binary := range binaries {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		if _, err := exec.LookPath(binary); err == nil {
			return true, nil
		}
	}

	return false, nil
}

func IsWebServerRunning(ctx context.Context, service string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	var processNames map[string]struct{}

	switch strings.ToLower(service) {
	case "nginx":
		processNames = map[string]struct{}{
			"nginx": {},
		}
	case "apache":
		processNames = map[string]struct{}{
			"apache2": {},
			"httpd":   {},
		}
	default:
		return false, fmt.Errorf("unsupported web server: %s", service)
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, fmt.Errorf("failed to read process information: %w", err)
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		if !entry.IsDir() {
			continue
		}

		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		commPath := filepath.Join("/proc", entry.Name(), "comm")

		data, err := os.ReadFile(commPath)
		if err != nil {
			// Process may have exited or access may be restricted.
			continue
		}

		processName := strings.TrimSpace(string(data))

		if _, found := processNames[processName]; found {
			return true, nil
		}
	}

	return false, nil
}
