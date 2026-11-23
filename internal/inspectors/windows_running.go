//go:build windows

package inspectors

import (
	"context"
	"encoding/csv"
	"fmt"
	"os/exec"
	"strings"
)

func IsWebServerRunning(ctx context.Context, service string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	var processNames map[string]struct{}

	switch strings.ToLower(service) {
	case "nginx":
		processNames = map[string]struct{}{
			"nginx.exe": {},
		}

	case "apache":
		processNames = map[string]struct{}{
			"httpd.exe":  {},
			"apache.exe": {},
		}

	case "iis":
		processNames = map[string]struct{}{
			"w3wp.exe": {},
			"was.exe":  {},
		}

	default:
		return false, fmt.Errorf("unsupported web server: %s", service)
	}

	cmd := exec.CommandContext(
		ctx,
		"tasklist.exe",
		"/FO",
		"CSV",
		"/NH",
	)

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}

		return false, fmt.Errorf("failed to read process information: %w", err)
	}

	reader := csv.NewReader(strings.NewReader(string(output)))
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return false, fmt.Errorf("failed to parse process information: %w", err)
	}

	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		if len(record) == 0 {
			continue
		}

		processName := strings.ToLower(strings.TrimSpace(record[0]))

		if _, found := processNames[processName]; found {
			return true, nil
		}
	}

	return false, nil
}
