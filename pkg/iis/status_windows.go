//go:build windows

package iis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// siteStatuses returns each website's state (Started, Stopped, ...) via the
// WebAdministration PowerShell module.
func siteStatuses(ctx context.Context) (map[string]string, error) {
	const script = `$sites = @(Get-Website | Select-Object Name, State); ConvertTo-Json -InputObject $sites -Compress`

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("Get-Website: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("Get-Website: %w", err)
	}

	var sites []struct {
		Name  string `json:"Name"`
		State string `json:"State"`
	}
	if err := json.Unmarshal(output, &sites); err != nil {
		return nil, fmt.Errorf("parse Get-Website output: %w", err)
	}

	statuses := make(map[string]string, len(sites))
	for _, s := range sites {
		statuses[s.Name] = s.State
	}
	return statuses, nil
}
