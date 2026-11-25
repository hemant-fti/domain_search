//go:build windows

package iis

import (
	"encoding/json"
	"os/exec"
)

func getIISSiteStatuses() (map[string]string, error) {
	script := `
		$sites = @(Get-Website | Select-Object Name, State)
		ConvertTo-Json -InputObject $sites -Compress
	`

	output, err := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		script,
	).Output()

	if err != nil {
		return nil, err
	}

	var sites []struct {
		Name  string `json:"Name"`
		State string `json:"State"`
	}

	if err := json.Unmarshal(output, &sites); err != nil {
		return nil, err
	}

	statuses := make(map[string]string, len(sites))

	for _, site := range sites {
		statuses[site.Name] = site.State
	}

	return statuses, nil
}
