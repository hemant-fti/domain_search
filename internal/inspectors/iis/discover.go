package iis

import (
	"context"
	"domain-search/models"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func discoverIIS(ctx context.Context) ([]models.Domain, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	configPath := getIISConfigPath()

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to read IIS configuration %s: %w",
			configPath,
			err,
		)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	statuses, err := getIISSiteStatuses()
	if err != nil {
		statuses = nil
	}

	domains, err := ParseWithStatuses(
		string(data),
		configPath,
		statuses,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse IIS configuration: %w",
			err,
		)
	}

	return domains, nil
}

func getIISConfigPath() string {
	windowsDir := os.Getenv("windir")
	if windowsDir == "" {
		windowsDir = `C:\Windows`
	}

	systemDir := "System32"

	// A 32-bit executable running on 64-bit Windows needs
	// Sysnative to bypass filesystem redirection.
	if runtime.GOARCH == "386" {
		systemDir = "Sysnative"
	}

	return filepath.Join(
		windowsDir,
		systemDir,
		"inetsrv",
		"config",
		"applicationHost.config",
	)
}

// Expand Windows environment variables such as %SystemDrive%.
func expandWindowsPath(value string) string {
	return strings.ReplaceAll(value, "%SystemDrive%", os.Getenv("SystemDrive"))
}
