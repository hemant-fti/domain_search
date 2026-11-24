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

	domains, err := Parse(string(data), configPath)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse IIS configuration: %w",
			err,
		)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
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
