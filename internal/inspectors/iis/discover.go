package iis

import (
	"context"
	"domain-search/models"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func discoverIIS(ctx context.Context) ([]models.Domain, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	configPath, err := getIISConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("IIS configuration not found at %s: %w", configPath, err)
		}

		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("permission denied reading IIS configuration: %s: %w", configPath, err)
		}

		return nil, fmt.Errorf("failed to read IIS configuration %s: %w", configPath, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	statuses, statusErr := getIISSiteStatuses()
	if statusErr != nil {
		// Site status is optional; configuration discovery can continue.
		statuses = nil
	}

	domains, err := ParseWithStatuses(string(data), configPath, statuses)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IIS configuration: %w", err)
	}

	return domains, nil
}

func getIISConfigPath() (string, error) {
	windowsDir := os.Getenv("windir")
	if windowsDir == "" {
		windowsDir = `C:\Windows`
	}

	systemDir := "System32"

	// Sysnative bypasses filesystem redirection for 32-bit processes.
	if runtime.GOARCH == "386" {
		systemDir = "Sysnative"
	}

	configPath := filepath.Join(
		windowsDir,
		systemDir,
		"inetsrv",
		"config",
		"applicationHost.config",
	)

	if _, err := os.Stat(configPath); err != nil {
		return "", fmt.Errorf("IIS configuration unavailable at %s: %w", configPath, err)
	}

	return configPath, nil
}
