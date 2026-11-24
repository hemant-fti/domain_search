package iis

import (
	"context"

	"domain-search/internal/inspectors"
	"domain-search/internal/logger"
)

type Inspector struct{}

func New() *Inspector {
	return &Inspector{}
}

func (i *Inspector) Name() string {
	return "iis"
}

func (i *Inspector) Detect(ctx context.Context) (bool, error) {
	detected, err := inspectors.DetectWebServer(ctx, "iis")
	if err != nil {
		logger.Error(err, "Failed to detect IIS")
		return false, err
	}

	logger.Info("IIS detection completed", "detected", detected)

	return detected, nil
}

func (i *Inspector) Running(ctx context.Context) (bool, error) {
	running, err := inspectors.IsWebServerRunning(ctx, "iis")
	if err != nil {
		logger.Error(err, "Failed to check IIS status")
		return false, err
	}

	logger.Info("IIS running status checked", "running", running)

	return running, nil
}

func (i *Inspector) Discover(ctx context.Context) ([]inspectors.Domain, error) {
	domains, err := discoverIIS(ctx)
	if err != nil {
		logger.Error(err, "Failed to discover IIS domains")
		return nil, err
	}

	logger.Info("IIS domain discovery completed",
		"domains_found", len(domains))

	return domains, nil
}
