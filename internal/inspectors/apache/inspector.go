package apache

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
	return "apache"
}

func (i *Inspector) Detect(ctx context.Context) (bool, error) {
	return inspectors.DetectWebServer(ctx, "apache")
}

func (i *Inspector) Running(ctx context.Context) (bool, error) {
	running, err := inspectors.IsWebServerRunning(ctx, "apache")
	if err != nil {
		logger.Error(err, "Failed to check Apache status")
		return false, err
	}

	logger.Info("Apache running status checked", "running", running)

	return running, nil
}

func (i *Inspector) Discover(ctx context.Context) ([]inspectors.Domain, error) {
	domains, err := discoverApache(ctx)
	if err != nil {
		logger.Error(err, "Failed to discover Apache domains")
		return nil, err
	}

	logger.Info("Apache domain discovery completed", "domains_found", len(domains))

	return domains, nil
}
