package apache

import (
	"context"

	ssh "domain-search/internal/executor"
	"domain-search/internal/inspectors"
	"domain-search/pkg/logger"
)

type Inspector struct{}

func New() *Inspector {
	return &Inspector{}
}

func (i *Inspector) Name() string {
	return "apache"
}

func (i *Inspector) Detect(ctx context.Context, ex ssh.Executor) (bool, error) {
	return inspectors.DetectWebServer(ctx, ex, "apache")
}

func (i *Inspector) Running(ctx context.Context, ex ssh.Executor) (bool, error) {
	running, err := inspectors.IsWebServerRunning(ctx, ex, "apache")
	if err != nil {
		logger.Error(err, "Failed to check Apache status")
		return false, err
	}

	logger.Info("Apache running status checked", "running", running)

	return running, nil
}

func (i *Inspector) Discover(ctx context.Context, ex ssh.Executor) ([]inspectors.Domain, error) {
	domains, err := discoverApache(ctx, ex)
	if err != nil {
		logger.Error(err, "Failed to discover Apache domains")
		return nil, err
	}

	logger.Info("Apache domain discovery completed", "domains_found", len(domains))

	return domains, nil
}
