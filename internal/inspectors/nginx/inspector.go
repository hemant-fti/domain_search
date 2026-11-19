package nginx

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
	return "nginx"
}

func (i *Inspector) Detect(ctx context.Context) (bool, error) {
	detected, err := inspectors.DetectWebServer(ctx, "nginx")
	if err != nil {
		logger.Error(err, "Failed to detect nginx")
		return false, err
	}

	logger.Info("Nginx detection completed", "detected", detected)

	return detected, nil
}

func (i *Inspector) Running(ctx context.Context) (bool, error) {
	running, err := inspectors.IsWebServerRunning(ctx, "nginx")
	if err != nil {
		logger.Error(err, "Failed to check nginx status")
		return false, err
	}

	logger.Info("Nginx running status checked", "running", running)

	return running, nil
}

func (i *Inspector) Discover(ctx context.Context) ([]inspectors.Domain, error) {
	domains, err := discoverNginx(ctx)
	if err != nil {
		logger.Error(err, "Failed to discover nginx domains")
		return nil, err
	}

	logger.Info("Nginx domain discovery completed", "domains_found", len(domains))

	return domains, nil
}
