package apache

import (
	"context"

	ssh "domain-search/internal/executor"
	"domain-search/internal/inspectors"
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
	return inspectors.IsWebServerRunning(ctx, ex, "apache")
}

func (i *Inspector) Discover(ctx context.Context, ex ssh.Executor) ([]inspectors.Domain, error) {
	return discoverApache(ctx, ex)
}
