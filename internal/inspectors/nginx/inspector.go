package nginx

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
	return "nginx"
}

func (i *Inspector) Detect(ctx context.Context, ex ssh.Executor) (bool, error) {
	return inspectors.DetectWebServer(ctx, ex, "nginx")
}

func (i *Inspector) Running(ctx context.Context, ex ssh.Executor) (bool, error) {
	return inspectors.IsWebServerRunning(ctx, ex, "nginx")
}

func (i *Inspector) Discover(ctx context.Context, _ ssh.Executor) ([]inspectors.Domain, error) {
	return discoverNginx(ctx)
}
