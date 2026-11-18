package nginx

import (
	"context"

	"domain-search/internal/inspectors"
	ssh "domain-search/internal/os"
)

type Inspector struct{}

func New() *Inspector {
	return &Inspector{}
}

func (i *Inspector) Name() string {
	return "nginx"
}

func (i *Inspector) Detect(ctx context.Context, _ ssh.Executor) (bool, error) {
	return detectNginx(ctx)
}

func (i *Inspector) Running(ctx context.Context, _ ssh.Executor) (bool, error) {
	return isNginxRunning(ctx)
}

func (i *Inspector) Discover(ctx context.Context, _ ssh.Executor) ([]inspectors.Domain, error) {
	return discoverNginx(ctx)
}
