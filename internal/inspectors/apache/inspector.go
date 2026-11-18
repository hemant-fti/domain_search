package apache

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
	return "apache"
}

func (i *Inspector) Detect(ctx context.Context, ex ssh.Executor) (bool, error) {
	return detectApache(ctx, ex)
}

func (i *Inspector) Running(ctx context.Context, ex ssh.Executor) (bool, error) {
	return isApacheRunning(ctx, ex)
}

func (i *Inspector) Discover(ctx context.Context, ex ssh.Executor) ([]inspectors.Domain, error) {
	return discoverApache(ctx, ex)
}
