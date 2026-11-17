package system

import (
	"context"

	"domain-scout/service/inspectors"
	ssh "domain-scout/service/os"
	"domain-scout/service/server"
)

type Inspector struct{}

func New() *Inspector {
	return &Inspector{}
}

func (i *Inspector) Name() string {
	return "system"
}

func (i *Inspector) Detect(context.Context, ssh.Executor) (bool, error) {
	return true, nil
}

func (i *Inspector) Discover(
	ctx context.Context,
	ex ssh.Executor,
) ([]inspectors.Domain, error) {
	return []inspectors.Domain{}, nil
}

func (i *Inspector) Collect(
	ctx context.Context,
	ex ssh.Executor,
) (server.SystemInfo, []string, error) {
	return collectSystemInfo(ctx)
}
