package ssh

import "context"

type Executor interface {
	Run(ctx context.Context, command string) (string, error)
	ReadFiles(ctx context.Context, paths []string) (map[string]string, error)
}

type ArgsExecutor interface {
	RunArgs(ctx context.Context, name string, args ...string) (string, error)
}
