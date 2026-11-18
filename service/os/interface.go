package ssh

import "context"

type Executor interface {
	Run(ctx context.Context, command string) (string, error)
	ReadFiles(ctx context.Context, paths []string) (map[string]string, error)
}
