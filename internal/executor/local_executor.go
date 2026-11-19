package ssh

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

type LocalExecutor struct{}

func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{}
}

func (e *LocalExecutor) Run(ctx context.Context, command string) (string, error) {
	var cmd *exec.Cmd

	cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command)

	output, err := cmd.CombinedOutput()

	if err != nil {
		if ctx.Err() != nil {
			return string(output), ctx.Err()
		}

		return string(output), fmt.Errorf(
			"command failed: %w: %s",
			err,
			string(output),
		)
	}

	return string(output), nil
}

func (e *LocalExecutor) RunArgs(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return string(output), ctx.Err()
		}
		return string(output), fmt.Errorf("command failed: %w: %s", err, string(output))
	}
	return string(output), nil
}

func (e *LocalExecutor) ReadFiles(ctx context.Context, paths []string) (map[string]string, error) {
	configs := make(map[string]string)

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		configs[path] = string(data)
	}

	return configs, nil
}
