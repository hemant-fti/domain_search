package ssh

import (
	"context"
	"fmt"
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
