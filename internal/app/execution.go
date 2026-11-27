package app

import (
	"context"
	"os"
	"time"

	"domain-search/internal/cli"
	"domain-search/pkg/logger"
	"domain-search/pkg/security"
)

func executeApplication(ctx context.Context) error {
	command := cli.NewRootCommand()

	command.SetContext(ctx)
	command.SetOut(os.Stdout)
	command.SetErr(os.Stderr)

	startedAt := time.Now()

	executedCommand, err := command.ExecuteC()
	duration := time.Since(startedAt)

	if executedCommand == nil {
		executedCommand = command
	}

	fields := []any{
		"command", executedCommand.CommandPath(),
		"args", security.RedactArgs(os.Args[1:]),
		"duration_ms", duration.Milliseconds(),
	}

	if err != nil {
		logger.Error(err, "Command execution failed", fields...)
		return err
	}

	logger.Info("Command execution completed", fields...)

	return nil
}
