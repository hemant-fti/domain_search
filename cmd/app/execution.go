package app

import (
	"context"
	"domain-search/cmd/cli/rootcli"
	"domain-search/internal/security"

	"domain-search/pkg/logger"
	"os"
	"time"
)

func executeApplication(ctx context.Context) error {
	command := rootcli.NewRootCommand()

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
		"response",
	}

	if err != nil {
		logger.Error(err, "Command execution failed", fields...)
		return err
	}

	logger.Info("Command execution completed", fields...)

	return nil
}
