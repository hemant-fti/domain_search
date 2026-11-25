package app

import (
	"bytes"
	"context"
	"domain-search/cmd/cli/rootcli"
	"domain-search/cmd/history"
	"domain-search/pkg/logger"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
)

func executeApplication(ctx context.Context) (any, error) {
	var stdout bytes.Buffer
	var fileOutput bytes.Buffer
	var result any

	ctx = context.WithValue(
		ctx,
		history.CommandOutputCaptureKey{},
		&fileOutput,
	)

	ctx = context.WithValue(
		ctx,
		history.CommandResultCaptureKey{},
		&result,
	)

	command := rootcli.NewRootCommand()
	command.SetContext(ctx)

	// Preserve human-readable terminal output.
	command.SetOut(io.MultiWriter(os.Stdout, &stdout))
	command.SetErr(os.Stderr)

	startedAt := time.Now()

	logger.Info("Command execution started")

	executedCommand, err := command.ExecuteC()

	duration := time.Since(startedAt)

	if executedCommand == nil {
		executedCommand = command
	}

	history.RecordCommandExecution(
		executedCommand.CommandPath(),
		os.Args[1:],
		startedAt,
		result,
		fileOutput.String(),
		getOutputFile(executedCommand),
		err,
	)

	if err != nil {
		logger.Error(err, "Command execution failed",
			"command", executedCommand.CommandPath(),
			"duration", duration.String(),
		)

		return nil, err
	}

	logger.Info("Command execution completed",
		"command", executedCommand.CommandPath(),
		"duration", duration.String(),
	)

	return result, nil
}

func getOutputFile(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}

	output, _ := cmd.Flags().GetString("output")
	return output
}
