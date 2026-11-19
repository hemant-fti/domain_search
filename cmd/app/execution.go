package app

import (
	"bytes"
	"context"
	"domain-search/cmd/apperr"
	"domain-search/cmd/cli/rootcli"
	"domain-search/cmd/history"
	"io"
	"os"
	"time"
)

func executeApplication(ctx context.Context) error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var fileOutput bytes.Buffer

	ctx = context.WithValue(
		ctx,
		history.CommandOutputCaptureKey{},
		&fileOutput,
	)

	command := rootcli.NewRootCommand()
	command.SetContext(ctx)
	command.SetOut(io.MultiWriter(os.Stdout, &stdout))
	command.SetErr(io.MultiWriter(os.Stderr, &stderr))

	startedAt := time.Now()

	executedCommand, err := command.ExecuteC()

	if executedCommand == nil {
		executedCommand = command
	}

	history.RecordCommandExecution(
		executedCommand,
		os.Args[1:],
		startedAt,
		stdout.String(),
		fileOutput.String(),
		err,
	)

	if err != nil {
		return apperr.HandleCommandError(err)
	}

	return nil
}
