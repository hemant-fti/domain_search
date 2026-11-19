package main

import (
	"bytes"
	"context"
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
		commandOutputCaptureKey{},
		&fileOutput,
	)

	command := newRootCommand()
	command.SetContext(ctx)
	command.SetOut(io.MultiWriter(os.Stdout, &stdout))
	command.SetErr(io.MultiWriter(os.Stderr, &stderr))

	startedAt := time.Now()

	executedCommand, err := command.ExecuteC()

	if executedCommand == nil {
		executedCommand = command
	}

	recordCommandExecution(
		executedCommand,
		os.Args[1:],
		startedAt,
		stdout.String(),
		fileOutput.String(),
		err,
	)

	if err != nil {
		return handleCommandError(err)
	}

	return nil
}
