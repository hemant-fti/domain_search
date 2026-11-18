package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var fileOutput bytes.Buffer

	ctx = context.WithValue(ctx, commandOutputCaptureKey{}, &fileOutput)

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
		jsonOutput := requestsJSONOutput(os.Args[1:])
		output := os.Stderr

		if jsonOutput {
			output = os.Stdout
		}

		if writeErr := writeError(output, "command_failed", err, jsonOutput); writeErr != nil {
			fmt.Fprintln(os.Stderr, "Could not save error details or display the error.")
		}

		os.Exit(1)
	}
}
