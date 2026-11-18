package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	command := newRootCommand()
	if err := command.ExecuteContext(ctx); err != nil {
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
