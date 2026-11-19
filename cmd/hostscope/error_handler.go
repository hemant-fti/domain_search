package main

import (
	"fmt"
	"os"
)

func handleCommandError(err error) error {
	jsonOutput := requestsJSONOutput(os.Args[1:])

	output := os.Stderr

	if jsonOutput {
		output = os.Stdout
	}

	if writeErr := writeError(
		output,
		"command_failed",
		err,
		jsonOutput,
	); writeErr != nil {
		fmt.Fprintln(
			os.Stderr,
			"Could not save error details or display the error.",
		)
	}

	return err
}
