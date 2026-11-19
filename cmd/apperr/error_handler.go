package apperr

import (
	"fmt"
	"os"

	outpt "domain-search/cmd/output"
	"domain-search/pkg/logger"
)

func HandleCommandError(err error) error {
	if err == nil {
		return nil
	}

	jsonOutput := outpt.RequestsJSONOutput(os.Args[1:])

	output := os.Stderr

	if jsonOutput {
		output = os.Stdout
	}

	logger.Error(err, "Command execution failed")

	if writeErr := outpt.WriteError(
		output,
		"command_failed",
		err,
		jsonOutput,
	); writeErr != nil {
		logger.Error(writeErr, "Failed to write command error output")

		fmt.Fprintln(
			os.Stderr,
			"Could not save error details or display the error.",
		)
	}

	return err
}
