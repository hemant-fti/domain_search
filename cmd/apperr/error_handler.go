package apperr

import (
	outpt "domain-search/cmd/output"
	"fmt"
	"os"
)

func HandleCommandError(err error) error {
	jsonOutput := outpt.RequestsJSONOutput(os.Args[1:])

	output := os.Stderr

	if jsonOutput {
		output = os.Stdout
	}

	if writeErr := outpt.WriteError(
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
