package apperr

import (
	"fmt"
	"io"
	"os"

	"domain-search/cmd/output"
	"domain-search/internal/logger"
)

func HandleCommandError(err error, jsonMode bool) error {
	if err == nil {
		return nil
	}

	writer := io.Writer(os.Stderr)
	if jsonMode {
		writer = os.Stdout
	}

	logger.Error(err, "Command execution failed")

	if writeErr := output.WriteError(
		writer,
		"command_failed",
		err,
		jsonMode,
	); writeErr != nil {
		logger.Error(writeErr, "Failed to write command error output")

		fmt.Fprintln(os.Stderr, "Could not display the command error.")
	}

	return err
}
