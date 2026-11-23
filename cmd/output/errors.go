package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"domain-search/internal/discovery"
	"domain-search/internal/storage"
)

func WriteError(output io.Writer, code string, err error, jsonMode bool) error {
	if err == nil {
		return nil
	}

	event := discovery.NewScanError(
		"error",
		"",
		err,
		time.Now().UTC(),
	)

	payload := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{}

	payload.Error.Code = code
	payload.Error.Message = event.Message

	var outputErr error

	if jsonMode {
		if err := json.NewEncoder(output).Encode(payload); err != nil {
			outputErr = fmt.Errorf("write JSON error: %w", err)
		}
	} else {
		if _, err := fmt.Fprintln(output, event.Message); err != nil {
			outputErr = fmt.Errorf("write error message: %w", err)
		}
	}

	logErr := storage.Append(event, ScanErrorsFile)

	if logErr != nil {
		logErr = fmt.Errorf("save error event: %w", logErr)
	}

	return errors.Join(outputErr, logErr)
}
