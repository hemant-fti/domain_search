package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func writeJSON(result any, pretty bool) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)

	if pretty {
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	return nil
}

func writeError(output *os.File, code string, err error) {
	if err == nil {
		return
	}

	payload := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{}

	payload.Error.Code = code
	payload.Error.Message = err.Error()

	_ = json.NewEncoder(output).Encode(payload)
}
