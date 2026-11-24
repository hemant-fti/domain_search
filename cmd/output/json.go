package output

import (
	"bytes"
	"encoding/json"
	"path/filepath"

	"domain-search/cmd/history"
)

var (
	ScanResultsFile = filepath.Join(
		history.LogDirectory,
		"scan-results.jsonl",
	)

	ScanErrorsFile = filepath.Join(
		history.LogDirectory,
		"scan-errors.jsonl",
	)
)

func MarshalJSON(result any, pretty bool) ([]byte, error) {
	var buffer bytes.Buffer

	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)

	if pretty {
		encoder.SetIndent("", "  ")
	}

	if err := encoder.Encode(result); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
