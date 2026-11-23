package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"

	"domain-search/cmd/history"
	"domain-search/internal/discovery"
	"domain-search/internal/storage"
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

func saveScanResult(result any) error {
	data, err := MarshalJSON(result, false)
	if err != nil {
		return fmt.Errorf("encode scan result: %w", err)
	}

	var record map[string]json.RawMessage

	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("prepare scan result: %w", err)
	}

	delete(record, "warnings")
	delete(record, "error_events")

	record["type"] = json.RawMessage(`"scan_result"`)

	if err := storage.Append(record, ScanResultsFile); err != nil {
		return fmt.Errorf("save scan result: %w", err)
	}

	var scan discovery.Result

	switch value := result.(type) {
	case discovery.Result:
		scan = value

	case *discovery.Result:
		if value == nil {
			return nil
		}
		scan = *value

	default:
		return nil
	}

	events := scanEvents(scan)
	if len(events) == 0 {
		return nil
	}

	records := make([]any, len(events))
	for i, event := range events {
		records[i] = event
	}

	if err := storage.AppendMany(records, ScanErrorsFile); err != nil {
		return fmt.Errorf("save scan warnings: %w", err)
	}

	return nil
}

func scanEvents(scan discovery.Result) []discovery.ScanError {
	if len(scan.ErrorEvents) == len(scan.Warnings) {
		return scan.ErrorEvents
	}

	events := make([]discovery.ScanError, 0, len(scan.Warnings))

	for _, warning := range scan.Warnings {
		events = append(events, discovery.WarningEvent(warning))
	}

	return events
}
