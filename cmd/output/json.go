package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

func WriteJSONTo(output io.Writer, result any, pretty bool) error {
	data, err := MarshalJSON(result, pretty)
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	var writeErr error

	if _, err := output.Write(data); err != nil {
		writeErr = fmt.Errorf("write JSON output: %w", err)
	}

	// Saving the report should not prevent displaying it.
	return errors.Join(writeErr, saveScanResult(result))
}

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

	if err := storage.Append(ScanResultsFile, record); err != nil {
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

	for _, event := range scanEvents(scan) {
		if err := storage.Append(ScanErrorsFile, event); err != nil {
			return fmt.Errorf("save scan warning: %w", err)
		}
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

func SaveFailedScanResult(path string, scannedAt time.Time) error {
	if scannedAt.IsZero() {
		scannedAt = time.Now().UTC()
	}

	record := map[string]any{
		"type":       "scan_result",
		"status":     "failed",
		"scanned_at": scannedAt.UTC(),
	}

	if err := storage.Append(path, record); err != nil {
		return fmt.Errorf("save failed scan result: %w", err)
	}

	return nil
}

func RequestsJSONOutput(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}

		name, value, hasValue := strings.Cut(arg, "=")

		switch name {
		case "--json", "--compact", "--pretty":
			if !hasValue {
				return true
			}

			enabled, err := strconv.ParseBool(value)
			if err == nil && enabled {
				return true
			}
		}
	}

	return false
}
