package storage

import (
	"encoding/json"
	"fmt"

	"domain-search/internal/logger"
)

func AppendRecords(records []any, path string) error {
	if len(records) == 0 {
		return nil
	}

	file, err := logger.OpenLogFile(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)

	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("encode JSONL record: %w", err)
		}
	}

	return nil
}
