package storage

import (
	"log/slog"

	"domain-search/internal/logger"
)

func Append(record any, path string) error {
	file, err := logger.OpenLogFile(path)
	if err != nil {
		return err
	}
	defer file.Close()

	log := slog.New(slog.NewJSONHandler(file, nil))
	log.Info("record", "data", record)

	return nil
}

func AppendMany(records []any, path string) error {
	if len(records) == 0 {
		return nil
	}

	file, err := logger.OpenLogFile(path)
	if err != nil {
		return err
	}
	defer file.Close()

	log := slog.New(slog.NewJSONHandler(file, nil))

	for _, record := range records {
		log.Info("record", "data", record)
	}

	return nil
}
