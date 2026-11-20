package storage

import (
	"log/slog"

	"domain-search/internal/logger"
)

type JSONL struct {
	path string
}

func NewJSONL(path string) *JSONL {
	return &JSONL{path: path}
}

func Append(path string, record any) error {
	return NewJSONL(path).Append(record)
}

func AppendMany(path string, records []any) error {
	return NewJSONL(path).AppendMany(records)
}

func (j *JSONL) Append(record any) error {
	return j.AppendMany([]any{record})
}

func (j *JSONL) AppendMany(records []any) error {
	file, err := logger.OpenLogFile(j.path)
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
