package main

import (
	"domain-search/cmd/app"
	"domain-search/internal/logger"
	"log/slog"
	"os"
)

func main() {
	err := logger.Init(logger.Config{
		Level:      slog.LevelDebug,
		FilePath:   "logs/application.jsonl",
		Console:    true,
		JSONFormat: true,
		AddSource:  false,
	})
	if err != nil {
		panic(err)
	}

	if err := app.RunApplication(); err != nil {
		logger.Error(err, "Application terminated")
		os.Exit(1)
	}
}
