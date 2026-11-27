package main

import (
	"domain-search/cmd/app"
	"domain-search/pkg/logger"
	"fmt"
	"log/slog"
	"os"
)

func main() {
	if err := logger.Init(logger.Config{
		Level:      slog.LevelDebug,
		FilePath:   "application.jsonl",
		Console:    false,
		JSONFormat: true,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "initialize logger: %v\n", err)
		os.Exit(1)
	}

	defer logger.Close()

	if err := app.RunApplication(); err != nil {
		logger.Error(err, "Application terminated")
		os.Exit(1)
	}
}
