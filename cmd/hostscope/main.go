package main

import (
	"fmt"
	"log/slog"
	"os"

	"domain-search/internal/app"
	"domain-search/pkg/logger"
	"domain-search/pkg/security"
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

	err := app.RunApplication()
	if err != nil {
		logger.Error(err, "Application terminated")
		// Cobra's own error printing is silenced, so report the error here.
		fmt.Fprintf(os.Stderr, "error: %s\n", security.RedactText(err.Error()))
	}
	// Close explicitly: os.Exit would skip a deferred Close.
	_ = logger.Close()
	if err != nil {
		os.Exit(1)
	}
}
