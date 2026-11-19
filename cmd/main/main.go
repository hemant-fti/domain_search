package main

import (
	"domain-search/cmd/app"
	"domain-search/pkg/logger"
	"os"
)

func main() {
	logger.Init(logger.Config{
		Level:      "info",
		JSONFormat: true,
		Output:     os.Stdout,
	})

	if err := app.RunApplication(); err != nil {
		logger.Error(err, "Application terminated")
		os.Exit(1)
	}
}
