// Package app runs the hostscope command line: signal handling, command
// execution and redacted command logging.
package app

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"domain-search/pkg/logger"
)

// RunApplication executes the command line until it completes or the
// process receives SIGINT/SIGTERM.
func RunApplication() error {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	logger.Info("Initializing application")

	return executeApplication(ctx)
}
