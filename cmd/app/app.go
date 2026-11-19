package app

import (
	"context"
	"domain-search/internal/logger"
	"os"
	"os/signal"
	"syscall"
)

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
