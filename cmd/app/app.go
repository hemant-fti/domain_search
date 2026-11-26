package app

import (
	"context"
	"domain-search/pkg/logger"
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

	err := executeApplication(ctx)
	return err

}
