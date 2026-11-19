package app

import (
	"context"
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

	return executeApplication(ctx)
}
