package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func runApplication() error {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	return executeApplication(ctx)
}
