package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	command := newRootCommand()
	if err := command.ExecuteContext(ctx); err != nil {
		if writeErr := writeError(os.Stdout, "command_failed", err, requestsJSONOutput(os.Args[1:])); writeErr != nil {
			fmt.Fprintln(os.Stderr, "Could not save error details or display the error.")
		}
		os.Exit(1)
	}
}

func requestsJSONOutput(args []string) bool {
	if len(args) == 0 || args[0] != "scan" {
		return false
	}
	for _, arg := range args[1:] {
		switch {
		case arg == "--json", arg == "--compact", arg == "--pretty":
			return true
		case strings.HasPrefix(arg, "--json="), strings.HasPrefix(arg, "--compact="), strings.HasPrefix(arg, "--pretty="):
			return true
		}
	}
	return false
}
