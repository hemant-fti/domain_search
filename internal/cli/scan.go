package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"domain-search/internal/cli/render"
	"domain-search/internal/scan"
	"domain-search/pkg/logger"

	"github.com/spf13/cobra"
)

// NewScanCommand returns the `scan` command.
func NewScanCommand() *cobra.Command {
	return newResultCommand("scan", "Discover services and system information",
		func(ctx context.Context, _ *cobra.Command, _ []string) (commandResult, error) {
			start := time.Now()

			res, err := scan.NewLocalService().Discover(ctx)
			if err != nil {
				return commandResult{}, fmt.Errorf("discovery failed: %w", err)
			}

			// Record each warning as a structured, redacted event.
			for _, e := range res.ErrorEvents {
				logger.Warn("Scan warning", "type", e.Type, "code", e.Code,
					"component", e.Component, "message", e.Message, "details", e.Details)
			}

			var human strings.Builder
			if err := render.WriteHuman(&human, res); err != nil {
				return commandResult{}, err
			}

			logger.Info("Scan completed", "duration_ms", time.Since(start).Milliseconds())
			return result(res, human.String()), nil
		})
}
