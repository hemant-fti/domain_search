package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"domain-search/cmd/output"
	"domain-search/internal/discovery"
	"domain-search/models"
	"domain-search/pkg/logger"

	"github.com/spf13/cobra"
)

func NewScanCommand() *cobra.Command {
	return newResultCommand("scan", "Discover services and system information",
		func(ctx context.Context, _ *cobra.Command, _ []string) (models.CommandResult, error) {
			start := time.Now()

			res, err := discovery.NewLocalService().Discover(ctx)
			if err != nil {
				return models.CommandResult{}, fmt.Errorf("discovery failed: %w", err)
			}

			var human strings.Builder
			if err := output.WriteHuman(&human, res); err != nil {
				return models.CommandResult{}, err
			}

			// Never log the full result: it is large and may contain host details.
			logger.Info("Scan completed", "duration_ms", time.Since(start).Milliseconds())
			return result(res, human.String()), nil
		})
}
