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
	return newResultCommand(
		"scan",
		"Discover services and system information",
		func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
			startedAt := time.Now()

			service := discovery.NewLocalService()

			result, err := service.Discover(ctx)
			if err != nil {
				return models.CommandResult{}, fmt.Errorf(
					"discovery failed: %w", err,
				)
			}

			var human strings.Builder

			if err := output.WriteHuman(&human, result); err != nil {
				return models.CommandResult{}, err
			}

			logger.Info(
				"Scan completed",
				"duration_ms", time.Since(startedAt).Milliseconds(),
				"output", result,
			)

			return textResult(result, human.String()), nil
		},
	)
}
