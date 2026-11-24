package cli

import (
	"context"
	"fmt"
	"time"

	cmdoutput "domain-search/cmd/output"
	"domain-search/internal/discovery"
	"domain-search/internal/logger"

	"github.com/spf13/cobra"
)

func NewScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scan",
		Short:   "Discover services and system information",
		Long:    "Scan the local server and display discovered services and system information in a human-readable format.",
		Example: "  domain-search scan",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(
				cmd.Context(),
				DefaultTimeout,
			)
			defer cancel()

			return RunDiscovery(cmd, ctx)
		},
	}

	return cmd
}

func RunDiscovery(cmd *cobra.Command, ctx context.Context) error {
	service := discovery.NewLocalService()
	startedAt := time.Now()

	result, err := service.Discover(ctx)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	if err := cmdoutput.WriteHuman(
		cmd.OutOrStdout(),
		result,
	); err != nil {
		return fmt.Errorf("write discovery result: %w", err)
	}

	logger.Info(
		"Scan completed",
		"duration", time.Since(startedAt).String(),
	)

	return nil
}
