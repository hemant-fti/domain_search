package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"domain-scout/service/discovery"
	"domain-scout/service/inspectors"
	"domain-scout/service/inspectors/apache"
	"domain-scout/service/inspectors/nginx"
	"domain-scout/service/inspectors/system"
	ssh "domain-scout/service/os"
)

const defaultTimeout = 2 * time.Minute

func newScanCommand() *cobra.Command {
	var (
		pretty  bool
		compact bool
		timeout time.Duration
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Discover services and system information",
		Long:  "Scan the local server and return discovered services and system information as JSON.",
		Example: `  domain-scout scan
  domain-scout scan --compact
  domain-scout scan --timeout 5m
  sudo domain-scout scan --compact > result.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if timeout <= 0 {
				return fmt.Errorf("timeout must be greater than zero")
			}

			if compact {
				pretty = false
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			return runDiscovery(ctx, pretty)
		},
	}

	cmd.Flags().Bool("json", false, "emit JSON output (compatibility flag)")
	cmd.Flags().BoolVar(&pretty, "pretty", true, "format JSON with indentation")
	cmd.Flags().BoolVar(&compact, "compact", false, "emit compact JSON")
	cmd.Flags().DurationVar(&timeout, "timeout", defaultTimeout, "maximum scan duration")

	return cmd
}

func runDiscovery(ctx context.Context, pretty bool) error {
	registry := []inspectors.Inspector{
		nginx.New(),
		apache.New(),
		system.New(),
	}

	service := discovery.NewService(registry)

	result, err := service.Discover(ctx, ssh.NewLocalExecutor())
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	if err := writeJSON(result, pretty); err != nil {
		return fmt.Errorf("write discovery result: %w", err)
	}

	return nil
}
