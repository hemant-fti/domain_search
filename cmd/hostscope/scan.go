package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"domain-search/internal/discovery"
	"domain-search/internal/inspectors"
	"domain-search/internal/inspectors/apache"
	"domain-search/internal/inspectors/nginx"
	"domain-search/internal/inspectors/system"
	ssh "domain-search/internal/os"
)

const defaultTimeout = 2 * time.Minute

func newScanCommand() *cobra.Command {
	var (
		jsonOutput bool
		pretty     bool
		compact    bool
		timeout    time.Duration
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Discover services and system information",
		Long:  "Scan the local server and display discovered services and system information in a human-readable format. Use --json for JSON output.",
		Example: `  domain-search scan
  domain-search scan --json
  domain-search scan --compact
  domain-search scan --timeout 5m
  sudo domain-search scan --json > result.json`,
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

			useJSON := jsonOutput || compact ||
				cmd.Flags().Changed("pretty")
			return runDiscovery(cmd, ctx, outputPath, useJSON, pretty)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit JSON output instead of human-readable text")
	cmd.Flags().BoolVar(&pretty, "pretty", true, "indent JSON output (implies --json)")
	cmd.Flags().BoolVar(&compact, "compact", false, "emit compact JSON output")
	cmd.Flags().DurationVar(&timeout, "timeout", defaultTimeout, "maximum scan duration")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "write the result to a file")

	return cmd
}

func writeScanOutput(cmd *cobra.Command, path string, result discovery.Result, useJSON, pretty bool) (returnErr error) {
	var output io.Writer = cmd.OutOrStdout()
	var file *os.File
	if path != "" {
		if err := validateScanOutputPath(path); err != nil {
			return err
		}
		var err error
		file, err = os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("open output file %s: %w", path, err)
		}
		output = file
		defer func() {
			if err := file.Close(); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close output file: %w", err))
			}
		}()
	}

	if useJSON {
		return writeJSONTo(output, result, pretty)
	}
	return writeHuman(output, result)
}

func validateScanOutputPath(path string) error {
	outputPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve output file path: %w", err)
	}
	for _, historyPath := range []string{scanResultsFile, scanErrorsFile} {
		resolvedHistoryPath, err := filepath.Abs(historyPath)
		if err != nil {
			return fmt.Errorf("resolve scan history path: %w", err)
		}
		matches := filepath.Clean(outputPath) == filepath.Clean(resolvedHistoryPath)
		if runtime.GOOS == "windows" {
			matches = strings.EqualFold(filepath.Clean(outputPath), filepath.Clean(resolvedHistoryPath))
		}
		if matches {
			return fmt.Errorf("output file cannot be the scan history file %s", historyPath)
		}
	}
	return nil
}

func runDiscovery(cmd *cobra.Command, ctx context.Context, outputPath string, useJSON, pretty bool) error {
	registry := []inspectors.Inspector{
		nginx.New(),
		apache.New(),
		system.New(),
	}

	service := discovery.NewService(registry)

	result, err := service.Discover(ctx, ssh.NewLocalExecutor())
	if err != nil {
		if recordErr := saveFailedScanResult(result.ScannedAt); recordErr != nil {
			return fmt.Errorf(
				"discovery failed: %w (failed to record unsuccessful scan: %v)",
				err,
				recordErr,
			)
		}
		return fmt.Errorf("discovery failed: %w", err)
	}

	if err := writeScanOutput(cmd, outputPath, result, useJSON, pretty); err != nil {
		return fmt.Errorf("write discovery result: %w", err)
	}

	return nil
}
