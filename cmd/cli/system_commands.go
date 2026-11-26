package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"domain-search/cmd/output"
	"domain-search/models"
	"domain-search/pkg/logger"
	"domain-search/pkg/system"
)

func NewSystemCPUCommand() *cobra.Command {
	return newResultCommand(
		"cpu",
		"Show CPU model and core counts",
		func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
			startedAt := time.Now()
			logger.Debug("CPU inspection started")

			info, err := system.CollectCPUInfo(ctx)
			if err != nil {
				return models.CommandResult{}, err
			}

			logger.Debug(
				"CPU inspection completed",
				"model", info.Model,
				"cores", info.Cores,
				"threads", info.Threads,
				"duration_ms", time.Since(startedAt).Milliseconds(),
			)

			var human strings.Builder
			if err := output.WriteCPU(&human, info); err != nil {
				return models.CommandResult{}, err
			}

			return textResult(info, human.String()), nil
		},
	)
}

func NewSystemMemoryCommand() *cobra.Command {
	return newResultCommand(
		"memory",
		"Show memory usage",
		func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
			startedAt := time.Now()
			logger.Debug("Memory inspection started")

			info, err := system.CollectMemoryInfo(ctx)
			if err != nil {
				return models.CommandResult{}, err
			}

			logger.Debug(
				"Memory inspection completed",
				"total_gb", info.TotalGB,
				"used_gb", info.UsedGB,
				"duration_ms", time.Since(startedAt).Milliseconds(),
			)

			var human strings.Builder
			if err := output.WriteMemory(&human, info); err != nil {
				return models.CommandResult{}, err
			}

			return textResult(info, human.String()), nil
		},
	)
}

func NewSystemUptimeCommand() *cobra.Command {
	return newResultCommand(
		"uptime",
		"Show system uptime",
		func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
			startedAt := time.Now()
			logger.Debug("Uptime inspection started")

			uptime, err := system.CollectUptime(ctx)
			if err != nil {
				return models.CommandResult{}, err
			}

			value := struct {
				Seconds uint64 `json:"seconds"`
				Display string `json:"display"`
			}{
				Seconds: uptime,
				Display: output.FormatUptime(uptime),
			}

			logger.Debug(
				"Uptime inspection completed",
				"uptime", value.Display,
				"duration_ms", time.Since(startedAt).Milliseconds(),
			)

			var human strings.Builder
			if err := output.WriteUptime(&human, uptime); err != nil {
				return models.CommandResult{}, err
			}

			return textResult(value, human.String()), nil
		},
	)
}

func NewDiskUsageCommand() *cobra.Command {
	return newResultCommand(
		"disk",
		"Show disk usage",
		func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
			startedAt := time.Now()
			logger.Debug("Disk inspection started")

			info, err := system.CollectDiskInfo(ctx, "")
			if err != nil {
				return models.CommandResult{}, err
			}

			logger.Debug(
				"Disk usage inspection completed",
				"total_gb", info.TotalGB,
				"used_gb", info.UsedGB,
				"free_gb", info.FreeGB,
				"available_gb", info.AvailableGB,
				"duration_ms", time.Since(startedAt).Milliseconds(),
			)

			var human strings.Builder
			if err := output.WriteDisk(&human, info); err != nil {
				return models.CommandResult{}, err
			}

			return textResult(info, human.String()), nil
		},
	)
}

// runSystemInfo prints the full system report.
func runSystemInfo(cmd *cobra.Command) error {
	ctx := cmd.Context()

	info, warnings, err := system.GetSysInfo(ctx)
	if err != nil {
		return err
	}

	var human strings.Builder
	if err := output.WriteSystem(&human, info); err != nil {
		return err
	}

	for _, warning := range warnings {
		if _, err := fmt.Fprintf(&human, "  ⚠ %s\n", warning); err != nil {
			return fmt.Errorf("write system warning: %w", err)
		}
	}

	return writeCommandOutput(cmd, "", []byte(human.String()))
}
