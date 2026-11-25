package cli

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"domain-search/cmd/history"
	"domain-search/cmd/output"
	"domain-search/models"
	"domain-search/pkg/logger"
	"domain-search/pkg/system"
)

func NewSystemCPUCommand() *cobra.Command {
	return newResultCommand("cpu", "Show CPU model and core counts", func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
		startedAt := time.Now()
		logger.Debug("CPU inspection started")

		info, err := system.CollectCPUInfo(ctx)
		if err != nil {
			return models.CommandResult{}, err
		}

		logger.Debug("CPU inspection completed",
			"model", info.Model,
			"cores", info.Cores,
			"threads", info.Threads,
			"duration", time.Since(startedAt).String(),
		)

		history.SetCommandResult(ctx, info)

		var human strings.Builder
		if err := output.WriteCPU(&human, info); err != nil {
			return models.CommandResult{}, err
		}

		return textResult(info, human.String()), nil
	})
}

func NewSystemMemoryCommand() *cobra.Command {
	return newResultCommand("memory", "Show memory usage", func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
		startedAt := time.Now()
		logger.Debug("Memory inspection started")

		info, err := system.CollectMemoryInfo(ctx)
		if err != nil {
			return models.CommandResult{}, err
		}

		logger.Debug("Memory inspection completed",
			"total_gb", info.TotalGB,
			"used_gb", info.UsedGB,
			"duration", time.Since(startedAt).String(),
		)

		history.SetCommandResult(ctx, info)

		var human strings.Builder
		if err := output.WriteMemory(&human, info); err != nil {
			return models.CommandResult{}, err
		}

		return textResult(info, human.String()), nil
	})
}

func NewSystemUptimeCommand() *cobra.Command {
	return newResultCommand("uptime", "Show system uptime", func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
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

		logger.Debug("Uptime inspection completed",
			"uptime", value.Display,
			"duration", time.Since(startedAt).String(),
		)

		history.SetCommandResult(ctx, value)

		var human strings.Builder
		if err := output.WriteUptime(&human, uptime); err != nil {
			return models.CommandResult{}, err
		}

		return textResult(value, human.String()), nil
	})
}

func NewDiskUsageCommand() *cobra.Command {
	return newResultCommand("disk", "Show disk usage", func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
		startedAt := time.Now()
		logger.Debug("Disk usage inspection started")

		info, err := system.CollectDiskInfo(ctx, "")
		if err != nil {
			return models.CommandResult{}, err
		}

		logger.Debug("Disk usage inspection completed",
			"total_gb", info.TotalGB,
			"used_gb", info.UsedGB,
			"free_gb", info.FreeGB,
			"available_gb", info.AvailableGB,
			"duration", time.Since(startedAt).String(),
		)

		history.SetCommandResult(ctx, info)

		var human strings.Builder
		if err := output.WriteDisk(&human, info); err != nil {
			return models.CommandResult{}, err
		}

		return textResult(info, human.String()), nil
	})
}

// runSystemInfo prints the full system report and records the same
// models.SystemInfo that `scan` collects.
func runSystemInfo(cmd *cobra.Command) error {
	ctx := cmd.Context()

	info, warnings, err := system.GetSysInfo(ctx)
	if err != nil {
		return err
	}

	history.SetCommandResult(ctx, info)

	var human strings.Builder
	if err := output.WriteSystem(&human, info); err != nil {
		return err
	}

	for _, w := range warnings {
		human.WriteString("  ⚠ " + w + "\n")
	}

	return writeCommandOutput(cmd, "", []byte(human.String()))
}
