package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	cmdoutput "domain-search/cmd/output"
	"domain-search/internal/inspectors/system"
	"domain-search/pkg/logger"
)

func NewSystemCPUCommand() *cobra.Command {
	return newResultCommand("cpu", "Show CPU model and core counts", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		startedAt := time.Now()
		logger.Debug("CPU inspection started")

		info, err := system.CollectCPUInfo(ctx)
		if err != nil {
			return commandResult{}, err
		}

		logger.Debug("CPU inspection completed",
			"model", info.Model,
			"cores", info.Cores,
			"threads", info.Threads,
			"duration", time.Since(startedAt).String(),
		)

		return textResult(info,
			fmt.Sprintf("CPU: %s\nCores: %d\nThreads: %d", info.Model, info.Cores, info.Threads)), nil
	})
}

func NewSystemMemoryCommand() *cobra.Command {
	return newResultCommand("memory", "Show memory usage", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		startedAt := time.Now()
		logger.Debug("Memory inspection started")

		info, err := system.CollectMemoryInfo(ctx)
		if err != nil {
			return commandResult{}, err
		}

		logger.Debug("Memory inspection completed",
			"total_gb", info.TotalGB,
			"used_gb", info.UsedGB,
			"duration", time.Since(startedAt).String(),
		)

		return textResult(info,
			fmt.Sprintf("Total: %.2f GiB\nUsed: %.2f GiB\nAvailable: %.2f GiB\nFree: %.2f GiB",
				info.TotalGB, info.UsedGB, info.AvailableGB, info.FreeGB)), nil
	})
}

func NewSystemUptimeCommand() *cobra.Command {
	return newResultCommand("uptime", "Show system uptime", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		startedAt := time.Now()
		logger.Debug("Uptime inspection started")

		uptime, err := system.CollectUptime(ctx)
		if err != nil {
			return commandResult{}, err
		}

		value := struct {
			Seconds uint64 `json:"seconds"`
			Display string `json:"display"`
		}{uptime, cmdoutput.FormatUptime(uptime)}

		logger.Debug("Uptime inspection completed",
			"uptime", value.Display,
			"duration", time.Since(startedAt).String(),
		)

		return textResult(value, "Uptime: "+value.Display), nil
	})
}

func NewDiskUsageCommand() *cobra.Command {
	return newResultCommand("disk", "Show disk usage", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		startedAt := time.Now()
		logger.Debug("Disk usage inspection started")

		info, err := system.CollectDiskInfo(ctx, "/")
		if err != nil {
			return commandResult{}, err
		}

		logger.Debug("Disk usage inspection completed",
			"total_gb", info.TotalGB,
			"used_gb", info.UsedGB,
			"free_gb", info.FreeGB,
			"available_gb", info.AvailableGB,
			"duration", time.Since(startedAt).String(),
		)

		return textResult(info,
			fmt.Sprintf(
				"Total: %.2f GiB\nUsed: %.2f GiB\nAvailable: %.2f GiB\nFree: %.2f GiB",
				info.TotalGB,
				info.UsedGB,
				info.AvailableGB,
				info.FreeGB,
			)), nil
	})
}
