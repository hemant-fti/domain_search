package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	cmdoutput "domain-search/cmd/output"
	"domain-search/internal/discovery"
	ssh "domain-search/internal/executor"
	"domain-search/internal/inspectors/system"
	"domain-search/internal/server"
)

type systemCommandResult struct {
	System   any      `json:"system"`
	Warnings []string `json:"warnings,omitempty"`
}

func NewSystemInfoCommand() *cobra.Command {
	var all, details bool
	cmd := newResultCommand("info", "Show system identity and resource information", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		info, warnings, err := discovery.NewLocalService().CollectSystem(ctx, ssh.NewLocalExecutor())
		if err != nil {
			return commandResult{}, err
		}
		human := fmt.Sprintf(
			"Hostname: %s\nOperating system: %s %s\nArchitecture: %s\nKernel: %s\nCPU: %s (%d cores, %d threads)\nMemory: %.2f GiB total, %.2f GiB available\nRoot disk: %.2f GiB total, %.2f GiB free\nUptime: %s\nIPv4: %s\nIPv6: %s",
			info.Hostname, info.ServerOS, info.OSVersion, info.Architecture, info.Kernel,
			info.CPUModel, info.Cores, info.Threads, info.Memory.TotalGB, info.Memory.AvailableGB,
			info.Disk.TotalGB, info.Disk.FreeGB, cmdoutput.FormatUptime(info.Uptime),
			cmdoutput.DisplayList(info.IPv4), cmdoutput.DisplayList(info.IPv6),
		)
		if all || details {
			human += fmt.Sprintf(
				"\nMAC address: %s\nCurrent user: %s\nTime zone: %s\nDisk used: %.2f GiB\nMemory free: %.2f GiB",
				cmdoutput.DisplayValue(info.MAC), cmdoutput.DisplayValue(info.CurrentUser), cmdoutput.DisplayValue(info.Timezone),
				info.Disk.UsedGB, info.Memory.FreeGB,
			)
		}
		return textResult(systemCommandResult{System: info, Warnings: warnings}, human), nil
	})
	cmd.Flags().BoolVar(&all, "all", false, "show all collected system fields in human-readable output")
	cmd.Flags().BoolVar(&details, "details", false, "include additional hardware and resource details")
	return cmd
}

func NewSystemCPUCommand() *cobra.Command {
	return newResultCommand("cpu", "Show CPU model and core counts", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		info, err := system.CollectCPUInfo(ctx)
		if err != nil {
			return commandResult{}, err
		}
		return textResult(info,
			fmt.Sprintf("CPU: %s\nCores: %d\nThreads: %d", info.Model, info.Cores, info.Threads)), nil
	})
}

func NewSystemMemoryCommand() *cobra.Command {
	return newResultCommand("memory", "Show memory usage", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		info, err := system.CollectMemoryInfo(ctx)
		if err != nil {
			return commandResult{}, err
		}
		return textResult(info,
			fmt.Sprintf("Total: %.2f GiB\nUsed: %.2f GiB\nAvailable: %.2f GiB\nFree: %.2f GiB",
				info.TotalGB, info.UsedGB, info.AvailableGB, info.FreeGB)), nil
	})
}

func NewSystemDiskCommand() *cobra.Command {
	var path string
	cmd := newResultCommand("disk", "Show disk usage for a path", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		if strings.TrimSpace(path) == "" {
			path = "/"
			if runtime.GOOS == "windows" {
				path = os.Getenv("SystemDrive")
				if path == "" {
					path = "C:"
				}
				path += `\`
			}
		}
		usage, err := system.CollectDiskInfo(ctx, path)
		if err != nil {
			return commandResult{}, err
		}
		value := struct {
			Path  string          `json:"path"`
			Usage server.DiskInfo `json:"usage"`
		}{path, usage}
		return textResult(value, fmt.Sprintf("Path: %s\nTotal: %.2f GiB\nUsed: %.2f GiB\nFree: %.2f GiB",
			path, usage.TotalGB, usage.UsedGB, usage.FreeGB)), nil
	})
	cmd.Flags().StringVar(&path, "path", "", "filesystem path to inspect (defaults to the platform root)")
	return cmd
}

func NewSystemNetworkCommand() *cobra.Command {
	return newResultCommand("network", "Show local network addresses", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		info, err := system.CollectNetworkInfo(ctx)
		if err != nil {
			return commandResult{}, err
		}
		return textResult(info,
			fmt.Sprintf("IPv4: %s\nIPv6: %s\nMAC: %s", cmdoutput.DisplayList(info.IPv4), cmdoutput.DisplayList(info.IPv6), cmdoutput.DisplayValue(info.MAC))), nil
	})
}

func NewSystemUptimeCommand() *cobra.Command {
	return newResultCommand("uptime", "Show system uptime", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		uptime, err := system.CollectUptime(ctx)
		if err != nil {
			return commandResult{}, err
		}
		value := struct {
			Seconds uint64 `json:"seconds"`
			Display string `json:"display"`
		}{uptime, cmdoutput.FormatUptime(uptime)}
		return textResult(value, "Uptime: "+value.Display), nil
	})
}
