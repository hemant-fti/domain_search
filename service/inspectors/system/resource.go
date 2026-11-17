package system

import (
	"context"
	"runtime"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"

	"domain-scout/service/server"
)

func collectCPUInfo(ctx context.Context) (int, int, string) {
	physical, err := cpu.CountsWithContext(ctx, false)
	if err != nil {
		physical = 0
	}

	logical, err := cpu.CountsWithContext(ctx, true)
	if err != nil {
		logical = runtime.NumCPU()
	}

	model := ""

	cpuInfo, err := cpu.InfoWithContext(ctx)
	if err == nil && len(cpuInfo) > 0 {
		model = cpuInfo[0].ModelName
	}

	return physical, logical, model
}

func collectMemoryInfo(ctx context.Context) server.MemoryInfo {
	var result server.MemoryInfo

	memory, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return result
	}

	const bytesPerGB = 1024 * 1024 * 1024

	result.TotalGB = float64(memory.Total) / bytesPerGB
	result.AvailableGB = float64(memory.Available) / bytesPerGB
	result.FreeGB = float64(memory.Free) / bytesPerGB
	result.UsedGB = float64(memory.Used) / bytesPerGB

	return result
}

func collectDiskInfo(ctx context.Context) server.DiskInfo {
	var result server.DiskInfo

	usage, err := disk.UsageWithContext(ctx, "/")
	if err != nil {
		return result
	}

	const bytesPerGB = 1024 * 1024 * 1024

	result.TotalGB = float64(usage.Total) / bytesPerGB
	result.FreeGB = float64(usage.Free) / bytesPerGB
	result.UsedGB = float64(usage.Used) / bytesPerGB

	return result
}
