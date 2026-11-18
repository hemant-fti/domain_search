package system

import (
	"context"
	"fmt"
	"runtime"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"

	"domain-search/internal/server"
)

type CPUInfo struct {
	Model   string `json:"model"`
	Cores   int    `json:"cores"`
	Threads int    `json:"threads"`
}

type NetworkInfo struct {
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
	MAC  string   `json:"mac"`
}

func CollectCPUInfo(ctx context.Context) (CPUInfo, error) {
	cores, err := cpu.CountsWithContext(ctx, false)
	if err != nil {
		return CPUInfo{}, fmt.Errorf("collect physical CPU count: %w", err)
	}
	threads, err := cpu.CountsWithContext(ctx, true)
	if err != nil {
		threads = runtime.NumCPU()
	}
	info, err := cpu.InfoWithContext(ctx)
	if err != nil {
		return CPUInfo{}, fmt.Errorf("collect CPU model: %w", err)
	}
	model := ""
	if len(info) > 0 {
		model = info[0].ModelName
	}
	return CPUInfo{Model: model, Cores: cores, Threads: threads}, nil
}

func CollectMemoryInfo(ctx context.Context) (server.MemoryInfo, error) {
	info, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return server.MemoryInfo{}, fmt.Errorf("collect memory usage: %w", err)
	}
	const bytesPerGiB = 1024 * 1024 * 1024
	return server.MemoryInfo{
		TotalGB:     float64(info.Total) / bytesPerGiB,
		AvailableGB: float64(info.Available) / bytesPerGiB,
		FreeGB:      float64(info.Free) / bytesPerGiB,
		UsedGB:      float64(info.Used) / bytesPerGiB,
	}, nil
}

func CollectUptime(ctx context.Context) (uint64, error) {
	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("collect system uptime: %w", err)
	}
	return info.Uptime, nil
}
