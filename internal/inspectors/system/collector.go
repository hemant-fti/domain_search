package system

import (
	"context"
	"fmt"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"

	"domain-search/internal/server"
)

func CollectSystemInfo(ctx context.Context) (server.SystemInfo, []string, error) {
	info := server.SystemInfo{
		IPv4: []string{},
		IPv6: []string{},
	}

	hostInfo, err := host.InfoWithContext(ctx)
	if err != nil {
		return info, nil, fmt.Errorf("collect host information: %w", err)
	}

	info.Hostname = hostInfo.Hostname
	info.ServerOS = hostInfo.Platform
	info.OSVersion = hostInfo.PlatformVersion
	info.Architecture = runtime.GOARCH
	info.Kernel = hostInfo.KernelVersion
	info.Uptime = hostInfo.Uptime

	currentUser, err := user.Current()
	if err != nil {
		return info, nil, fmt.Errorf("get current user: %w", err)
	}
	info.CurrentUser = currentUser.Username
	info.Timezone = time.Now().Location().String()

	if info.Timezone == "" {
		info.Timezone = "UTC"
	}

	info.IPv4, info.IPv6, info.MAC = collectNetworkInfo(ctx)

	info.Cores, info.Threads, info.CPUModel = collectCPUInfo(ctx)

	info.Memory = collectMemoryInfo(ctx)

	info.Disk = collectDiskInfo(ctx)

	var unavailable []string

	fields := []struct {
		name  string
		value string
	}{
		{"hostname", info.Hostname},
		{"server_os", info.ServerOS},
		{"os_version", info.OSVersion},
		{"architecture", info.Architecture},
		{"kernel", info.Kernel},
		{"current_user", info.CurrentUser},
		{"timezone", info.Timezone},
		{"mac", info.MAC},
		{"cpu_model", info.CPUModel},
	}

	for _, field := range fields {
		if strings.TrimSpace(field.value) == "" {
			unavailable = append(unavailable, field.name)
		}
	}

	if info.Cores <= 0 {
		unavailable = append(unavailable, "cores")
	}

	if info.Threads <= 0 {
		unavailable = append(unavailable, "threads")
	}

	if info.Uptime == 0 {
		unavailable = append(unavailable, "uptime")
	}

	if len(info.IPv4) == 0 {
		unavailable = append(unavailable, "ipv4")
	}

	if len(info.IPv6) == 0 {
		unavailable = append(unavailable, "ipv6")
	}

	if info.Disk.TotalGB <= 0 {
		unavailable = append(unavailable, "disk")
	}

	if info.Memory.TotalGB <= 0 {
		unavailable = append(unavailable, "memory")
	}

	var warnings []string

	if len(unavailable) > 0 {
		warnings = append(
			warnings,
			"system information unavailable for: "+strings.Join(unavailable, ", "),
		)
	}

	return info, warnings, nil
}
