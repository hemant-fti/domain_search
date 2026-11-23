package system

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
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

func GetSysInfo(ctx context.Context) (server.SystemInfo, []string, error) {
	info := server.SystemInfo{
		IPv4: []string{},
		IPv6: []string{},
	}

	if err := ctx.Err(); err != nil {
		return info, nil, err
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

	// Collect independent system metrics concurrently.
	var (
		cpuInfo     CPUInfo
		memoryInfo  server.MemoryInfo
		diskInfo    server.DiskInfo
		networkInfo NetworkInfo

		cpuErr     error
		memoryErr  error
		diskErr    error
		networkErr error
	)

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		cpuInfo, cpuErr = CollectCPUInfo(ctx)
	}()

	go func() {
		defer wg.Done()
		memoryInfo, memoryErr = CollectMemoryInfo(ctx)
	}()

	go func() {
		defer wg.Done()
		diskInfo, diskErr = CollectDiskInfo(ctx, "")
	}()

	go func() {
		defer wg.Done()
		networkInfo, networkErr = CollectNetworkInfo(ctx)
	}()

	wg.Wait()

	if err := ctx.Err(); err != nil {
		return info, nil, err
	}

	// Populate successfully collected information.
	info.CPUModel = cpuInfo.Model
	info.Cores = cpuInfo.Cores
	info.Threads = cpuInfo.Threads

	info.Memory = memoryInfo
	info.Disk = diskInfo

	info.IPv4 = networkInfo.IPv4
	info.IPv6 = networkInfo.IPv6
	info.MAC = networkInfo.MAC

	// Identify unavailable information.
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
	}

	for _, field := range fields {
		if strings.TrimSpace(field.value) == "" {
			unavailable = append(unavailable, field.name)
		}
	}

	if info.Cores <= 0 || info.Threads <= 0 || cpuErr != nil {
		unavailable = append(unavailable, "cpu")
	}

	if info.Memory.TotalGB <= 0 || memoryErr != nil {
		unavailable = append(unavailable, "memory")
	}

	if info.Disk.TotalGB <= 0 || diskErr != nil {
		unavailable = append(unavailable, "disk")
	}

	if info.Uptime == 0 {
		unavailable = append(unavailable, "uptime")
	}

	if len(info.IPv4) == 0 {
		unavailable = append(unavailable, "ipv4")
	}

	if networkErr != nil {
		unavailable = append(unavailable, "network")
	}

	var warnings []string

	if len(unavailable) > 0 {
		warnings = append(warnings,
			"system information unavailable for: "+
				strings.Join(unavailable, ", "))
	}

	return info, warnings, nil
}

func CollectCPUInfo(ctx context.Context) (CPUInfo, error) {
	if err := ctx.Err(); err != nil {
		return CPUInfo{}, err
	}

	cores, err := cpu.CountsWithContext(ctx, false)
	if err != nil {
		return CPUInfo{}, fmt.Errorf("collect physical CPU count: %w", err)
	}

	threads, err := cpu.CountsWithContext(ctx, true)
	if err != nil {
		if ctx.Err() != nil {
			return CPUInfo{}, ctx.Err()
		}
		threads = runtime.NumCPU()
	}

	cpuDetails, err := cpu.InfoWithContext(ctx)
	if err != nil {
		return CPUInfo{}, fmt.Errorf("collect CPU model: %w", err)
	}

	model := ""
	if len(cpuDetails) > 0 {
		model = cpuDetails[0].ModelName
	}

	return CPUInfo{
		Model:   model,
		Cores:   cores,
		Threads: threads,
	}, nil
}

func CollectMemoryInfo(ctx context.Context) (server.MemoryInfo, error) {
	if err := ctx.Err(); err != nil {
		return server.MemoryInfo{}, err
	}

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
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("collect system uptime: %w", err)
	}

	return info.Uptime, nil
}

func CollectDiskInfo(ctx context.Context, path string) (server.DiskInfo, error) {
	var result server.DiskInfo

	if err := ctx.Err(); err != nil {
		return result, err
	}

	path = strings.TrimSpace(path)
	if path == "" {
		path = systemDiskPath()
	}

	usage, err := disk.UsageWithContext(ctx, path)
	if err != nil {
		return result, fmt.Errorf("collect disk usage for %s: %w", path, err)
	}

	const bytesPerGiB = 1024 * 1024 * 1024

	result.TotalGB = float64(usage.Total) / bytesPerGiB
	result.FreeGB = float64(usage.Free) / bytesPerGiB
	result.UsedGB = float64(usage.Used) / bytesPerGiB

	return result, nil
}

func CollectNetworkInfo(ctx context.Context) (NetworkInfo, error) {
	if err := ctx.Err(); err != nil {
		return NetworkInfo{}, err
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("collect network interfaces: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return NetworkInfo{}, err
	}

	ipv4, ipv6, mac := collectNetworkInterfaces(interfaces)

	return NetworkInfo{
		IPv4: ipv4,
		IPv6: ipv6,
		MAC:  mac,
	}, nil
}

func collectNetworkInterfaces(interfaces []net.Interface) ([]string, []string, string) {
	ipv4 := []string{}
	ipv6 := []string{}
	mac := ""

	seen := make(map[string]bool)

	for _, iface := range interfaces {
		// Ignore inactive and loopback interfaces.
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if mac == "" && len(iface.HardwareAddr) > 0 {
			mac = iface.HardwareAddr.String()
		}

		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil {
				continue
			}

			value := ip.String()

			if ip.IsLoopback() || seen[value] {
				continue
			}

			seen[value] = true

			if ip.To4() != nil {
				ipv4 = append(ipv4, value)
			} else {
				ipv6 = append(ipv6, value)
			}
		}
	}

	return ipv4, ipv6, mac
}
