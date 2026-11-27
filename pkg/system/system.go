// Package system collects host information: OS, CPU, memory, disk, network,
// uptime and process/service state.
package system

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"runtime"
	"slices"
	"strings"
	"sync"

	"domain-search/pkg/models"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

// GetSysInfo collects system information.
func GetSysInfo(ctx context.Context) (models.SystemInfo, []string, error) {
	info := models.SystemInfo{
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

	// Default OS information from gopsutil.
	info.Hostname = hostInfo.Hostname
	info.ServerOS = hostInfo.Platform
	info.OSVersion = hostInfo.PlatformVersion
	info.Architecture = runtime.GOARCH
	info.Kernel = hostInfo.KernelVersion
	info.Uptime = hostInfo.Uptime

	// Prefer detailed platform-specific OS information.
	osInfo, osErr := DetectOS()

	if osErr == nil {
		info.OS = osInfo

		if osInfo.Name != "" {
			info.ServerOS = osInfo.Name
		}

		if osInfo.Version != "" {
			info.OSVersion = osInfo.Version
		}

		if osInfo.Architecture != "" {
			info.Architecture = osInfo.Architecture
		}
	}

	if kernel, err := KernelVersion(); err == nil && kernel != "" {
		info.Kernel = kernel
	}

	// Current user.
	currentUser, err := user.Current()
	if err == nil {
		info.CurrentUser = currentUser.Username
	}

	// Timezone.
	timezone, timezoneErr := detectTimezone(ctx)
	if timezoneErr == nil {
		info.Timezone = timezone
	}

	var (
		cpuInfo     models.CPUInfo
		memoryInfo  models.MemoryInfo
		diskInfo    models.DiskInfo
		networkInfo models.NetworkInfo

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

	// Assign collected information.
	info.CPUModel = cpuInfo.Model
	info.Cores = cpuInfo.Cores
	info.Threads = cpuInfo.Threads
	info.Memory = memoryInfo
	info.Disk = diskInfo
	info.IPv4 = networkInfo.IPv4
	info.IPv6 = networkInfo.IPv6
	info.MAC = networkInfo.MAC

	if info.IPv4 == nil {
		info.IPv4 = []string{}
	}

	if info.IPv6 == nil {
		info.IPv6 = []string{}
	}

	// Track unavailable information.
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

	if osErr != nil {
		unavailable = append(unavailable, "detailed_os_information")
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
		warnings = append(
			warnings,
			"system information unavailable for: "+
				strings.Join(unavailable, ", "),
		)
	}

	return info, warnings, nil
}

// Hostname returns the system hostname.
func Hostname() (string, error) {
	return os.Hostname()
}

// PrimaryIP returns the primary outbound network IP.
func PrimaryIP(ctx context.Context) (string, error) {
	conn, err := (&net.Dialer{}).DialContext(
		ctx,
		"udp",
		"1.1.1.1:80",
	)
	if err != nil {
		return "", fmt.Errorf("determine primary IP: %w", err)
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", fmt.Errorf("unexpected local address type")
	}

	return addr.IP.String(), nil
}

// CollectCPUInfo collects CPU information.
func CollectCPUInfo(ctx context.Context) (models.CPUInfo, error) {
	if err := ctx.Err(); err != nil {
		return models.CPUInfo{}, err
	}

	cores, err := cpu.CountsWithContext(ctx, false)
	if err != nil {
		return models.CPUInfo{}, fmt.Errorf("collect physical CPU count: %w", err)
	}

	threads, err := cpu.CountsWithContext(ctx, true)
	if err != nil {
		if ctx.Err() != nil {
			return models.CPUInfo{}, ctx.Err()
		}
		threads = runtime.NumCPU()
	}

	details, err := cpu.InfoWithContext(ctx)
	if err != nil {
		return models.CPUInfo{}, fmt.Errorf("collect CPU model: %w", err)
	}

	model := ""
	if len(details) > 0 {
		model = details[0].ModelName
	}

	return models.CPUInfo{
		Model:   model,
		Cores:   cores,
		Threads: threads,
	}, nil
}

// CollectMemoryInfo collects virtual memory information.
func CollectMemoryInfo(ctx context.Context) (models.MemoryInfo, error) {
	if err := ctx.Err(); err != nil {
		return models.MemoryInfo{}, err
	}

	info, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return models.MemoryInfo{}, fmt.Errorf("collect memory usage: %w", err)
	}

	const bytesPerGB = 1024 * 1024 * 1024

	return models.MemoryInfo{
		TotalGB:     float64(info.Total) / bytesPerGB,
		AvailableGB: float64(info.Available) / bytesPerGB,
		FreeGB:      float64(info.Free) / bytesPerGB,
		UsedGB:      float64(info.Used) / bytesPerGB,
	}, nil

}

// CollectDiskInfo collects disk usage information.
func CollectDiskInfo(ctx context.Context, path string) (models.DiskInfo, error) {
	if err := ctx.Err(); err != nil {
		return models.DiskInfo{}, err
	}

	path = strings.TrimSpace(path)
	if path == "" {
		path = systemDiskPath()
	}

	if path == "" {
		return models.DiskInfo{}, fmt.Errorf(
			"unsupported operating system: %s", runtime.GOOS,
		)
	}

	return collectDiskUsage(ctx, path)
}

// systemDiskPath returns the default system disk path.
func systemDiskPath() string {
	switch runtime.GOOS {
	case "windows":
		drive := strings.TrimSpace(os.Getenv("SystemDrive"))
		if drive == "" {
			drive = "C:"
		}
		return drive + `\`

	case "linux":
		return "/"

	default:
		return ""
	}
}

// CollectNetworkInfo collects active network interface information.
func CollectNetworkInfo(ctx context.Context) (models.NetworkInfo, error) {

	if err := ctx.Err(); err != nil {
		return models.NetworkInfo{}, err
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return models.NetworkInfo{}, fmt.Errorf(
			"collect network interfaces: %w", err,
		)
	}

	var result = models.NetworkInfo{
		IPv4: []string{},
		IPv6: []string{},
	}

	for _, iface := range interfaces {
		if err := ctx.Err(); err != nil {
			return models.NetworkInfo{}, err
		}

		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}

			ip := prefix.Addr().Unmap()

			if !ip.IsValid() ||
				ip.IsLoopback() ||
				ip.IsUnspecified() ||
				ip.IsLinkLocalUnicast() {
				continue
			}

			if ip.Is4() && len(result.IPv4) == 0 {
				result.IPv4 = append(result.IPv4, ip.String())
			}

			if ip.Is6() && len(result.IPv6) == 0 {
				result.IPv6 = append(result.IPv6, ip.String())
			}
		}

		if len(result.IPv4) > 0 || len(result.IPv6) > 0 {
			result.MAC = iface.HardwareAddr.String()
			break
		}
	}

	return result, nil
}

func CollectUptime(ctx context.Context) (uint64, error) {
	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("collect system uptime: %w", err)
	}

	return info.Uptime, nil
}

func GetProcessMemory() models.ProcessMemory {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	const mb = 1024 * 1024

	return models.ProcessMemory{
		AllocMB:      float64(stats.Alloc) / mb,
		TotalAllocMB: float64(stats.TotalAlloc) / mb,
		SysMB:        float64(stats.Sys) / mb,
		HeapAllocMB:  float64(stats.HeapAlloc) / mb,
		HeapSysMB:    float64(stats.HeapSys) / mb,
	}
}

// LocalIPs returns every non-loopback address on the interfaces that are up,
// sorted and without duplicates.
func LocalIPs() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}

	seen := make(map[netip.Addr]struct{})
	var addrs []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ifaceAddrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if !ip.IsValid() || ip.IsLoopback() {
				continue
			}
			if _, dup := seen[ip]; dup {
				continue
			}
			seen[ip] = struct{}{}
			addrs = append(addrs, ip)
		}
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })

	out := make([]string, len(addrs))
	for i, ip := range addrs {
		out[i] = ip.String()
	}
	return out, nil
}
