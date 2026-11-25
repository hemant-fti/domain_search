package system

import (
	"context"
	"domain-search/models"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
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

	info.Hostname = hostInfo.Hostname
	info.ServerOS = hostInfo.Platform
	info.OSVersion = hostInfo.PlatformVersion
	info.Architecture = runtime.GOARCH
	info.Kernel = hostInfo.KernelVersion
	info.Uptime = hostInfo.Uptime

	if kernel, err := KernelVersion(); err == nil && kernel != "" {
		info.Kernel = kernel
	}

	// Use more descriptive OS name where available.
	if osName, err := OperatingSystem(); err == nil && osName != "" {
		info.ServerOS = osName
	}
	currentUser, err := user.Current()
	if err == nil {
		info.CurrentUser = currentUser.Username
	}

	info.Timezone = time.Now().Location().String()
	if info.Timezone == "" {
		info.Timezone = "UTC"
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

	info.CPUModel = cpuInfo.Model
	info.Cores = cpuInfo.Cores
	info.Threads = cpuInfo.Threads
	info.Memory = memoryInfo
	info.Disk = diskInfo
	info.IPv4 = networkInfo.IPv4
	info.IPv6 = networkInfo.IPv6
	info.MAC = networkInfo.MAC

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
		return models.DiskInfo{}, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	usage, err := disk.UsageWithContext(ctx, path)
	if err != nil {
		return models.DiskInfo{}, fmt.Errorf("collect disk usage for %s: %w", path, err)
	}

	const bytesPerGB = 1024 * 1024 * 1024

	return models.DiskInfo{
		TotalGB: float64(usage.Total) / bytesPerGB,
		FreeGB:  float64(usage.Free) / bytesPerGB,
		UsedGB:  float64(usage.Used) / bytesPerGB,
	}, nil
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
		return models.NetworkInfo{}, fmt.Errorf("collect network interfaces: %w", err)
	}

	var ipv4, ipv6 []string
	mac := ""
	seen := make(map[string]bool)

	for _, iface := range interfaces {
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
			if err != nil || ip.IsLoopback() {
				continue
			}

			value := ip.String()
			if seen[value] {
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

	return models.NetworkInfo{
		IPv4: ipv4,
		IPv6: ipv6,
		MAC:  mac,
	}, nil
}

func CollectUptime(ctx context.Context) (uint64, error) {
	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return 0, fmt.Errorf("collect system uptime: %w", err)
	}

	return info.Uptime, nil
}
