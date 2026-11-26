//go:build windows

package system

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"domain-search/models"

	"github.com/shirou/gopsutil/v4/disk"
	"golang.org/x/sys/windows"
)

func DetectOS() (models.OSInfo, error) {
	version := windows.RtlGetVersion()
	if version == nil {
		return models.OSInfo{}, fmt.Errorf("unable to retrieve Windows version")
	}

	major := version.MajorVersion
	minor := version.MinorVersion
	build := version.BuildNumber

	name := "Microsoft Windows"
	family := "windows"
	osVersion := fmt.Sprintf("%d.%d.%d", major, minor, build)

	// Identify Windows edition.
	switch {
	case major == 10 && build >= 22000:
		name = "Windows 11"
	case major == 10:
		name = "Windows 10"
	case major == 6 && minor == 3:
		name = "Windows 8.1"
	case major == 6 && minor == 2:
		name = "Windows 8"
	case major == 6 && minor == 1:
		name = "Windows 7"
	case major == 6 && minor == 0:
		name = "Windows Vista"
	}

	return models.OSInfo{
		Name:         name,
		Family:       family,
		Version:      osVersion,
		Architecture: runtime.GOARCH,
	}, nil
}

func KernelVersion() (string, error) {
	version := windows.RtlGetVersion()
	if version == nil {
		return "", fmt.Errorf("unable to retrieve Windows version")
	}

	return fmt.Sprintf(
		"%d.%d.%d",
		version.MajorVersion,
		version.MinorVersion,
		version.BuildNumber,
	), nil
}

func detectTimezone(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "tzutil", "/g").Output()
	if err != nil {
		return "", fmt.Errorf("read Windows timezone: %w", err)
	}

	tz := strings.TrimSpace(string(output))
	if tz == "" {
		return "", fmt.Errorf("Windows returned an empty timezone")
	}

	return tz, nil
}

func collectDiskUsage(ctx context.Context, path string) (models.DiskInfo, error) {
	usage, err := disk.UsageWithContext(ctx, path)
	if err != nil {
		return models.DiskInfo{}, fmt.Errorf(
			"collect disk usage for %s: %w", path, err,
		)
	}

	const bytesPerGiB = 1024 * 1024 * 1024

	return models.DiskInfo{
		TotalGB:     float64(usage.Total) / bytesPerGiB,
		UsedGB:      float64(usage.Used) / bytesPerGiB,
		FreeGB:      float64(usage.Free) / bytesPerGiB,
		AvailableGB: float64(usage.Free) / bytesPerGiB,
	}, nil
}
