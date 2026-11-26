//go:build linux

package system

import (
	"context"
	"domain-search/models"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func DetectOS() (models.OSInfo, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return models.OSInfo{}, err
	}

	values := make(map[string]string)

	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		values[strings.TrimSpace(key)] =
			strings.Trim(strings.TrimSpace(value), `"`)
	}

	name := values["NAME"]
	version := values["VERSION"]

	if name == "" {
		name = values["ID"]
	}

	if version == "" {
		version = values["VERSION_ID"]
	}

	// Remove the codename in parentheses.
	version = strings.TrimSpace(strings.SplitN(version, "(", 2)[0])

	return models.OSInfo{
		Name:         name,
		Family:       values["ID"],
		Version:      version,
		Architecture: runtime.GOARCH,
	}, nil
}

func KernelVersion() (string, error) {
	var uts syscall.Utsname

	if err := syscall.Uname(&uts); err != nil {
		return "", err
	}

	return CharsToString(uts.Release[:]), nil
}

func CharsToString(chars []int8) string {
	var result strings.Builder

	for _, c := range chars {
		if c == 0 {
			break
		}

		result.WriteByte(byte(c))
	}

	return result.String()
}

func detectTimezone(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// 1. Check TZ environment variable.
	if tz := strings.TrimPrefix(strings.TrimSpace(os.Getenv("TZ")), ":"); tz != "" {
		if _, err := time.LoadLocation(tz); err == nil {
			return tz, nil
		}
	}

	// 2. Check /etc/timezone.
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		tz := strings.TrimSpace(string(data))
		if _, err := time.LoadLocation(tz); err == nil {
			return tz, nil
		}
	}

	// 3. Resolve /etc/localtime symlink.
	if target, err := filepath.EvalSymlinks("/etc/localtime"); err == nil {
		const zoneinfo = "/usr/share/zoneinfo/"

		if strings.HasPrefix(target, zoneinfo) {
			tz := strings.TrimPrefix(target, zoneinfo)
			if _, err := time.LoadLocation(tz); err == nil {
				return tz, nil
			}
		}
	}

	return "", fmt.Errorf("could not determine Linux timezone")
}

func collectDiskUsage(ctx context.Context, path string) (models.DiskInfo, error) {
	if err := ctx.Err(); err != nil {
		return models.DiskInfo{}, err
	}

	var stat unix.Statfs_t

	if err := unix.Statfs(path, &stat); err != nil {
		return models.DiskInfo{}, fmt.Errorf(
			"collect disk usage for %s: %w", path, err,
		)
	}

	const bytesPerGiB = 1024 * 1024 * 1024

	blockSize := float64(stat.Bsize)

	total := float64(stat.Blocks) * blockSize
	free := float64(stat.Bfree) * blockSize
	available := float64(stat.Bavail) * blockSize
	used := total - free

	return models.DiskInfo{
		TotalGB:     total / bytesPerGiB,
		UsedGB:      used / bytesPerGiB,
		FreeGB:      free / bytesPerGiB,
		AvailableGB: available / bytesPerGiB,
	}, nil
}
