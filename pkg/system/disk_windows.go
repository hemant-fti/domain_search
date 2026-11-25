//go:build windows

package system

import (
	"context"
	"fmt"

	"domain-search/models"

	"github.com/shirou/gopsutil/v4/disk"
)

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
