//go:build linux

package system

import (
	"context"
	"fmt"

	"domain-search/models"

	"golang.org/x/sys/unix"
)

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
