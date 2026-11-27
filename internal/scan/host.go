package scan

import (
	"context"
	"time"

	"domain-search/pkg/models"
	"domain-search/pkg/system"
)

// primaryIPTimeout bounds the primary-IP probe. It opens a UDP socket and
// sends no packets, so it is normally instant.
const primaryIPTimeout = 2 * time.Second

// hostInfo identifies this server: hostname, kernel and the IP used for
// outbound traffic, which DNS verification compares against.
func hostInfo(ctx context.Context) (models.Info, []string, error) {
	var info models.Info
	var warnings []string

	if err := ctx.Err(); err != nil {
		return info, nil, err
	}
	if hostname, err := system.Hostname(); err == nil {
		info.Hostname = hostname
	}
	if kernel, err := system.KernelVersion(); err == nil {
		info.Kernel = kernel
	}

	ipCtx, cancel := context.WithTimeout(ctx, primaryIPTimeout)
	defer cancel()
	ip, err := system.PrimaryIP(ipCtx)
	if err != nil {
		if ctx.Err() != nil {
			return info, nil, ctx.Err()
		}
		warnings = append(warnings, "network: "+err.Error())
	}
	info.PrimaryIP = ip
	return info, warnings, nil
}
