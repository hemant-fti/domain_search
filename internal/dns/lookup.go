package dns

import (
	"context"
	"domain-search/internal/logger"
	"net/netip"
	"slices"
	"time"
)

func (r *Resolver) LookupIP(ctx context.Context, host string) ([]string, error) {
	startedAt := time.Now()

	logger.Debug("DNS IP lookup started", "host", host)

	ips, err := r.client.LookupNetIP(ctx, "ip", host)
	if err != nil {
		logger.Debug("DNS IP lookup failed",
			"host", host,
			"error", err,
			"duration", time.Since(startedAt).String(),
		)
		return nil, err
	}

	addresses := make([]netip.Addr, 0, len(ips))
	seen := make(map[netip.Addr]struct{}, len(ips))

	for _, address := range ips {
		if _, exists := seen[address]; exists {
			continue
		}

		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}

	slices.SortFunc(addresses, func(a, b netip.Addr) int {
		return a.Compare(b)
	})

	result := make([]string, len(addresses))
	for i, address := range addresses {
		result[i] = address.String()
	}

	logger.Debug("DNS IP lookup completed",
		"host", host,
		"results", len(result),
		"duration", time.Since(startedAt).String(),
	)

	return result, nil
}
