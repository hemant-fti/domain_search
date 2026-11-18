package dns

import (
	"context"
	"net/netip"
	"slices"
)

func (r *Resolver) LookupIP(ctx context.Context, host string) ([]string, error) {
	ips, err := r.client.LookupNetIP(ctx, "ip", host)
	if err != nil {
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
	return result, nil
}
