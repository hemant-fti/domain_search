package dns

import (
	"context"
	"sort"
)

func (r *Resolver) LookupIP(ctx context.Context, host string) ([]string, error) {
	ips, err := r.client.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	unique := make(map[string]struct{})
	result := make([]string, 0, len(ips))

	for _, item := range ips {
		ip := item.IP.String()

		if _, exists := unique[ip]; exists {
			continue
		}

		unique[ip] = struct{}{}
		result = append(result, ip)
	}

	sort.Strings(result)

	return result, nil
}
