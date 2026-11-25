package dns

import (
	"context"
	"domain-search/models"
	"domain-search/pkg/logger"
	"net/netip"
	"slices"
	"time"
)

type Resolver struct {
	client lookupClient
}

func NewResolver() *Resolver {
	return &Resolver{
		client: newSystemResolver(),
	}
}

func (r *Resolver) Verify(
	ctx context.Context,
	domain string,
	serverIP string,
) models.DNSResult {
	ips, err := r.LookupIP(ctx, domain)

	if err != nil {
		logger.Warn(
			"DNS lookup failed",
			"domain", domain,
			"error", err,
		)

		return models.DNSResult{
			ResolvedIPs:   []string{},
			MatchesServer: false,
			Status:        "unresolved",
		}
	}

	if len(ips) == 0 {
		logger.Warn(
			"No IP addresses resolved",
			"domain", domain,
		)

		return models.DNSResult{
			ResolvedIPs:   []string{},
			MatchesServer: false,
			Status:        "unresolved",
		}
	}

	normalizedIP, err := normalizeIPString(serverIP)
	if err != nil {
		logger.Warn(
			"Invalid server IP address",
			"domain", domain,
			"server_ip", serverIP,
			"error", err,
		)

		return models.DNSResult{
			ResolvedIPs:   ips,
			MatchesServer: false,
			Status:        "invalid_server_ip",
		}
	}

	matches := matchesServerIP(ips, normalizedIP)

	status := "resolved_other_ip"
	if matches {
		status = "matches_server"
	}

	logger.Info(
		"DNS verification completed",
		"domain", domain,
		"server_ip", normalizedIP,
		"resolved_ips", ips,
		"matches_server", matches,
		"status", status,
	)

	return models.DNSResult{
		ResolvedIPs:   ips,
		MatchesServer: matches,
		Status:        status,
	}
}

func (r *Resolver) LookupIP(
	ctx context.Context,
	host string,
) ([]string, error) {
	startedAt := time.Now()

	logger.Debug("DNS IP lookup started", "host", host)

	ips, err := r.client.LookupNetIP(ctx, "ip", host)
	if err != nil {
		logger.Debug(
			"DNS IP lookup failed",
			"host", host,
			"error", err,
			"duration", time.Since(startedAt).String(),
		)

		return nil, err
	}

	addresses := make([]netip.Addr, 0, len(ips))
	seen := make(map[netip.Addr]struct{}, len(ips))

	for _, address := range ips {
		address = normalizeIP(address)

		if !isValidIP(address) {
			continue
		}

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

	logger.Debug(
		"DNS IP lookup completed",
		"host", host,
		"results", len(result),
		"duration", time.Since(startedAt).String(),
	)

	return result, nil
}

func matchesServerIP(ips []string, serverIP string) bool {
	serverAddr, err := parseIP(serverIP)
	if err != nil {
		return false
	}

	serverAddr = normalizeIP(serverAddr)

	for _, ip := range ips {
		addr, err := parseIP(ip)
		if err != nil {
			continue
		}

		if normalizeIP(addr) == serverAddr {
			return true
		}
	}

	return false
}
