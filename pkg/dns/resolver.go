// Package dns resolves domain names with the system resolver and checks
// whether they point at this server.
package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"domain-search/pkg/models"
)

// Resolver looks up addresses and verifies domains against a server IP.
type Resolver struct {
	client LookupClient
}

// NewResolver returns a Resolver that uses the system resolver.
func NewResolver() *Resolver {
	return NewResolverWithClient(net.DefaultResolver)
}

// NewResolverWithClient returns a Resolver that uses client, e.g. a custom
// *net.Resolver or a test fake.
func NewResolverWithClient(client LookupClient) *Resolver {
	return &Resolver{client: client}
}

// Verify resolves domain and reports whether any address equals serverIP.
// The error explains an unresolved or invalid_server_ip status; the
// DNSResult is always usable.
func (r *Resolver) Verify(ctx context.Context, domain, serverIP string) (models.DNSResult, error) {
	ips, err := r.LookupIP(ctx, domain)
	if err != nil {
		return unresolved(), err
	}
	if len(ips) == 0 {
		return unresolved(), fmt.Errorf("lookup %s: no addresses", domain)
	}

	server, err := netip.ParseAddr(serverIP)
	if err != nil {
		return models.DNSResult{ResolvedIPs: ips, Status: models.DNSStatusInvalidServerIP},
			fmt.Errorf("invalid server IP %q: %w", serverIP, err)
	}
	server = server.Unmap()

	matches := slices.ContainsFunc(ips, func(ip string) bool {
		addr, err := netip.ParseAddr(ip)
		return err == nil && addr.Unmap() == server
	})
	status := models.DNSStatusResolvedOtherIP
	if matches {
		status = models.DNSStatusMatchesServer
	}
	return models.DNSResult{ResolvedIPs: ips, MatchesServer: matches, Status: status}, nil
}

// LookupIP returns the distinct IPv4 and IPv6 addresses of host, sorted.
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]string, error) {
	addrs, err := r.client.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	unique := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsValid() && !slices.Contains(unique, a) {
			unique = append(unique, a)
		}
	}
	slices.SortFunc(unique, netip.Addr.Compare)

	out := make([]string, len(unique))
	for i, a := range unique {
		out[i] = a.String()
	}
	return out, nil
}

func unresolved() models.DNSResult {
	return models.DNSResult{ResolvedIPs: []string{}, Status: models.DNSStatusUnresolved}
}
