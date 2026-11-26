package dns

import (
	"context"
	"net"
	"net/netip"
)

type lookupClient interface {
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

type systemResolver struct {
	resolver *net.Resolver
}

func newSystemResolver() *systemResolver {
	return &systemResolver{
		resolver: net.DefaultResolver,
	}
}

func (r *systemResolver) LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error) {
	return r.resolver.LookupNetIP(ctx, network, host)
}

func parseIP(value string) (netip.Addr, error) {
	return netip.ParseAddr(value)
}

func normalizeIP(address netip.Addr) netip.Addr {
	return address.Unmap()
}

func normalizeIPString(value string) (string, error) {
	address, err := parseIP(value)
	if err != nil {
		return "", err
	}

	return normalizeIP(address).String(), nil
}

func isValidIP(address netip.Addr) bool {
	return address.IsValid()
}
