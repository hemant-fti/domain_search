package dns

import (
	"context"
	"net"
	"net/netip"
)

type lookupClient interface {
	LookupNetIP(
		ctx context.Context,
		network string,
		host string,
	) ([]netip.Addr, error)
}

type systemResolver struct {
	resolver *net.Resolver
}

func newSystemResolver() *systemResolver {
	return &systemResolver{
		resolver: net.DefaultResolver,
	}
}

func (r *systemResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) ([]netip.Addr, error) {
	return r.resolver.LookupNetIP(ctx, network, host)
}
