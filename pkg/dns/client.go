package dns

import (
	"context"
	"net"
	"net/netip"
)

// LookupClient resolves host names. *net.Resolver satisfies it.
type LookupClient interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var _ LookupClient = (*net.Resolver)(nil)
