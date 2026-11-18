package dns

import "net"

type Resolver struct {
	client *net.Resolver
}

func NewResolver() *Resolver {
	return &Resolver{
		client: net.DefaultResolver,
	}
}
