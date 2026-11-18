package discovery

import (
	"context"

	"domain-search/internal/inspectors"
	osExec "domain-search/internal/os"
)

// statusInspector checks whether a service is running.
type statusInspector interface {
	Running(
		context.Context,
		osExec.Executor,
	) (bool, error)
}

func scanInspector(
	ctx context.Context,
	inspector inspectors.Inspector,
	ex osExec.Executor,
) (ServerInfo, []inspectors.Domain, []string, error) {

	result := ServerInfo{
		Server:  inspector.Name(),
		Domains: []DomainInfo{},
	}

	var found []inspectors.Domain
	var warnings []string

	// Check service status.
	if status, ok := inspector.(statusInspector); ok {
		running, err := status.Running(ctx, ex)

		if err != nil {
			if ctx.Err() != nil {
				return result, nil, warnings, ctx.Err()
			}

			warnings = append(
				warnings,
				inspector.Name()+" status: "+err.Error(),
			)
		} else {
			result.Running = running
		}
	}

	if err := ctx.Err(); err != nil {
		return result, nil, warnings, err
	}

	// Discover configured domains.
	domains, err := inspector.Discover(ctx, ex)

	if err != nil {
		if ctx.Err() != nil {
			return result, nil, warnings, ctx.Err()
		}

		warnings = append(
			warnings,
			inspector.Name()+" scan: "+err.Error(),
		)
	}

	for _, domain := range domains {
		result.Domains = append(result.Domains, DomainInfo{
			Domain:       domain.Name,
			Aliases:      nonNilStrings(domain.Aliases),
			ConfigFile:   domain.ConfigPath,
			DocumentRoot: domain.DocumentRoot,
			Ports:        nonNilInts(domain.Ports),
		})

		found = append(found, domain)

		// Include aliases as individual domains for DNS verification.
		for _, alias := range domain.Aliases {
			aliasDomain := domain
			aliasDomain.Name = alias
			aliasDomain.Aliases = nil

			found = append(found, aliasDomain)
		}
	}

	return result, found, warnings, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}

	return values
}

func nonNilInts(values []int) []int {
	if values == nil {
		return []int{}
	}

	return values
}
