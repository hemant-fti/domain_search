package discovery

import (
	"context"

	"domain-search/internal/inspectors"
	"domain-search/models"
)

// statusInspector checks whether a service is running.
type statusInspector interface {
	Running(
		context.Context,
	) (bool, error)
}

func scanInspector(
	ctx context.Context,
	inspector inspectors.Inspector,
) (models.ServerInfo, []models.Domain, []string, error) {

	result := models.ServerInfo{
		Server:  inspector.Name(),
		Domains: []models.DomainInfo{},
	}

	var found []models.Domain
	var warnings []string

	// Check service status.
	if status, ok := inspector.(statusInspector); ok {
		running, err := status.Running(ctx)

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

	// Discover configured virtual hosts.
	domains, err := inspector.Discover(ctx)

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
		result.Domains = append(result.Domains, models.DomainInfo{
			Domain:     domain.Name,
			Aliases:    nonNilStrings(domain.Aliases),
			ConfigFile: domain.ConfigPath,
			Ports:      nonNilInts(domain.Ports),
		})

		// Keep one record per virtual host.
		// Aliases remain attached to the primary domain.
		found = append(found, domain)
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
