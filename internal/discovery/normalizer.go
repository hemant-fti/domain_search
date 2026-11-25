package discovery

import (
	"domain-search/models"
	"sort"
	"strings"
)

func Normalize(input []models.Domain) []models.Domain {
	index := make(map[string]int)
	out := make([]models.Domain, 0, len(input))

	for _, domain := range input {
		domain.Name = strings.TrimSuffix(
			strings.ToLower(strings.TrimSpace(domain.Name)),
			".",
		)

		domain.Aliases = appendUnique(nil, domain.Aliases...)
		domain.Ports = appendUniqueInts(nil, domain.Ports...)
		sort.Ints(domain.Ports)

		// IIS records represent websites, not just DNS hostnames.
		// Preserve each website independently.
		if strings.EqualFold(domain.Source, "iis") {
			out = append(out, domain)
			continue
		}

		// DNS-based domain validation for other inspectors.
		if domain.Name == "" || !strings.Contains(domain.Name, ".") {
			continue
		}

		if pos, exists := index[domain.Name]; exists {
			existing := &out[pos]

			existing.Source = mergeSources(existing.Source, domain.Source)

			if existing.ConfigPath == "" {
				existing.ConfigPath = domain.ConfigPath
			}
			if existing.ProxyTarget == "" {
				existing.ProxyTarget = domain.ProxyTarget
			}
			if existing.SSLCertificate == "" {
				existing.SSLCertificate = domain.SSLCertificate
			}

			existing.Aliases = appendUnique(
				existing.Aliases,
				domain.Aliases...,
			)

			existing.Ports = appendUniqueInts(
				existing.Ports,
				domain.Ports...,
			)
			sort.Ints(existing.Ports)

			continue
		}

		index[domain.Name] = len(out)
		out = append(out, domain)
	}

	return out
}

func mergeSources(existing, added string) string {
	if existing == "" {
		return added
	}

	if added == "" {
		return existing
	}

	for _, source := range strings.Split(existing, ",") {
		if strings.TrimSpace(source) == added {
			return existing
		}
	}

	return existing + "," + added
}

func appendUnique(values []string, added ...string) []string {
	seen := make(map[string]bool, len(values)+len(added))

	result := make([]string, 0, len(values)+len(added))

	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}

		seen[value] = true
		result = append(result, value)
	}

	for _, value := range added {
		if value == "" || seen[value] {
			continue
		}

		seen[value] = true
		result = append(result, value)
	}

	return result
}

func appendUniqueInts(values []int, added ...int) []int {
	seen := make(map[int]bool, len(values)+len(added))

	result := make([]int, 0, len(values)+len(added))

	for _, value := range values {
		if value <= 0 || seen[value] {
			continue
		}

		seen[value] = true
		result = append(result, value)
	}

	for _, value := range added {
		if value <= 0 || seen[value] {
			continue
		}

		seen[value] = true
		result = append(result, value)
	}

	return result
}
