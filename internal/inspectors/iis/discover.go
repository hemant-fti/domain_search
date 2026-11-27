package iis

import (
	"context"
	"domain-search/models"
	"domain-search/pkg/iis"
	"errors"
	"fmt"
	"os"
	"strings"

	"domain-search/pkg/logger"
)

// bindKey identifies one HTTPS binding: IP + port + hostname.
type bindKey struct {
	ip   string
	port int
	host string
}

// normBindIP makes IPs from different parsers comparable:
// "", "*", "0.0.0.0" and "::" all mean "all unassigned"; IPv6 brackets are removed.
func normBindIP(ip string) string {
	ip = strings.ToLower(strings.TrimSpace(ip))
	ip = strings.TrimSuffix(strings.TrimPrefix(ip, "["), "]")
	switch ip {
	case "", "*", "0.0.0.0", "::":
		return "*"
	}
	return ip
}

func makeBindKey(ip string, port int, host string) bindKey {
	return bindKey{
		ip:   normBindIP(ip),
		port: port,
		host: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."),
	}
}

func discoverIIS(ctx context.Context) ([]models.Domain, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	configPath, err := iis.GetIISConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("IIS configuration not found at %s: %w", configPath, err)
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("permission denied reading IIS configuration: %s: %w", configPath, err)
		}
		return nil, fmt.Errorf("failed to read IIS configuration %s: %w", configPath, err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Site status is optional; configuration discovery continues without it.
	statuses, statusErr := getIISSiteStatuses()
	if statusErr != nil {
		logger.Error(statusErr, "IIS site statuses could not be retrieved; continuing without them")
		statuses = nil
	}

	domains, err := ParseWithStatuses(string(data), configPath, statuses)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IIS configuration: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Certificates actually bound in HTTP.sys. This returns partial results
	// together with an error, so keep using the results even when certErr != nil.
	certificates, certErr := iis.GetIISCertificates()
	if certErr != nil {
		logger.Error(certErr, "Some IIS SSL certificates could not be discovered")
	}

	// Index certificates by binding key. Identical bindings (same IP, port and
	// host on different sites) resolve to the same HTTP.sys entry, so keep one.
	certIndex := make(map[bindKey]models.CertificateResult, len(certificates))
	for _, c := range certificates {
		k := makeBindKey(c.IP, c.Port, c.FQDN)
		if _, exists := certIndex[k]; !exists {
			certIndex[k] = c
		}
	}

	// Attach each certificate to the domains whose HTTPS bindings use it.
	for i := range domains {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		attached := make(map[bindKey]bool)

		for _, b := range domains[i].Bindings {
			if !strings.EqualFold(strings.TrimSpace(b.Protocol), "https") {
				continue
			}

			k := makeBindKey(b.IP, b.Port, b.Hostname)
			if attached[k] {
				continue // two identical bindings on one site: attach once
			}

			cert, ok := certIndex[k]
			if !ok {
				continue
			}

			attached[k] = true
			domains[i].Certificates = append(domains[i].Certificates, cert)
		}
	}

	return domains, nil
}
