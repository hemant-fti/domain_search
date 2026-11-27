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

	statuses, statusErr := getIISSiteStatuses()
	if statusErr != nil {
		// Site status is optional; configuration discovery can continue.
		statuses = nil
	}

	domains, err := ParseWithStatuses(string(data), configPath, statuses)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IIS configuration: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Retrieve certificates actually bound in HTTP.sys.
	certificates, certErr := iis.GetIISCertificates()

	if certErr != nil {
		logger.Error(
			certErr,
			"Some IIS SSL certificates could not be discovered",
		)
	}

	// Associate certificates with their respective IIS websites.
	for i := range domains {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		for _, binding := range domains[i].Bindings {
			if !strings.EqualFold(
				strings.TrimSpace(binding.Protocol),
				"https",
			) {
				continue
			}

			bindingIP := strings.TrimSpace(binding.IP)
			if bindingIP == "" {
				bindingIP = "*"
			}

			for _, cert := range certificates {
				certIP := strings.TrimSpace(cert.IP)
				if certIP == "" {
					certIP = "*"
				}

				if cert.Port != binding.Port {
					continue
				}

				if !strings.EqualFold(certIP, bindingIP) {
					continue
				}

				if !strings.EqualFold(
					strings.TrimSpace(cert.FQDN),
					strings.TrimSpace(binding.Hostname),
				) {
					continue
				}

				domains[i].Certificates = append(
					domains[i].Certificates,
					cert,
				)
			}
		}
	}

	return domains, nil
}
