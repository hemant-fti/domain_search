package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"domain-search/internal/discovery"
	"domain-search/internal/inspectors"
	ssh "domain-search/internal/os"
)

type localCertificate struct {
	Domain    string    `json:"domain"`
	Server    string    `json:"server"`
	Path      string    `json:"path"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DaysLeft  int       `json:"days_left"`
	Expired   bool      `json:"expired"`
}

func configuredCertificates(ctx context.Context, domainFilter string) ([]localCertificate, error) {
	service := discovery.NewLocalService()
	domains, err := service.DiscoverDomains(ctx, ssh.NewLocalExecutor(), []string{"nginx", "apache"})
	if err != nil {
		return nil, err
	}

	var certificates []localCertificate
	seen := make(map[string]bool)
	for _, domain := range domains {
		if domainFilter != "" && !strings.EqualFold(domain.Name, domainFilter) && !hasStringFold(domain.Aliases, domainFilter) {
			continue
		}
		path := strings.TrimSpace(domain.SSLCertificate)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read configured certificate %s: %w", path, err)
		}
		found := false
		for len(data) > 0 {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse configured certificate %s: %w", path, err)
			}
			found = true
			certificates = append(certificates, localCertificate{
				Domain:    domain.Name,
				Server:    domain.Source,
				Path:      path,
				Subject:   certificate.Subject.String(),
				Issuer:    certificate.Issuer.String(),
				NotBefore: certificate.NotBefore,
				NotAfter:  certificate.NotAfter,
				DaysLeft:  int(time.Until(certificate.NotAfter).Hours() / 24),
				Expired:   time.Now().After(certificate.NotAfter),
			})
		}
		if !found {
			return nil, fmt.Errorf("configured certificate %s contains no PEM certificate", path)
		}
	}
	return certificates, nil
}

func newCertificateCommand(use string) *cobra.Command {
	var domain string
	var expired bool
	var expiringInText string
	var expiringIn time.Duration
	cmd := newResultCommand(use, "Inspect locally configured TLS certificates", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		certificates, err := configuredCertificates(ctx, domain)
		if err != nil {
			return commandResult{}, err
		}
		if use == "check" {
			filtered := make([]localCertificate, 0, len(certificates))
			for _, certificate := range certificates {
				if expired && !certificate.Expired {
					continue
				}
				if expiringIn > 0 && !certificate.Expired && time.Until(certificate.NotAfter) > expiringIn {
					continue
				}
				filtered = append(filtered, certificate)
			}
			certificates = filtered
		}
		lines := make([]string, 0, len(certificates))
		for _, certificate := range certificates {
			state := "valid"
			if certificate.Expired {
				state = "expired"
			} else if expiringIn > 0 && time.Until(certificate.NotAfter) <= expiringIn {
				state = "expiring soon"
			}
			lines = append(lines, fmt.Sprintf("%s: %s (%s; expires %s; %s days left)",
				certificate.Domain, certificate.Path, state, certificate.NotAfter.Format(time.RFC3339), formatDays(certificate.DaysLeft)))
		}
		if len(lines) == 0 {
			return textResult(certificates, "No locally configured certificates matched."), nil
		}
		return textResult(certificates, strings.Join(lines, "\n")), nil
	})
	cmd.Flags().StringVar(&domain, "domain", "", "filter by configured domain name")
	if use == "check" {
		cmd.Flags().BoolVar(&expired, "expired", false, "show only expired certificates")
		cmd.Flags().StringVar(&expiringInText, "expiring-in", "", "show certificates expiring within a duration (for example 30d or 720h)")
		cmd.PreRunE = func(_ *cobra.Command, _ []string) error {
			if expiringInText == "" {
				expiringIn = 0
				return nil
			}
			duration, err := parseCertificateDuration(expiringInText)
			if err != nil || duration <= 0 {
				return fmt.Errorf("--expiring-in must be a positive duration such as 30d or 720h")
			}
			expiringIn = duration
			if expired && expiringIn > 0 {
				return fmt.Errorf("--expired and --expiring-in cannot be used together")
			}
			return nil
		}
	}
	cmd.Long = "Reports certificates found at local certificate paths referenced by Nginx or Apache configuration. It does not probe remote TLS endpoints or enumerate certificates that are not configured locally."
	return cmd
}

func newConfigServerCommand(name string) *cobra.Command {
	var test, virtualHosts bool
	cmd := newResultCommand(name, "Inspect "+name+" configuration without printing its contents", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		result := struct {
			Server       string              `json:"server"`
			TestOutput   string              `json:"test_output,omitempty"`
			ConfigPaths  []string            `json:"config_paths"`
			VirtualHosts []inspectors.Domain `json:"virtual_hosts,omitempty"`
		}{Server: name, ConfigPaths: []string{}}

		ex := ssh.NewLocalExecutor()
		if test {
			output, err := discovery.NewLocalService().TestConfig(ctx, ex, name)
			if err != nil {
				return commandResult{}, err
			}
			result.TestOutput = output
		}

		inspection, err := discovery.NewLocalService().Inspect(ctx, ex, name, discovery.InspectOptions{
			Domains: virtualHosts,
			Config:  true,
		})
		if err != nil {
			return commandResult{}, err
		}
		result.ConfigPaths = inspection.Configs
		if virtualHosts {
			result.VirtualHosts = inspection.Domains
		}
		lines := []string{"Server: " + name}
		if test {
			lines = append(lines, "Configuration test: "+displayValue(result.TestOutput))
		}
		if len(result.ConfigPaths) == 0 {
			lines = append(lines, "Configuration paths: none discovered")
		} else {
			lines = append(lines, "Configuration paths: "+strings.Join(result.ConfigPaths, ", "))
		}
		if virtualHosts {
			for _, domain := range result.VirtualHosts {
				lines = append(lines, "Virtual host: "+domain.Name)
			}
		}
		return textResult(result, strings.Join(lines, "\n")), nil
	})
	cmd.Flags().BoolVar(&test, "test", false, "run the server's native configuration test")
	cmd.Flags().BoolVar(&virtualHosts, "virtual-hosts", false, "include parsed virtual host metadata")
	return cmd
}

func parseCertificateDuration(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseInt(strings.TrimSuffix(value, "d"), 10, 64)
		if err != nil {
			return 0, err
		}
		maxDays := int64((1<<63 - 1) / int64(24*time.Hour))
		if days > maxDays {
			return 0, fmt.Errorf("duration is too large")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(value)
}

func hasStringFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func formatDays(days int) string {
	if days == 1 || days == -1 {
		return fmt.Sprintf("%d day", days)
	}
	return fmt.Sprintf("%d days", days)
}
