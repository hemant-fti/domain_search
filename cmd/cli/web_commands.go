package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"domain-search/cmd/output"
	"domain-search/internal/discovery"
	"domain-search/models"
	"domain-search/pkg/logger"

	"github.com/spf13/cobra"
)

// inspectDomains discovers domains from the requested web servers.
//
// A failure in one web server does not stop discovery of other servers.
func inspectDomains(
	ctx context.Context,
	service *discovery.Service,
	serverNames []string,
) ([]models.Domain, []string) {
	domains := make([]models.Domain, 0)
	var failures []string

	for _, name := range serverNames {
		logger.Debug("Discovering virtual hosts", "server", name)

		result, err := service.Inspect(ctx, name, models.InspectOptions{
			Domains: true,
		})

		if err != nil {
			logger.Error(
				err,
				"Failed to discover web server domains",
				"server", name,
			)

			failures = append(
				failures,
				fmt.Sprintf("%s: %v", name, err),
			)

			continue
		}

		if result.Detected {
			domains = append(domains, result.Domains...)
		}
	}

	return domains, failures
}

func NewDomainsListCommand() *cobra.Command {
	return NewDomainsCommandForServer("list", "")
}

func NewDomainsCommandForServer(use, serverName string) *cobra.Command {
	return newResultCommand(
		use,
		"List configured virtual hosts",
		func(ctx context.Context, _ *cobra.Command) (models.CommandResult, error) {
			startedAt := time.Now()

			service := discovery.NewLocalService()

			names := []string{serverName}

			if serverName == "" {
				names = service.InspectorNames()
			}

			if len(names) == 0 {
				return models.CommandResult{}, fmt.Errorf(
					"no web server inspectors are registered for this platform",
				)
			}

			logger.Info("Domain inspection started", "servers", names)

			domains, failures := inspectDomains(ctx, service, names)

			var lines []string

			for i, domain := range domains {
				if i > 0 {
					lines = append(lines, "")
				}

				lines = append(lines,
					fmt.Sprintf("Domain: %s", output.DisplayValue(domain.Name)),
					fmt.Sprintf("Server: %s", output.DisplayValue(domain.Source)),
					fmt.Sprintf("Configuration: %s", output.DisplayValue(domain.ConfigPath)),
					fmt.Sprintf("Proxy Target: %s", output.DisplayValue(domain.ProxyTarget)),
					fmt.Sprintf("SSL Certificate: %s", output.DisplayValue(domain.SSLCertificate)),
					fmt.Sprintf("Aliases: %s", output.DisplayList(domain.Aliases)),
					fmt.Sprintf("Ports: %s", output.DisplayPorts(domain.Ports)),
				)
			}

			if len(failures) > 0 {
				lines = append(
					lines,
					"",
					"Warnings:",
					strings.Join(failures, "\n"),
				)
			}

			logger.Info(
				"Domain inspection completed",
				"domains_found", len(domains),
				"failed_servers", len(failures),
				"duration", time.Since(startedAt).String(),
			)

			if len(domains) == 0 && len(failures) > 0 {
				return models.CommandResult{}, fmt.Errorf(
					"domain discovery failed: %s",
					strings.Join(failures, "; "),
				)
			}

			if len(domains) == 0 {
				return textResult(
					domains,
					"No virtual hosts were found.",
				), nil
			}

			var human strings.Builder
			if err := output.WriteDomains(&human, domains); err != nil {
				return models.CommandResult{}, err
			}

			return textResult(domains, human.String()), nil
		},
	)
}

func NewDomainsGetdatabyServerNameCommand() *cobra.Command {
	cmd := newResultCommand(
		"get-data-by-name <domain>",
		"Retrieve domain data by name",
		func(ctx context.Context, cmd *cobra.Command) (models.CommandResult, error) {
			args := cmd.Flags().Args()

			if len(args) == 0 {
				return models.CommandResult{}, fmt.Errorf("domain name cannot be empty")
			}

			name := strings.TrimSpace(args[0])

			if name == "" {
				return models.CommandResult{}, fmt.Errorf(
					"domain name cannot be empty",
				)
			}

			startedAt := time.Now()

			logger.Info("Domain lookup started", "domain", name)

			service := discovery.NewLocalService()
			serverNames := service.InspectorNames()

			domains, failures := inspectDomains(
				ctx,
				service,
				serverNames,
			)

			for _, domain := range domains {
				matched := strings.EqualFold(
					strings.TrimSpace(domain.Name),
					name,
				) || strings.EqualFold(
					strings.TrimSpace(domain.WebsiteName),
					name,
				)
				if !matched {
					for _, alias := range domain.Aliases {
						if strings.EqualFold(
							strings.TrimSpace(alias),
							name,
						) {
							matched = true
							break
						}
					}
				}

				if !matched {
					continue
				}

				logger.Info(
					"Domain lookup completed",
					"domain", name,
					"server", domain.Source,
					"duration", time.Since(startedAt).String(),
				)

				var human strings.Builder

				if err := output.WriteDomain(
					&human,
					domain,
					failures,
				); err != nil {
					return models.CommandResult{}, err
				}

				return textResult(domain, human.String()), nil
			}

			if len(failures) > 0 {
				return models.CommandResult{}, fmt.Errorf(
					"domain %q was not found; some servers could not be inspected: %s",
					name,
					strings.Join(failures, "; "),
				)
			}

			return models.CommandResult{}, fmt.Errorf(
				"domain %q was not found in the available web server configurations",
				name,
			)
		},
	)

	cmd.Args = cobra.ExactArgs(1)

	return cmd
}
