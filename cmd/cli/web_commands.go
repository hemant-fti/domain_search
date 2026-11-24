package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

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

		result, err := service.Inspect(ctx, name, discovery.InspectOptions{
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
		func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
			startedAt := time.Now()

			service := discovery.NewLocalService()

			names := []string{serverName}

			if serverName == "" {
				names = service.InspectorNames()
			}

			if len(names) == 0 {
				return commandResult{}, fmt.Errorf(
					"no web server inspectors are registered for this platform",
				)
			}

			logger.Info("Domain inspection started", "servers", names)

			domains, failures := inspectDomains(ctx, service, names)

			var lines []string

			for _, domain := range domains {
				line := fmt.Sprintf(
					"%s (%s)",
					domain.Name,
					domain.Source,
				)

				if domain.DocumentRoot != "" {
					line += " -> " + domain.DocumentRoot
				}

				if len(domain.Aliases) > 0 {
					line += " [aliases: " +
						strings.Join(domain.Aliases, ", ") + "]"
				}

				lines = append(lines, line)
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
				return commandResult{}, fmt.Errorf(
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

			return textResult(
				domains,
				strings.Join(lines, "\n"),
			), nil
		},
	)
}

func NewDomainsGetdatabyServerNameCommand() *cobra.Command {
	cmd := newResultCommand(
		"get-data-by-name <domain>",
		"Retrieve domain data by name",
		func(ctx context.Context, cmd *cobra.Command) (commandResult, error) {
			args := cmd.Flags().Args()

			if len(args) == 0 {
				return commandResult{}, fmt.Errorf("domain name cannot be empty")
			}

			name := strings.TrimSpace(args[0])

			if name == "" {
				return commandResult{}, fmt.Errorf(
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

				human := fmt.Sprintf(
					"Domain: %s\n"+
						"Server: %s\n"+
						"Configuration: %s\n"+
						"Document Root: %s\n"+
						"Proxy Target: %s\n"+
						"SSL Certificate: %s\n"+
						"Aliases: %s\n"+
						"Ports: %v",
					domain.Name,
					domain.Source,
					domain.ConfigPath,
					domain.DocumentRoot,
					domain.ProxyTarget,
					domain.SSLCertificate,
					strings.Join(domain.Aliases, ", "),
					domain.Ports,
				)

				if len(failures) > 0 {
					human += "\n\nWarnings:\n" +
						strings.Join(failures, "\n")
				}

				return textResult(domain, human), nil
			}

			if len(failures) > 0 {
				return commandResult{}, fmt.Errorf(
					"domain %q was not found; some servers could not be inspected: %s",
					name,
					strings.Join(failures, "; "),
				)
			}

			return commandResult{}, fmt.Errorf(
				"domain %q was not found in the available web server configurations",
				name,
			)
		},
	)

	cmd.Args = cobra.ExactArgs(1)

	return cmd
}
