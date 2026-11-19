package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	cmdoutput "domain-search/cmd/output"
	"domain-search/internal/discovery"
	"domain-search/internal/dns"
	ssh "domain-search/internal/executor"
	"domain-search/internal/inspectors"
	"domain-search/pkg/logger"

	"github.com/spf13/cobra"
)

func NewWebListCommand() *cobra.Command {
	return NewWebInspectionCommand("list", "List installed Nginx and Apache servers", "")
}

func NewWebServerCommand(name string) *cobra.Command {
	return NewWebInspectionCommand(name, "Inspect "+name+" installation and status", name)
}

func NewWebStatusCommand() *cobra.Command {
	return NewWebInspectionCommand("status", "Show whether Nginx and Apache are running", "")
}

func NewWebInspectionCommand(use, short, name string) *cobra.Command {
	var config, versionFlag, domains bool

	cmd := newResultCommand(use, short, func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		startedAt := time.Now()

		names := []string{name}
		if name == "" {
			names = []string{"nginx", "apache"}
		}

		logger.Info("Web inspection started", "servers", names)

		results := make([]discovery.Inspection, 0, len(names))

		service := discovery.NewLocalService()
		executor := ssh.NewLocalExecutor()

		for _, serverName := range names {
			logger.Debug("Inspecting web server", "server", serverName)

			result, err := service.Inspect(ctx, executor, serverName, discovery.InspectOptions{
				Domains: domains,
				Config:  config,
				Version: versionFlag,
			})
			if err != nil {
				return commandResult{}, err
			}

			results = append(results, result)
		}

		lines := make([]string, 0, len(results))

		for _, result := range results {
			state := "not detected"
			if result.Detected {
				state = "stopped"
				if result.Running {
					state = "running"
				}
			}

			line := fmt.Sprintf("%s: %s", result.Server, state)

			if result.Version != "" {
				line += " (" + result.Version + ")"
			}

			if len(result.Configs) > 0 {
				line += "\n  Configurations: " + strings.Join(result.Configs, ", ")
			}

			if len(result.Domains) > 0 {
				domainNames := make([]string, 0, len(result.Domains))
				for _, domain := range result.Domains {
					domainNames = append(domainNames, domain.Name)
				}
				line += "\n  Domains: " + strings.Join(domainNames, ", ")
			}

			lines = append(lines, line)
		}

		logger.Info("Web inspection completed",
			"servers", len(results),
			"duration", time.Since(startedAt).String(),
		)

		return textResult(results, strings.Join(lines, "\n")), nil
	})

	cmd.Flags().BoolVar(&config, "config", false, "include discovered configuration file paths")
	cmd.Flags().BoolVar(&versionFlag, "version", false, "include the installed server version")
	cmd.Flags().BoolVar(&domains, "domains", false, "include discovered virtual hosts")

	return cmd
}

func NewDomainsListCommand() *cobra.Command {
	return NewDomainsCommandForServer("list", "")
}

func NewDomainsServerCommand(name string) *cobra.Command {
	return NewDomainsCommandForServer(name, name)
}

func NewDomainsCommandForServer(use, serverName string) *cobra.Command {
	var serverFilter, configPath, documentRoot string
	var port int
	var aliases bool

	cmd := newResultCommand(use, "List configured virtual hosts", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		startedAt := time.Now()

		names := []string{serverName}
		if serverName == "" {
			names = []string{"nginx", "apache"}
		}

		if serverFilter != "" {
			names = []string{serverFilter}
		}

		logger.Info("Domain inspection started", "servers", names)

		domains := make([]inspectors.Domain, 0)

		service := discovery.NewLocalService()
		executor := ssh.NewLocalExecutor()

		for _, name := range names {
			logger.Debug("Discovering virtual hosts", "server", name)

			result, err := service.Inspect(ctx, executor, name, discovery.InspectOptions{
				Domains: true,
			})
			if err != nil {
				return commandResult{}, err
			}

			if result.Detected {
				domains = append(domains, result.Domains...)
			}
		}

		filtered := make([]inspectors.Domain, 0, len(domains))

		for _, domain := range domains {
			if port != 0 && !ContainsPort(domain.Ports, port) {
				continue
			}

			if configPath != "" && domain.ConfigPath != configPath {
				continue
			}

			if documentRoot != "" && domain.DocumentRoot != documentRoot {
				continue
			}

			if !aliases {
				domain.Aliases = nil
			}

			filtered = append(filtered, domain)
		}

		var lines []string

		for _, domain := range filtered {
			line := fmt.Sprintf("%s (%s)", domain.Name, domain.Source)

			if domain.DocumentRoot != "" {
				line += " -> " + domain.DocumentRoot
			}

			if len(domain.Aliases) > 0 {
				line += " [aliases: " + strings.Join(domain.Aliases, ", ") + "]"
			}

			lines = append(lines, line)
		}

		logger.Info("Domain inspection completed",
			"domains_found", len(filtered),
			"duration", time.Since(startedAt).String(),
		)

		if len(lines) == 0 {
			return textResult(filtered, "No virtual hosts were found."), nil
		}

		return textResult(filtered, strings.Join(lines, "\n")), nil
	})

	cmd.Flags().StringVar(&serverFilter, "server", "", "filter by nginx or apache")
	cmd.Flags().IntVar(&port, "port", 0, "filter by configured listening port")
	cmd.Flags().BoolVar(&aliases, "aliases", false, "include domain aliases")
	cmd.Flags().StringVar(&configPath, "config-path", "", "filter by configuration path")
	cmd.Flags().StringVar(&documentRoot, "document-root", "", "filter by document root")

	cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
		if serverFilter != "" && serverFilter != "nginx" && serverFilter != "apache" {
			return fmt.Errorf("--server must be nginx or apache")
		}

		if (cmd.Flags().Changed("port") && port < 1) || port > 65535 {
			return fmt.Errorf("--port must be between 1 and 65535")
		}

		return nil
	}

	return cmd
}

func NewDomainsDNSCommand() *cobra.Command {
	var domain, record string

	cmd := newResultCommand("dns", "Look up DNS records using the configured resolver", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		startedAt := time.Now()

		logger.Info("DNS lookup started",
			"domain", domain,
			"record", record,
		)

		result, err := dns.NewResolver().LookupRecord(ctx, record, domain)
		if err != nil {
			return commandResult{}, err
		}

		logger.Info("DNS lookup completed",
			"domain", result.Domain,
			"record", result.Type,
			"records_found", len(result.Records),
			"duration", time.Since(startedAt).String(),
		)

		human := fmt.Sprintf(
			"%s records for %s:\n%s",
			result.Type,
			result.Domain,
			cmdoutput.DisplayList(result.Records),
		)

		return textResult(result, human), nil
	})

	cmd.Long = "Look up DNS records through the system resolver. This performs DNS lookup only; it does not enumerate authoritative DNS records."

	cmd.Flags().StringVar(&domain, "domain", "", "domain name to look up")
	cmd.Flags().StringVar(&record, "record", "A", "record type: A, AAAA, MX, NS, or TXT")

	if err := cmd.MarkFlagRequired("domain"); err != nil {
		panic(err)
	}

	return cmd
}

func ContainsPort(ports []int, port int) bool {
	for _, current := range ports {
		if current == port {
			return true
		}
	}
	return false
}

func NewDomainsGetdatabyServerNameCommand() *cobra.Command {
	var domainName string

	cmd := newResultCommand(
		"get-data-by-name",
		"Retrieve domain data by name",
		func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
			name := strings.TrimSpace(domainName)
			if name == "" {
				return commandResult{}, fmt.Errorf("domain name cannot be empty")
			}

			startedAt := time.Now()

			logger.Info("Domain lookup started", "domain", name)

			service := discovery.NewLocalService()
			executor := ssh.NewLocalExecutor()

			domains, err := service.DiscoverDomains(
				ctx,
				executor,
				[]string{"nginx", "apache"},
			)
			if err != nil {
				return commandResult{}, fmt.Errorf("discover domain data: %w", err)
			}

			for _, domain := range domains {
				matched := strings.EqualFold(domain.Name, name)

				if !matched {
					for _, alias := range domain.Aliases {
						if strings.EqualFold(strings.TrimSpace(alias), name) {
							matched = true
							break
						}
					}
				}

				if !matched {
					continue
				}

				logger.Info("Domain lookup completed",
					"domain", name,
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

				return textResult(domain, human), nil
			}

			return commandResult{}, fmt.Errorf(
				"domain %q was not found in Nginx or Apache configurations",
				name,
			)
		},
	)

	cmd.Flags().StringVar(
		&domainName,
		"name",
		"",
		"Name of the domain to retrieve",
	)

	if err := cmd.MarkFlagRequired("name"); err != nil {
		panic(err)
	}

	return cmd
}
