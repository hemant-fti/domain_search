package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"domain-search/internal/dns"
	"domain-search/internal/inspectors"
	"domain-search/internal/inspectors/apache"
	"domain-search/internal/inspectors/nginx"
	ssh "domain-search/internal/os"
)

type webResult struct {
	Server   string              `json:"server"`
	Detected bool                `json:"detected"`
	Running  bool                `json:"running"`
	Version  string              `json:"version,omitempty"`
	Configs  []string            `json:"config_paths,omitempty"`
	Domains  []inspectors.Domain `json:"domains,omitempty"`
}

func ensureLinux(operation string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%s is supported only on Linux", operation)
	}
	return nil
}

func inspectWeb(ctx context.Context, name string, includeDomains, includeConfig, includeVersion bool) (webResult, error) {
	if err := ensureLinux("web server inspection"); err != nil {
		return webResult{}, err
	}

	executor := ssh.NewLocalExecutor()
	var detector interface {
		Detect(context.Context, ssh.Executor) (bool, error)
		Discover(context.Context, ssh.Executor) ([]inspectors.Domain, error)
	}
	var running func(context.Context, ssh.Executor) (bool, error)
	command := name
	if name == "nginx" {
		instance := nginx.New()
		detector = instance
		running = instance.Running
	} else {
		instance := apache.New()
		detector = instance
		running = instance.Running
		command = "apachectl"
	}

	result := webResult{Server: name, Domains: []inspectors.Domain{}}
	detected, err := detector.Detect(ctx, executor)
	if err != nil {
		return result, fmt.Errorf("detect %s: %w", name, err)
	}
	result.Detected = detected
	if !detected {
		return result, nil
	}

	result.Running, err = running(ctx, executor)
	if err != nil {
		return result, fmt.Errorf("check %s status: %w", name, err)
	}
	if includeDomains || includeConfig {
		result.Domains, err = detector.Discover(ctx, executor)
		if err != nil {
			return result, fmt.Errorf("discover %s configuration: %w", name, err)
		}
		if includeConfig {
			seen := make(map[string]bool)
			for _, domain := range result.Domains {
				if domain.ConfigPath != "" && !seen[domain.ConfigPath] {
					seen[domain.ConfigPath] = true
					result.Configs = append(result.Configs, domain.ConfigPath)
				}
			}
		}
	}
	if includeVersion {
		commands := []string{command + " -v 2>&1"}
		if name == "apache" {
			commands = append(commands, "httpd -v 2>&1")
		}
		output, err := runFirstCommand(ctx, executor, commands)
		if err != nil {
			return result, fmt.Errorf("read %s version: %w", name, err)
		}
		result.Version = strings.TrimSpace(output)
	}
	return result, nil
}

func runFirstCommand(ctx context.Context, executor ssh.Executor, commands []string) (string, error) {
	var lastErr error
	for _, command := range commands {
		output, err := executor.Run(ctx, command)
		if err == nil {
			return output, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		lastErr = err
	}
	return "", lastErr
}

func newWebListCommand() *cobra.Command {
	return newWebInspectionCommand("list", "List installed Nginx and Apache servers", "")
}

func newWebServerCommand(name string) *cobra.Command {
	return newWebInspectionCommand(name, "Inspect "+name+" installation and status", name)
}

func newWebStatusCommand() *cobra.Command {
	return newWebInspectionCommand("status", "Show whether Nginx and Apache are running", "")
}

func newWebInspectionCommand(use, short, name string) *cobra.Command {
	var config, versionFlag, domains bool
	cmd := newResultCommand(use, short, func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		names := []string{name}
		if name == "" {
			names = []string{"nginx", "apache"}
		}
		results := make([]webResult, 0, len(names))
		for _, serverName := range names {
			result, err := inspectWeb(ctx, serverName, domains, config, versionFlag)
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
		return textResult(results, strings.Join(lines, "\n")), nil
	})
	cmd.Flags().BoolVar(&config, "config", false, "include discovered configuration file paths")
	cmd.Flags().BoolVar(&versionFlag, "version", false, "include the installed server version")
	cmd.Flags().BoolVar(&domains, "domains", false, "include discovered virtual hosts")
	return cmd
}

func newDomainsListCommand() *cobra.Command {
	return newDomainsCommandForServer("list", "")
}

func newDomainsServerCommand(name string) *cobra.Command {
	return newDomainsCommandForServer(name, name)
}

func newDomainsCommandForServer(use, serverName string) *cobra.Command {
	var serverFilter, configPath, documentRoot string
	var port int
	var aliases bool
	cmd := newResultCommand(use, "List configured virtual hosts", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		names := []string{serverName}
		if serverName == "" {
			names = []string{"nginx", "apache"}
		}
		if serverFilter != "" {
			names = []string{serverFilter}
		}
		domains := make([]inspectors.Domain, 0)
		for _, name := range names {
			result, err := inspectWeb(ctx, name, true, false, false)
			if err != nil {
				return commandResult{}, err
			}
			if result.Detected {
				domains = append(domains, result.Domains...)
			}
		}
		filtered := make([]inspectors.Domain, 0, len(domains))
		for _, domain := range domains {
			if port != 0 && !containsPort(domain.Ports, port) {
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

func newDomainsDNSCommand() *cobra.Command {
	var domain, record string
	cmd := newResultCommand("dns", "Look up DNS records using the configured resolver", func(ctx context.Context, _ *cobra.Command) (commandResult, error) {
		result, err := dns.NewResolver().LookupRecord(ctx, record, domain)
		if err != nil {
			return commandResult{}, err
		}
		human := fmt.Sprintf("%s records for %s:\n%s", result.Type, result.Domain, displayList(result.Records))
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

func containsPort(ports []int, port int) bool {
	for _, current := range ports {
		if current == port {
			return true
		}
	}
	return false
}
