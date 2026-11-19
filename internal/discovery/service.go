package discovery

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"domain-search/internal/dns"
	osExec "domain-search/internal/executor"
	"domain-search/internal/inspectors"
	"domain-search/internal/inspectors/apache"
	"domain-search/internal/inspectors/nginx"
	"domain-search/internal/inspectors/system"
	"domain-search/internal/server"
)

type Service struct {
	inspectors    []inspectors.Inspector
	serverService *server.Service
	verifier      *dns.Verifier
}

func NewService(list []inspectors.Inspector) *Service {
	return &Service{
		inspectors:    list,
		serverService: server.NewService(),
		verifier:      dns.NewVerifier(),
	}
}

func NewLocalService() *Service {
	return NewService([]inspectors.Inspector{
		nginx.New(),
		apache.New(),
	})
}

type InspectOptions struct {
	Domains bool
	Config  bool
	Version bool
}

func EnsureLinux(operation string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%s is supported only on Linux", operation)
	}
	return nil
}

func (s *Service) CollectSystem(ctx context.Context, _ osExec.Executor) (server.SystemInfo, []string, error) {
	info, warnings, err := system.CollectSystemInfo(ctx)
	if err != nil {
		return info, warnings, fmt.Errorf("collect system information: %w", err)
	}
	return info, warnings, nil
}

func (s *Service) Inspect(ctx context.Context, ex osExec.Executor, name string, options InspectOptions) (Inspection, error) {
	if err := EnsureLinux("web server inspection"); err != nil {
		return Inspection{}, err
	}

	result := Inspection{
		Server:  name,
		Domains: []inspectors.Domain{},
		Configs: []string{},
	}

	var inspector inspectors.Inspector
	for _, candidate := range s.inspectors {
		if candidate.Name() == name {
			inspector = candidate
			break
		}
	}
	if inspector == nil {
		return result, fmt.Errorf("unsupported web server %q", name)
	}

	detected, err := inspector.Detect(ctx, ex)
	if err != nil {
		return result, fmt.Errorf("detect %s: %w", name, err)
	}
	result.Detected = detected
	if !detected {
		return result, nil
	}

	if status, ok := inspector.(statusInspector); ok {
		running, err := status.Running(ctx, ex)
		if err != nil {
			return result, fmt.Errorf("check %s status: %w", name, err)
		}
		result.Running = running
	}

	if options.Domains || options.Config {
		domains, err := inspector.Discover(ctx, ex)
		if err != nil {
			return result, fmt.Errorf("discover %s configuration: %w", name, err)
		}
		result.Domains = domains
		if options.Config {
			seen := make(map[string]bool)
			for _, domain := range domains {
				if domain.ConfigPath != "" && !seen[domain.ConfigPath] {
					seen[domain.ConfigPath] = true
					result.Configs = append(result.Configs, domain.ConfigPath)
				}
			}
		}
	}

	if options.Version {
		command := name + " -v 2>&1"
		if name == "apache" {
			command = "apachectl -v 2>&1"
		}
		commands := []string{command}
		if name == "apache" {
			commands = append(commands, "httpd -v 2>&1")
		}
		output, err := runFirstCommand(ctx, ex, commands)
		if err != nil {
			return result, fmt.Errorf("read %s version: %w", name, err)
		}
		result.Version = strings.TrimSpace(output)
	}

	return result, nil
}

func (s *Service) DiscoverDomains(ctx context.Context, ex osExec.Executor, names []string) ([]inspectors.Domain, error) {
	var domains []inspectors.Domain
	for _, name := range names {
		result, err := s.Inspect(ctx, ex, name, InspectOptions{Domains: true})
		if err != nil {
			return nil, err
		}
		if result.Detected {
			domains = append(domains, result.Domains...)
		}
	}
	return domains, nil
}

func (s *Service) TestConfig(ctx context.Context, ex osExec.Executor, name string) (string, error) {
	if err := EnsureLinux("web server configuration inspection"); err != nil {
		return "", err
	}
	commands := []string{"nginx -t 2>&1"}
	if name == "apache" {
		commands = []string{"apachectl configtest 2>&1", "httpd -t 2>&1"}
	}
	output, err := runFirstCommand(ctx, ex, commands)
	if err != nil {
		return "", fmt.Errorf("test %s configuration: %w", name, err)
	}
	return strings.TrimSpace(output), nil
}

func runFirstCommand(ctx context.Context, ex osExec.Executor, commands []string) (string, error) {
	var lastErr error
	for _, command := range commands {
		output, err := ex.Run(ctx, command)
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

func (s *Service) Discover(
	ctx context.Context,
	ex osExec.Executor,
) (Result, error) {

	result := newResult()

	info, err := s.serverService.GetInfo(ctx, ex)
	if err != nil {
		return result, err
	}

	result.Server = info

	var found []inspectors.Domain

	systemInfo, warnings, collectErr := system.CollectSystemInfo(ctx)
	result.System = systemInfo
	appendWarnings(&result, warnings)
	if collectErr != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		appendWarnings(&result, []string{
			"system information: " + collectErr.Error(),
		})
	}

	for _, inspector := range s.inspectors {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		// Detect installed service.
		detected, detectErr := inspector.Detect(ctx, ex)

		if detectErr != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}

			appendWarnings(&result, []string{
				inspector.Name() + " detection: " + detectErr.Error(),
			})

			continue
		}

		if !detected {
			continue
		}

		result.DetectedServices = append(
			result.DetectedServices,
			inspector.Name(),
		)

		// System inspector collects information but has no domains.
		if inspector.Name() == "system" {
			continue
		}

		serverInfo, domains, warnings, err := scanInspector(
			ctx,
			inspector,
			ex,
		)

		if err != nil {
			return result, err
		}

		result.Servers = append(result.Servers, serverInfo)
		appendWarnings(&result, warnings)

		found = append(found, domains...)
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	// Merge duplicate domains.
	found = Normalize(found)

	// Verify DNS records.
	for _, domain := range found {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		domainResult := DomainResult{
			Domain: domain,
			DNS: s.verifier.Verify(
				ctx,
				domain.Name,
				info.PrimaryIP,
			),
		}

		if err := ctx.Err(); err != nil {
			return result, err
		}

		result.Domains = append(result.Domains, domainResult)
	}

	result.TotalDomains = len(result.Domains)

	return result, nil
}

func appendWarnings(result *Result, warnings []string) {
	for _, warning := range warnings {
		result.Warnings = append(result.Warnings, warning)
		result.ErrorEvents = append(result.ErrorEvents, WarningEvent(warning))
	}
}

func newResult() Result {
	return Result{
		ScanResponse: ScanResponse{
			Servers: []ServerInfo{},
			System: SystemInfo{
				IPv4: []string{},
				IPv6: []string{},
			},
		},
		Status:           "completed",
		ScannedAt:        time.Now().UTC(),
		DetectedServices: []string{},
		Domains:          []DomainResult{},
		Warnings:         []string{},
	}
}
