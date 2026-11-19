package discovery

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"domain-search/internal/dns"
	"domain-search/internal/inspectors"
	"domain-search/internal/inspectors/apache"
	"domain-search/internal/inspectors/nginx"
	"domain-search/internal/inspectors/system"
	"domain-search/internal/logger"
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

func (s *Service) CollectSystem(ctx context.Context) (server.SystemInfo, []string, error) {
	startedAt := time.Now()

	logger.Debug("Collecting system information")

	info, warnings, err := system.CollectSystemInfo(ctx)
	if err != nil {
		logger.Debug("System information collection failed",
			"error", err,
			"duration", time.Since(startedAt).String(),
		)
		return info, warnings, fmt.Errorf("collect system information: %w", err)
	}

	logger.Debug("System information collection completed",
		"hostname", info.Hostname,
		"warnings", len(warnings),
		"duration", time.Since(startedAt).String(),
	)

	return info, warnings, nil
}

func (s *Service) Inspect(ctx context.Context, name string, options InspectOptions) (Inspection, error) {
	startedAt := time.Now()

	logger.Debug("Web server inspection started", "server", name)

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

	detected, err := inspector.Detect(ctx)
	if err != nil {
		logger.Debug("Web server detection failed",
			"server", name,
			"error", err,
		)
		return result, fmt.Errorf("detect %s: %w", name, err)
	}

	result.Detected = detected

	if !detected {
		logger.Debug("Web server not detected",
			"server", name,
			"duration", time.Since(startedAt).String(),
		)
		return result, nil
	}

	logger.Debug("Web server detected", "server", name)

	if status, ok := inspector.(statusInspector); ok {
		running, err := status.Running(ctx)
		if err != nil {
			logger.Debug("Web server status inspection failed",
				"server", name,
				"error", err,
			)
			return result, fmt.Errorf("check %s status: %w", name, err)
		}

		result.Running = running
	}

	if options.Domains || options.Config {
		logger.Debug("Discovering web server configuration",
			"server", name,
		)

		domains, err := inspector.Discover(ctx)
		if err != nil {
			logger.Debug("Web server configuration discovery failed",
				"server", name,
				"error", err,
			)
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
		var commands []commandSpec

		switch name {
		case "nginx":
			commands = []commandSpec{
				{name: "nginx", args: []string{"-v"}},
			}

		case "apache":
			commands = []commandSpec{
				{name: "apachectl", args: []string{"-v"}},
				{name: "httpd", args: []string{"-v"}},
			}
		}

		output, err := runFirstCommand(ctx, commands)
		if err != nil {
			return result, fmt.Errorf("read %s version: %w", name, err)
		}

		result.Version = strings.TrimSpace(output)
	}

	logger.Debug("Web server inspection completed",
		"server", name,
		"detected", result.Detected,
		"running", result.Running,
		"domains", len(result.Domains),
		"duration", time.Since(startedAt).String(),
	)

	return result, nil
}

func (s *Service) DiscoverDomains(ctx context.Context, names []string) ([]inspectors.Domain, error) {
	startedAt := time.Now()

	logger.Debug("Domain discovery started", "servers", names)

	var domains []inspectors.Domain

	for _, name := range names {
		result, err := s.Inspect(ctx, name, InspectOptions{
			Domains: true,
		})
		if err != nil {
			return nil, err
		}

		if result.Detected {
			domains = append(domains, result.Domains...)
		}
	}

	logger.Debug("Domain discovery completed",
		"domains", len(domains),
		"duration", time.Since(startedAt).String(),
	)

	return domains, nil
}

func (s *Service) TestConfig(ctx context.Context, name string) (string, error) {
	startedAt := time.Now()

	logger.Debug("Web server configuration test started",
		"server", name,
	)

	if err := EnsureLinux("web server configuration inspection"); err != nil {
		return "", err
	}

	var commands []commandSpec

	switch name {
	case "nginx":
		commands = []commandSpec{
			{name: "nginx", args: []string{"-t"}},
		}

	case "apache":
		commands = []commandSpec{
			{name: "apachectl", args: []string{"configtest"}},
			{name: "httpd", args: []string{"-t"}},
		}

	default:
		return "", fmt.Errorf("unsupported web server: %s", name)
	}

	output, err := runFirstCommand(ctx, commands)
	if err != nil {
		logger.Debug("Web server configuration test failed",
			"server", name,
			"error", err,
		)
		return output, fmt.Errorf("test %s configuration: %w", name, err)
	}

	logger.Debug("Web server configuration test completed",
		"server", name,
		"duration", time.Since(startedAt).String(),
	)

	return strings.TrimSpace(output), nil
}

type commandSpec struct {
	name string
	args []string
}

func runFirstCommand(ctx context.Context, commands []commandSpec) (string, error) {
	var lastErr error

	for _, command := range commands {
		if err := ctx.Err(); err != nil {
			return "", err
		}

		cmd := exec.CommandContext(ctx, command.name, command.args...)

		output, err := cmd.CombinedOutput()

		if err == nil {
			return string(output), nil
		}

		if ctx.Err() != nil {
			return string(output), ctx.Err()
		}

		lastErr = fmt.Errorf(
			"%s failed: %w; output: %s",
			command.name,
			err,
			strings.TrimSpace(string(output)),
		)
	}

	if lastErr == nil {
		return "", fmt.Errorf("no commands provided")
	}

	return "", lastErr
}

func (s *Service) Discover(
	ctx context.Context,
) (Result, error) {
	startedAt := time.Now()

	logger.Debug("Discovery lifecycle started")

	result := newResult()

	info, err := s.serverService.GetInfo(ctx)
	if err != nil {
		logger.Debug("Server information discovery failed", "error", err)
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

		logger.Debug("System information collection produced an error",
			"error", collectErr,
		)

		appendWarnings(&result, []string{
			"system information: " + collectErr.Error(),
		})
	}

	for _, inspector := range s.inspectors {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		name := inspector.Name()

		logger.Debug("Detecting installed service", "service", name)

		detected, detectErr := inspector.Detect(ctx)

		if detectErr != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}

			logger.Debug("Service detection failed",
				"service", name,
				"error", detectErr,
			)

			appendWarnings(&result, []string{
				name + " detection: " + detectErr.Error(),
			})

			continue
		}

		if !detected {
			logger.Debug("Service not detected", "service", name)
			continue
		}

		logger.Debug("Service detected", "service", name)

		result.DetectedServices = append(
			result.DetectedServices,
			name,
		)

		if name == "system" {
			continue
		}

		serverInfo, domains, warnings, err := scanInspector(
			ctx,
			inspector,
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

	logger.Debug("Normalizing discovered domains",
		"domains_before_normalization", len(found),
	)

	found = Normalize(found)

	logger.Debug("Domain normalization completed",
		"unique_domains", len(found),
	)

	for _, domain := range found {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		logger.Debug("Verifying domain DNS",
			"domain", domain.Name,
		)

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

	logger.Debug("Discovery lifecycle completed",
		"detected_services", len(result.DetectedServices),
		"domains", result.TotalDomains,
		"warnings", len(result.Warnings),
		"duration", time.Since(startedAt).String(),
	)

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
