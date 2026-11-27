// Package scan orchestrates a discovery run: it asks each platform inspector
// for its websites, verifies their DNS, collects system information and
// builds the report. It is application logic; the reusable pieces live in pkg/.
package scan

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"domain-search/pkg/dns"
	"domain-search/pkg/logger"
	"domain-search/pkg/models"
	"domain-search/pkg/system"
)

// Service runs inspections.
type Service struct {
	inspectors []Inspector
	resolver   *dns.Resolver
}

// NewService returns a Service using the given inspectors.
func NewService(list []Inspector) *Service {
	return &Service{inspectors: list, resolver: dns.NewResolver()}
}

// NewLocalService returns a Service with the inspectors for this platform.
func NewLocalService() *Service {
	return NewService(platformInspectors())
}

// InspectorNames returns the names of all registered inspectors.
func (s *Service) InspectorNames() []string {
	names := make([]string, 0, len(s.inspectors))
	for _, inspector := range s.inspectors {
		names = append(names, inspector.Name())
	}
	return names
}

func (s *Service) find(name string) Inspector {
	for _, candidate := range s.inspectors {
		if strings.EqualFold(candidate.Name(), name) {
			return candidate
		}
	}
	return nil
}

// Inspect inspects one web server by name. Problems that leave a usable
// partial result are reported in Inspection.Warnings, not as an error.
func (s *Service) Inspect(ctx context.Context, name string, options InspectOptions) (models.Inspection, error) {
	startedAt := time.Now()
	name = strings.ToLower(strings.TrimSpace(name))

	result := models.Inspection{Server: name, Domains: []models.Domain{}, Configs: []string{}}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	inspector := s.find(name)
	if inspector == nil {
		return result, fmt.Errorf("unsupported web server %q", name)
	}

	detected, err := inspector.Detect(ctx)
	if err != nil {
		return result, fmt.Errorf("detect %s: %w", name, err)
	}
	result.Detected = detected
	if !detected {
		logger.Debug("Web server not detected", "server", name)
		return result, nil
	}

	if status, ok := inspector.(statusInspector); ok {
		running, err := status.Running(ctx)
		if err != nil {
			return result, fmt.Errorf("check %s status: %w", name, err)
		}
		result.Running = running
	}

	if options.Domains || options.Config {
		domains, err := inspector.Discover(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			if domains == nil {
				return result, fmt.Errorf("discover %s configuration: %w", name, err)
			}
			logger.Warn("Web server discovery incomplete", "server", name, "error", err)
			result.Warnings = append(result.Warnings, name+" scan: "+err.Error())
		}
		if domains != nil {
			result.Domains = domains
		}
		if options.Config {
			result.Configs = configPaths(domains)
		}
	}

	if options.Version {
		version, err := serverVersion(ctx, name)
		if err != nil {
			return result, err
		}
		result.Version = version
	}

	logger.Debug("Web server inspection completed",
		"server", name, "detected", result.Detected, "running", result.Running,
		"domains", len(result.Domains), "duration", time.Since(startedAt).String())
	return result, nil
}

func configPaths(domains []models.Domain) []string {
	paths := []string{}
	seen := map[string]bool{}
	for _, d := range domains {
		if d.ConfigPath == "" || seen[d.ConfigPath] {
			continue
		}
		seen[d.ConfigPath] = true
		paths = append(paths, d.ConfigPath)
	}
	return paths
}

// Discover runs a full scan: host identity, system information, every
// detected web server and DNS verification of each discovered domain.
// Only cancellation and host identification failures abort the scan; every
// other problem becomes a warning.
func (s *Service) Discover(ctx context.Context) (models.Result, error) {
	startedAt := time.Now()
	result := newResult()

	info, hostWarnings, err := hostInfo(ctx)
	if err != nil {
		return result, err
	}
	result.Server = info
	appendWarnings(&result, hostWarnings...)

	systemInfo, warnings, collectErr := system.GetSysInfo(ctx)
	result.System = systemInfo
	appendWarnings(&result, warnings...)
	if collectErr != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		appendWarnings(&result, "system information: "+collectErr.Error())
	}

	var found []models.Domain
	for _, inspector := range s.inspectors {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		name := inspector.Name()

		detected, err := inspector.Detect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			appendWarnings(&result, name+" detection: "+err.Error())
			continue
		}
		if !detected {
			logger.Debug("Service not detected", "service", name)
			continue
		}
		result.DetectedServices = append(result.DetectedServices, name)

		serverInfo, domains, warnings, err := scanInspector(ctx, inspector)
		if err != nil {
			return result, err
		}
		logger.Info("Service discovery completed", "service", name,
			"running", serverInfo.Running, "domains", len(domains), "warnings", len(warnings))
		result.Servers = append(result.Servers, serverInfo)
		appendWarnings(&result, warnings...)
		found = append(found, domains...)
	}

	found = Normalize(found)

	for _, domain := range found {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		dnsResult, err := s.resolver.Verify(ctx, domain.Name, info.PrimaryIP)
		if err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			logger.Warn("DNS verification incomplete", "domain", domain.Name, "status", dnsResult.Status, "error", err)
		}
		result.Domains = append(result.Domains, models.DomainResult{Domain: domain, DNS: dnsResult})
	}
	result.TotalDomains = len(result.Domains)

	logger.Debug("Discovery completed",
		"detected_services", len(result.DetectedServices), "domains", result.TotalDomains,
		"warnings", len(result.Warnings), "duration", time.Since(startedAt).String())
	return result, nil
}

func appendWarnings(result *models.Result, warnings ...string) {
	for _, warning := range warnings {
		result.Warnings = append(result.Warnings, warning)
		result.ErrorEvents = append(result.ErrorEvents, WarningEvent(warning))
	}
}

func newResult() models.Result {
	return models.Result{
		ScanResponse: models.ScanResponse{
			Servers: []models.ServerInfo{},
			System:  models.SystemInfo{IPv4: []string{}, IPv6: []string{}},
		},
		Status:           "completed",
		ScannedAt:        time.Now().UTC(),
		DetectedServices: []string{},
		Domains:          []models.DomainResult{},
		Warnings:         []string{},
	}
}

// commandSpec is one executable invocation to try.
type commandSpec struct {
	name string
	args []string
}

// serverVersion returns the web server's own version string.
func serverVersion(ctx context.Context, server string) (string, error) {
	var commands []commandSpec
	switch runtime.GOOS + "/" + server {
	case "linux/nginx":
		commands = []commandSpec{{"nginx", []string{"-v"}}}
	case "linux/apache":
		commands = []commandSpec{{"apachectl", []string{"-v"}}, {"httpd", []string{"-v"}}}
	case "windows/nginx":
		commands = []commandSpec{{"nginx.exe", []string{"-v"}}}
	case "windows/apache":
		commands = []commandSpec{{"httpd.exe", []string{"-v"}}}
	default:
		return "", fmt.Errorf("version inspection is not supported for %q on %s", server, runtime.GOOS)
	}

	var lastErr error
	for _, c := range commands {
		output, err := exec.CommandContext(ctx, c.name, c.args...).CombinedOutput()
		if err == nil {
			return strings.TrimSpace(string(output)), nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		lastErr = fmt.Errorf("%s failed: %w; output: %s", c.name, err, strings.TrimSpace(string(output)))
	}
	return "", fmt.Errorf("read %s version: %w", server, lastErr)
}
