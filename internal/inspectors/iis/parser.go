package iis

import (
	"domain-search/models"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func ParseWithStatuses(config string, configPath string, statuses map[string]string) ([]models.Domain, error) {
	var configuration models.IISConfiguration

	if err := xml.Unmarshal([]byte(config), &configuration); err != nil {
		return nil, err
	}

	var domains []models.Domain

	for _, site := range configuration.SystemApplicationHost.Sites.Sites {
		var hosts []string
		var bindings []models.Binding
		var ports []int

		seenHosts := make(map[string]bool)
		seenPorts := make(map[int]bool)
		seenBindings := make(map[string]bool)

		var sslCertificate string

		for _, binding := range site.Bindings.Bindings {
			ip, port, hostname, valid := parseBindingInformation(
				binding.BindingInformation,
			)

			if !valid {
				continue
			}

			protocol := strings.ToLower(strings.TrimSpace(binding.Protocol))

			if protocol == "" {
				continue
			}

			hostname = strings.TrimSpace(hostname)

			// Build structured IIS binding.
			structuredBinding := resolveBinding(
				protocol,
				ip,
				port,
				hostname,
			)

			// Prevent duplicate bindings.
			key := fmt.Sprintf(
				"%s|%s|%d|%s",
				protocol,
				ip,
				port,
				strings.ToLower(hostname),
			)

			if !seenBindings[key] {
				bindings = append(bindings, structuredBinding)
				seenBindings[key] = true
			}

			// Collect actual website hostnames.
			if hostname != "" && hostname != "*" {
				hostKey := strings.ToLower(hostname)

				if !seenHosts[hostKey] {
					hosts = append(hosts, hostname)
					seenHosts[hostKey] = true
				}
			}

			// Collect unique ports.
			if !seenPorts[port] {
				ports = append(ports, port)
				seenPorts[port] = true
			}

			// Extract HTTPS certificate.
			if strings.EqualFold(protocol, "https") &&
				binding.CertificateHash != "" {
				sslCertificate = normalizeCertificateHash(
					binding.CertificateHash,
				)
			}
		}

		// Ignore websites without valid bindings.
		if len(bindings) == 0 {
			continue
		}

		documentRoot := expandWindowsPath(
			extractDocumentRoot(site),
		)

		proxyTarget := extractProxyTarget(config, site.Name)

		if sslCertificate == "" {
			sslCertificate = resolveSSLCertificate(site)
		}

		status := statuses[site.Name]
		if status == "" {
			status = "Unknown"
		}

		// First hostname becomes primary hostname.
		hostname := ""
		if len(hosts) > 0 {
			hostname = hosts[0]
		}

		// Remaining hostnames become aliases.
		var aliases []string
		if len(hosts) > 1 {
			aliases = append(aliases, hosts[1:]...)
		}

		domain := models.Domain{
			ID:          site.ID,
			Name:        hostname,
			WebsiteName: site.Name,
			Status:      status,
			Bindings:    bindings,
			Path:        documentRoot,
			Hostname:    hostname,

			Source:         "iis",
			ConfigPath:     configPath,
			ProxyTarget:    proxyTarget,
			SSLCertificate: sslCertificate,
			Aliases:        aliases,
			Ports:          ports,
		}

		domains = append(domains, domain)
	}

	return domains, nil
}

// Extract root application physical path.
func extractDocumentRoot(site models.IISSite) string {
	for _, app := range site.Applications {
		if app.Path != "/" {
			continue
		}

		for _, directory := range app.VirtualDirectories {
			if directory.Path == "/" {
				return expandWindowsPath(
					directory.PhysicalPath,
				)
			}
		}
	}

	return ""
}

// Extract reverse proxy target from URL Rewrite rules.

func extractProxyTarget(config string, siteName string) string {
	var configuration models.IISConfiguration

	if err := xml.Unmarshal([]byte(config), &configuration); err != nil {
		return ""
	}

	// First check site-specific configuration.
	for _, location := range configuration.Locations {
		if !strings.EqualFold(location.Path, siteName) {
			continue
		}

		if target := findProxyTarget(location.WebServer.Rewrite); target != "" {
			return target
		}
	}

	// Then check global IIS rewrite configuration.
	return findProxyTarget(configuration.SystemWebServer.Rewrite)
}

func findProxyTarget(rewrite models.IISRewrite) string {
	for _, rule := range rewrite.Rules {
		if strings.EqualFold(rule.Enabled, "false") {
			continue
		}

		if !strings.EqualFold(rule.Action.Type, "Rewrite") {
			continue
		}

		target := strings.TrimSpace(rule.Action.URL)

		lower := strings.ToLower(target)

		if strings.HasPrefix(lower, "http://") ||
			strings.HasPrefix(lower, "https://") {
			return target
		}
	}

	return ""
}

// Parse IIS binding information.
//
// Examples:
// *:80:example.com
// 127.0.0.1:443:example.com
// *:443:www.example.com

func parseBindingInformation(value string) (ip string, port int, hostname string, valid bool) {
	parts := strings.SplitN(value, ":", 3)

	if len(parts) != 3 {
		return "", 0, "", false
	}

	parsedPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return "", 0, "", false
	}

	ip = strings.TrimSpace(parts[0])
	hostname = strings.TrimSpace(parts[2])

	if ip == "" {
		ip = "*"
	}

	return ip, parsedPort, hostname, true
}

func normalizeCertificateHash(hash string) string {
	hash = strings.TrimSpace(hash)
	hash = strings.ReplaceAll(hash, " ", "")
	hash = strings.ReplaceAll(hash, ":", "")

	return strings.ToUpper(hash)
}

func resolveBinding(protocol, ip string, port int, hostname string) models.Binding {
	ip = strings.TrimSpace(ip)

	binding := models.Binding{
		Protocol: protocol,
		IP:       ip,
		Port:     port,
		Hostname: hostname,
	}

	if isWildcardIP(ip) {
		binding.ResolvedIPs = detectLocalIPs()
		return binding
	}

	// Explicitly assigned IP: show only that IP.
	if parsed := net.ParseIP(ip); parsed != nil {
		binding.ResolvedIPs = []string{parsed.String()}
	}

	return binding
}

// Expand Windows environment variables such as %SystemDrive%.
func expandWindowsPath(value string) string {
	return strings.ReplaceAll(value, "%SystemDrive%", os.Getenv("SystemDrive"))
}
