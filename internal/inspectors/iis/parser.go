package iis

import (
	"domain-search/models"
	"encoding/xml"
	"strconv"
	"strings"
)

func Parse(config string, configPath string) ([]models.Domain, error) {
	var configuration models.IISConfiguration

	if err := xml.Unmarshal([]byte(config), &configuration); err != nil {
		return nil, err
	}

	var domains []models.Domain

	for _, site := range configuration.SystemApplicationHost.Sites.Sites {
		hosts := make([]string, 0)
		ports := make([]int, 0)

		seenHosts := make(map[string]bool)
		seenPorts := make(map[int]bool)

		var sslCertificate string

		// Extract bindings.
		for _, binding := range site.Bindings.Bindings {
			host, port, valid := parseBindingInformation(
				binding.BindingInformation,
			)

			if !valid {
				continue
			}

			if host != "" && host != "*" && !seenHosts[strings.ToLower(host)] {
				hosts = append(hosts, host)
				seenHosts[strings.ToLower(host)] = true
			}

			if !seenPorts[port] {
				ports = append(ports, port)
				seenPorts[port] = true
			}

			if strings.EqualFold(binding.Protocol, "https") &&
				binding.CertificateHash != "" {
				sslCertificate = normalizeCertificateHash(
					binding.CertificateHash,
				)
			}
		}

		if len(hosts) == 0 {
			continue
		}

		documentRoot := extractDocumentRoot(site)
		proxyTarget := extractProxyTarget(config, site.Name)

		// Resolve certificate from HTTP.sys if XML does not contain it.
		if sslCertificate == "" {
			sslCertificate = resolveSSLCertificate(site)
		}

		domain := models.Domain{
			Name:           hosts[0],
			Source:         "iis",
			ConfigPath:     configPath,
			Aliases:        append([]string{}, hosts[1:]...),
			Ports:          ports,
			DocumentRoot:   documentRoot,
			ProxyTarget:    proxyTarget,
			SSLCertificate: sslCertificate,
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
func parseBindingInformation(value string) (
	host string,
	port int,
	ok bool,
) {
	lastColon := strings.LastIndex(value, ":")
	if lastColon == -1 {
		return "", 0, false
	}

	host = strings.TrimSpace(value[lastColon+1:])

	remaining := value[:lastColon]

	portColon := strings.LastIndex(remaining, ":")
	if portColon == -1 {
		return "", 0, false
	}

	portValue := remaining[portColon+1:]

	port, err := strconv.Atoi(portValue)
	if err != nil || port <= 0 {
		return "", 0, false
	}

	return host, port, true
}

func normalizeCertificateHash(hash string) string {
	hash = strings.TrimSpace(hash)
	hash = strings.ReplaceAll(hash, " ", "")
	hash = strings.ReplaceAll(hash, ":", "")

	return strings.ToUpper(hash)
}
