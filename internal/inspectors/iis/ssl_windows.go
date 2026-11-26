//go:build windows

package iis

import (
	"domain-search/models"
	"os/exec"
	"strings"
)

func resolveSSLCertificate(site models.IISSite) string {
	output, err := exec.Command(
		"netsh",
		"http",
		"show",
		"sslcert",
	).Output()

	if err != nil {
		return ""
	}

	bindings := parseHTTPSSLCertificates(string(output))

	for _, binding := range site.Bindings.Bindings {
		if !strings.EqualFold(binding.Protocol, "https") {
			continue
		}

		_, port, host, ok := parseIISBindingParts(
			binding.BindingInformation,
		)

		if !ok {
			continue
		}

		// Prefer SNI hostname matching.
		if host != "" {
			expected := strings.ToLower(host) + ":" + port

			for _, cert := range bindings {
				if strings.EqualFold(cert.HostnamePort, expected) {
					return normalizeCertificateHash(cert.Hash)
				}
			}
		}

		// Match IP and port.
		ip, _, _, _ := parseIISBindingParts(
			binding.BindingInformation,
		)

		expectedIP := normalizeIP(ip) + ":" + port

		for _, cert := range bindings {
			if strings.EqualFold(cert.IPPort, expectedIP) {
				return normalizeCertificateHash(cert.Hash)
			}
		}

		// Wildcard IP binding.
		if ip == "*" || ip == "" {
			for _, cert := range bindings {
				if cert.IPPort == "0.0.0.0:"+port ||
					cert.IPPort == "[::]:"+port {
					return normalizeCertificateHash(cert.Hash)
				}
			}
		}
	}

	return ""
}

func parseHTTPSSLCertificates(output string) []models.HTTPSSLCertificateBinding {
	var results []models.HTTPSSLCertificateBinding
	var current models.HTTPSSLCertificateBinding

	flush := func() {
		if current.Hash != "" {
			results = append(results, current)
		}
		current = models.HTTPSSLCertificateBinding{}
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)

		if line == "" {
			flush()
			continue
		}

		separator := strings.Index(line, " : ")
		if separator < 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(line[:separator]))
		value := strings.TrimSpace(line[separator+3:])

		switch key {
		case "ip:port":
			current.IPPort = value
		case "hostname:port":
			current.HostnamePort = value
		case "certificate hash":
			current.Hash = value
		case "certificate store name":
			current.StoreName = value
		}
	}

	flush()

	return results
}

func parseIISBindingParts(value string) (ip string, port string, host string, ok bool) {
	lastColon := strings.LastIndex(value, ":")
	if lastColon < 0 {
		return "", "", "", false
	}

	host = strings.TrimSpace(value[lastColon+1:])
	remaining := value[:lastColon]

	portColon := strings.LastIndex(remaining, ":")
	if portColon < 0 {
		return "", "", "", false
	}

	ip = strings.TrimSpace(remaining[:portColon])
	port = strings.TrimSpace(remaining[portColon+1:])

	if port == "" {
		return "", "", "", false
	}

	return ip, port, host, true
}

func normalizeIP(ip string) string {
	if strings.TrimSpace(ip) == "*" {
		return "0.0.0.0"
	}

	return strings.TrimSpace(ip)
}
