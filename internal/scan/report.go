package scan

import (
	"context"
	"errors"
	"strings"
	"time"

	"domain-search/pkg/models"
	"domain-search/pkg/security"
)

// NewScanError builds a classified, redacted error event.
func NewScanError(eventType, component string, err error, timestamp time.Time) models.ScanError {
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	if component == "" {
		component = errorComponent(err)
	}

	details := ""
	if err != nil {
		details = security.RedactText(err.Error())
	}
	code, message := classifyError(err, component)

	return models.ScanError{
		Type:      eventType,
		Code:      code,
		Message:   message,
		Details:   details,
		Component: component,
		Timestamp: timestamp.UTC(),
	}
}

// WarningEvent turns a "component: detail" warning into an event.
func WarningEvent(warning string) models.ScanError {
	component, detail := splitWarning(warning)
	return NewScanError("warning", component, errors.New(detail), time.Now().UTC())
}

// FriendlyErrorMessage returns a short, non-technical description of err.
func FriendlyErrorMessage(err error, component string) string {
	_, message := classifyError(err, component)
	return message
}

func errorComponent(err error) string {
	if err == nil {
		return ""
	}

	detail := strings.ToLower(err.Error())
	for _, component := range []string{"nginx", "apache", "httpd", "iis", "dns"} {
		if strings.Contains(detail, component) ||
			(component == "dns" && (strings.Contains(detail, "lookup") || strings.Contains(detail, "no such host"))) {
			return component
		}
	}
	return ""
}

func splitWarning(warning string) (string, string) {
	component, detail, found := strings.Cut(warning, ":")
	if !found {
		return "", warning
	}

	component = strings.TrimSpace(component)
	detail = strings.TrimSpace(detail)
	if strings.HasPrefix(strings.ToLower(component), "system information") {
		component = "system"
	}
	for _, suffix := range []string{" information", " detection", " status", " scan"} {
		component = strings.TrimSuffix(component, suffix)
	}
	component = strings.ToLower(component)
	switch component {
	case "nginx", "apache", "httpd", "iis", "system", "dns", "network":
		return component, detail
	default:
		return "", warning
	}
}

func classifyError(err error, component string) (string, string) {
	detail := ""
	if err != nil {
		detail = strings.ToLower(err.Error())
	}
	component = strings.ToLower(component)
	combined := component + " " + detail

	switch {
	case strings.Contains(combined, "unsupported dns record type"):
		return "DNS_RECORD_UNSUPPORTED", "DNS lookup supports only A, AAAA, MX, NS, and TXT records."
	case strings.Contains(combined, "unsupported"), strings.Contains(combined, "supported only on"):
		return "UNSUPPORTED_OPERATION", "This command is not supported on the current operating system."
	case strings.Contains(combined, "systemd is unavailable"):
		return "SYSTEMD_UNAVAILABLE", "System service inspection requires systemd on this Linux host."
	case strings.Contains(combined, "dns"), strings.Contains(combined, "lookup"), strings.Contains(combined, "no such host"):
		return "DNS_LOOKUP_FAILED", "Could not verify the website's domain address."
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(combined, "timeout"), strings.Contains(combined, "timed out"), strings.Contains(combined, "deadline exceeded"):
		return "CHECK_TIMEOUT", "Some checks took too long and could not be completed."
	case strings.Contains(combined, "network is unreachable"), strings.Contains(combined, "network unreachable"), strings.Contains(combined, "no route to host"):
		return "NETWORK_UNREACHABLE", "Could not connect to the network to complete some checks."
	case strings.Contains(combined, "metrics were unavailable"), strings.Contains(combined, "information unavailable"):
		return "SYSTEM_INFO_UNAVAILABLE", "Some system information could not be collected."
	case strings.Contains(combined, "permission denied"), strings.Contains(combined, "operation not permitted"), strings.Contains(combined, "access is denied"):
		return configAccessError(component)
	case strings.Contains(combined, "syntax"), strings.Contains(combined, "unexpected token"), strings.Contains(combined, "configuration test failed"):
		return "CONFIG_SYNTAX_INVALID", "Some web server configuration files contain errors."
	case strings.Contains(combined, "not found"), strings.Contains(combined, "no such file"), strings.Contains(combined, "does not exist"):
		return "CONFIG_FILE_NOT_FOUND", "Some website configuration files could not be found."
	case strings.Contains(combined, "nginx"):
		return "NGINX_CONFIG_FAILED", "Could not retrieve the Nginx configuration."
	case strings.Contains(combined, "apache"), strings.Contains(combined, "httpd"):
		return "APACHE_CONFIG_FAILED", "Could not retrieve the Apache configuration."
	default:
		return "CHECK_FAILED", "Some checks could not be completed."
	}
}

func configAccessError(component string) (string, string) {
	switch component {
	case "nginx":
		return "NGINX_CONFIG_ACCESS_FAILED", "Could not access some web server configuration files."
	case "apache", "httpd":
		return "APACHE_CONFIG_ACCESS_FAILED", "Could not access some web server configuration files."
	default:
		return "CONFIG_ACCESS_FAILED", "Could not access some web server configuration files."
	}
}
