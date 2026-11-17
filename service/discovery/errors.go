package discovery

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
)

type ScanError struct {
	Type      string    `json:"type"`
	Code      string    `json:"code"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	Component string    `json:"component,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

var (
	secretAssignmentPattern  = regexp.MustCompile(`(?im)(["']?\b(password|passwd|token|secret|api[_-]?key)["']?\s*(?:[:=]\s*|\bis\s+))[^\r\n,;]*`)
	secretEnvironmentPattern = regexp.MustCompile(`(?im)(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|PRIVATE_KEY|API_KEY)[A-Z0-9_]*\s*=\s*)[^\r\n,;]*`)
	urlPasswordPattern       = regexp.MustCompile(`(?i)(://[^:/@\s]+:)[^@\s]+(@)`)
	privateKeyPattern        = regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
)

func NewScanError(eventType, component string, err error, timestamp time.Time) ScanError {
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	if component == "" {
		component = errorComponent(err)
	}

	details := ""
	if err != nil {
		details = redactSensitiveDetails(err.Error())
	}
	code, message := classifyError(err, component)

	return ScanError{
		Type:      eventType,
		Code:      code,
		Message:   message,
		Details:   details,
		Component: component,
		Timestamp: timestamp.UTC(),
	}
}

func WarningEvent(warning string) ScanError {
	component, detail := splitWarning(warning)
	return NewScanError("warning", component, errors.New(detail), time.Now().UTC())
}

func FriendlyErrorMessage(err error, component string) string {
	_, message := classifyError(err, component)
	return message
}

func errorComponent(err error) string {
	if err == nil {
		return ""
	}

	detail := strings.ToLower(err.Error())
	for _, component := range []string{"nginx", "apache", "httpd", "dns"} {
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
	case "nginx", "apache", "httpd", "system", "dns":
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

func redactSensitiveDetails(details string) string {
	details = privateKeyPattern.ReplaceAllString(details, "[REDACTED PRIVATE KEY]")
	details = secretAssignmentPattern.ReplaceAllString(details, "$1[REDACTED]")
	details = secretEnvironmentPattern.ReplaceAllString(details, "$1[REDACTED]")
	return urlPasswordPattern.ReplaceAllString(details, "$1[REDACTED]$2")
}
