// Package security redacts secrets from command arguments and text before
// they are logged or displayed.
package security

import (
	"regexp"
	"strings"
)

var (
	sensitiveFlag = regexp.MustCompile(
		`(?i)(password|passwd|token|secret|api[-_]?key|authorization|credential|private[-_]?key)`,
	)

	// key=value, key: value, "key":"value" and "key is value" forms.
	secretAssignment = regexp.MustCompile(
		`(?im)(["']?\b(password|passwd|token|secret|api[_-]?key|authorization|credentials?)["']?\s*(?:[:=]\s*|\bis\s+))[^\r\n,;]*`,
	)

	// Environment-style assignments such as DB_PASSWORD=...
	secretEnvironment = regexp.MustCompile(
		`(?im)(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|PRIVATE_KEY|API_KEY)[A-Z0-9_]*\s*=\s*)[^\r\n,;]*`,
	)

	// scheme://user:password@host
	urlPassword = regexp.MustCompile(`(?i)(://[^:/@\s]+:)[^@\s]+(@)`)

	privateKey = regexp.MustCompile(
		`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`,
	)
)

// RedactArgs removes sensitive values from command arguments.
func RedactArgs(args []string) []string {
	result := make([]string, len(args))

	redactNext := false

	for i, arg := range args {
		if redactNext {
			result[i] = "[REDACTED]"
			redactNext = false
			continue
		}

		if strings.HasPrefix(arg, "--") {
			parts := strings.SplitN(
				strings.TrimPrefix(arg, "--"),
				"=",
				2,
			)

			if sensitiveFlag.MatchString(parts[0]) {
				if len(parts) == 2 {
					result[i] = "--" + parts[0] + "=[REDACTED]"
				} else {
					result[i] = arg
					redactNext = true
				}

				continue
			}
		}

		result[i] = arg
	}

	return result
}

// RedactText removes secrets from free text such as error messages while
// keeping the surrounding detail: the key and separator stay, the value
// becomes [REDACTED].
func RedactText(value string) string {
	value = privateKey.ReplaceAllString(value, "[REDACTED PRIVATE KEY]")
	value = secretAssignment.ReplaceAllString(value, "$1[REDACTED]")
	value = secretEnvironment.ReplaceAllString(value, "$1[REDACTED]")
	return urlPassword.ReplaceAllString(value, "$1[REDACTED]$2")
}
