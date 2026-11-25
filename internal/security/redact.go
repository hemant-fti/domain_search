package security

import (
	"regexp"
	"strings"
)

var (
	sensitiveFlag = regexp.MustCompile(
		`(?i)(password|passwd|token|secret|api[-_]?key|authorization|credential|private[-_]?key)`,
	)

	sensitiveText = regexp.MustCompile(
		`(?i)(password|passwd|token|secret|api[-_]?key|authorization|credential)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)`,
	)

	privateKeyPattern = regexp.MustCompile(
		`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`,
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

// RedactText removes sensitive values from text.
func RedactText(value string) string {
	value = privateKeyPattern.ReplaceAllString(
		value,
		"[REDACTED PRIVATE KEY]",
	)

	return sensitiveText.ReplaceAllString(
		value,
		"$1=[REDACTED]",
	)
}
