package apache

import (
	"strings"
)

func shellPaths(paths []string) string {
	quoted := make([]string, 0, len(paths))

	for _, path := range paths {
		quoted = append(quoted, shellQuote(path))
	}

	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
