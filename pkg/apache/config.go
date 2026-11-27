package apache

import (
	"regexp"
	"strings"

	"domain-search/pkg/models"
)

var configMarker = regexp.MustCompile(
	`^# DOMAIN_SCOUT_CONFIG:(.*)$`,
)

func applyDocumentRoots(domains []models.Domain, text string) {
	roots := make(map[string]string)

	currentFile := ""
	inVHost := false

	var names []string
	root := ""

	flush := func() {
		for _, name := range names {
			roots[currentFile+"\x00"+name] = root
		}

		names = nil
		root = ""
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)

		if marker := configMarker.FindStringSubmatch(line); len(marker) > 1 {
			if inVHost {
				flush()
			}

			currentFile = strings.TrimSpace(marker[1])
			inVHost = false

			continue
		}

		// Remove comments.
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "<virtualhost ") {
			if inVHost {
				flush()
			}

			inVHost = true
			continue
		}

		if !inVHost {
			continue
		}

		if strings.HasPrefix(lower, "</virtualhost") {
			flush()
			inVHost = false
			continue
		}

		fields := strings.Fields(line)

		if len(fields) < 2 {
			continue
		}

		switch strings.ToLower(fields[0]) {
		case "servername":
			names = append(names, fields[1])

		case "serveralias":
			names = append(names, fields[1:]...)

		case "documentroot":
			root = strings.Trim(fields[1], `"'`)
		}
	}

	if inVHost {
		flush()
	}

	for i := range domains {
		key := domains[i].ConfigPath + "\x00" + domains[i].Name

		if value := roots[key]; value != "" {
			domains[i].Path = value
		}
	}
}
