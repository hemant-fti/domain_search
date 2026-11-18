package apache

import (
	"domain-search/internal/inspectors"
	"regexp"
	"strconv"
	"strings"
)

var (
	vhost = regexp.MustCompile(`(?i)port\s+(\d+)\s+namevhost\s+([^\s]+)\s+\((.+):\d+\)`)
	alias = regexp.MustCompile(`(?i)^\s*alias\s+([^\s]+)`)
)

func Parse(text string) []inspectors.Domain {
	var result []inspectors.Domain
	var current *inspectors.Domain

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")

		// Detect a new Apache VirtualHost.
		if match := vhost.FindStringSubmatch(line); len(match) == 4 {
			portNumber, err := strconv.Atoi(match[1])
			if err != nil || portNumber < 1 || portNumber > 65535 {
				current = nil
				continue
			}

			domain := inspectors.Domain{
				Name:       strings.TrimSpace(match[2]),
				Source:     "apache",
				ConfigPath: strings.TrimSpace(match[3]),
				Aliases:    []string{},
				Ports:      []int{portNumber},
			}

			// Avoid duplicate VirtualHost entries.
			var existing *inspectors.Domain

			for i := range result {
				if result[i].Name == domain.Name &&
					result[i].ConfigPath == domain.ConfigPath {
					existing = &result[i]
					break
				}
			}

			if existing != nil {
				current = existing

				if !containsPort(current.Ports, portNumber) {
					current.Ports = append(current.Ports, portNumber)
				}

				continue
			}

			result = append(result, domain)
			current = &result[len(result)-1]

			continue
		}

		if current == nil {
			continue
		}

		// Extract aliases belonging to the current VirtualHost.
		if match := alias.FindStringSubmatch(line); len(match) == 2 {
			hostname := strings.TrimSpace(match[1])

			if hostname != "" && !containsAlias(current.Aliases, hostname) {
				current.Aliases = append(current.Aliases, hostname)
			}
		}
	}

	return result
}

func containsAlias(aliases []string, hostname string) bool {
	for _, existing := range aliases {
		if strings.EqualFold(existing, hostname) {
			return true
		}
	}

	return false
}

func containsPort(ports []int, port int) bool {
	for _, existing := range ports {
		if existing == port {
			return true
		}
	}

	return false
}
