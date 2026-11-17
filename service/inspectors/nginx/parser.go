package nginx

import (
	"bufio"
	"regexp"
	"strings"

	"domain-scout/service/inspectors"
)

var (
	serverStart = regexp.MustCompile(`(?m)^[ \t]*server[ \t]*\{`)

	serverName  = regexp.MustCompile(`(?m)^[ \t]*server_name[ \t]+([^;]+);`)
	root        = regexp.MustCompile(`(?m)^[ \t]*root[ \t]+([^;]+);`)
	proxy       = regexp.MustCompile(`(?m)^[ \t]*proxy_pass[ \t]+([^;]+);`)
	listen      = regexp.MustCompile(`(?m)^[ \t]*listen[ \t]+([^;]+);`)
	certificate = regexp.MustCompile(`(?m)^[ \t]*ssl_certificate[ \t]+([^;]+);`)
)

func Parse(config string) []inspectors.Domain {
	var domains []inspectors.Domain

	matches := serverStart.FindAllStringIndex(config, -1)

	for _, match := range matches {
		openBrace := strings.Index(config[match[0]:match[1]], "{") + match[0]

		closeBrace := findMatchingBrace(config, openBrace)
		if closeBrace == -1 {
			continue
		}

		block := config[openBrace+1 : closeBrace]

		startLine := strings.Count(config[:match[0]], "\n")
		configPath := configFileAtLine(config, startLine)

		names := serverName.FindStringSubmatch(block)
		if len(names) < 2 {
			continue
		}

		hosts := parseServerNames(names[1])
		if len(hosts) == 0 {
			continue
		}

		domain := inspectors.Domain{
			Name:       hosts[0],
			Source:     "nginx",
			ConfigPath: configPath,
			Aliases:    append([]string{}, hosts[1:]...),
			Ports:      parsePorts(block),
		}

		if len(domain.Ports) == 0 {
			domain.Ports = []int{80}
		}

		domain.SSL = hasSSL(block, domain.Ports)

		if match := root.FindStringSubmatch(block); len(match) > 1 {
			domain.DocumentRoot = strings.TrimSpace(match[1])
		}

		if match := proxy.FindStringSubmatch(block); len(match) > 1 {
			domain.ProxyTarget = strings.TrimSpace(match[1])
		}

		if match := certificate.FindStringSubmatch(block); len(match) > 1 {
			domain.SSLCertificate = strings.TrimSpace(match[1])
		}

		domains = append(domains, domain)
	}

	return domains
}

func parseServerNames(value string) []string {
	var hosts []string
	seen := make(map[string]bool)

	for _, name := range strings.Fields(value) {
		name = strings.TrimSpace(name)

		if name == "" || name == "_" || strings.HasPrefix(name, "~") {
			continue
		}

		if !seen[name] {
			hosts = append(hosts, name)
			seen[name] = true
		}
	}

	return hosts
}

// findMatchingBrace returns the closing brace for an opening brace.
// It ignores braces inside comments and quoted strings.
func findMatchingBrace(config string, open int) int {
	depth := 0
	var quote rune
	escaped := false
	comment := false

	for i := open; i < len(config); i++ {
		ch := rune(config[i])

		if comment {
			if ch == '\n' {
				comment = false
			}
			continue
		}

		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}

			if ch == '\\' {
				escaped = true
				continue
			}

			if ch == quote {
				quote = 0
			}
			continue
		}

		switch ch {
		case '#':
			comment = true
		case '\'', '"':
			quote = ch
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}

	return -1
}

func configFileAtLine(config string, targetLine int) string {
	scanner := bufio.NewScanner(strings.NewReader(config))
	currentFile := ""

	for lineNumber := 0; scanner.Scan(); lineNumber++ {
		if lineNumber > targetLine {
			break
		}

		line := scanner.Text()

		const prefix = "# configuration file "

		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, ":") {
			currentFile = strings.TrimSuffix(
				strings.TrimPrefix(line, prefix),
				":",
			)
		}
	}

	return currentFile
}
