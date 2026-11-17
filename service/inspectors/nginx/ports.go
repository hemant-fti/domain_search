package nginx

import (
	"strconv"
	"strings"
)

func parsePorts(block string) []int {
	var ports []int
	seen := make(map[int]bool)

	for _, match := range listen.FindAllStringSubmatch(block, -1) {
		if len(match) < 2 {
			continue
		}

		fields := strings.Fields(match[1])
		if len(fields) == 0 {
			continue
		}

		address := fields[0]
		portText := address

		if strings.HasPrefix(address, "unix:") {
			continue
		}

		if strings.HasPrefix(address, "[") {
			end := strings.LastIndex(address, "]")
			if end == -1 || end+1 >= len(address) || address[end+1] != ':' {
				continue
			}
			portText = address[end+2:]
		} else if index := strings.LastIndex(address, ":"); index >= 0 {
			portText = address[index+1:]
		} else {
			portText = address
		}

		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || seen[port] {
			continue
		}

		seen[port] = true
		ports = append(ports, port)
	}

	return ports
}

func hasSSL(block string, ports []int) bool {
	for _, port := range ports {
		if port == 443 {
			return true
		}
	}

	for _, match := range listen.FindAllStringSubmatch(block, -1) {
		if len(match) > 1 {
			for _, field := range strings.Fields(match[1]) {
				if field == "ssl" {
					return true
				}
			}
		}
	}

	return false
}
