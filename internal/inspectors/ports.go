package inspectors

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var listen = regexp.MustCompile(`(?m)^[ \t]*listen[ \t]+([^;]+);`)

func ParsePorts(block string) []int {
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

	sort.Ints(ports)
	return ports
}
