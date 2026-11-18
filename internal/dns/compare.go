package dns

import "net"

func matchesServerIP(resolvedIPs []string, serverIP string) bool {
	target := net.ParseIP(serverIP)

	if target == nil {
		return false
	}

	for _, value := range resolvedIPs {
		resolved := net.ParseIP(value)

		if resolved != nil && resolved.Equal(target) {
			return true
		}
	}

	return false
}
