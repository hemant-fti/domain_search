package iis

import (
	"net"
	"sort"
	"strings"
)

func isWildcardIP(ip string) bool {
	switch strings.TrimSpace(ip) {
	case "", "*", "0.0.0.0", "::", "[::]":
		return true
	default:
		return false
	}
}

// detectLocalIPs returns detected IPv4 and IPv6 addresses.
func detectLocalIPs() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})

	var ips []string

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP

			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			parsed := ip.String()

			if _, exists := seen[parsed]; exists {
				continue
			}

			seen[parsed] = struct{}{}
			ips = append(ips, parsed)
		}
	}

	sort.Strings(ips)

	return ips
}
