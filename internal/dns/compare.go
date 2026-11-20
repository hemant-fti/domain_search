package dns

import "net/netip"

func matchesServerIP(ips []string, serverIP string) bool {
	serverAddr, err := netip.ParseAddr(serverIP)
	if err != nil {
		return false
	}

	serverAddr = serverAddr.Unmap()

	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}

		if addr.Unmap() == serverAddr {
			return true
		}
	}

	return false
}
