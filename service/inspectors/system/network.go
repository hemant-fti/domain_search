package system

import (
	"context"
	"net"
	"strings"

	gonet "github.com/shirou/gopsutil/v4/net"
)

func collectNetworkInfo(ctx context.Context) ([]string, []string, string) {
	ipv4 := []string{}
	ipv6 := []string{}
	mac := ""

	interfaces, err := gonet.InterfacesWithContext(ctx)
	if err != nil {
		return ipv4, ipv6, mac
	}

	seen := make(map[string]bool)

	for _, iface := range interfaces {
		if iface.HardwareAddr != "" && mac == "" {
			mac = iface.HardwareAddr
		}

		for _, addr := range iface.Addrs {
			ip, _, err := net.ParseCIDR(addr.Addr)
			if err != nil {
				parsed := net.ParseIP(strings.Split(addr.Addr, "/")[0])
				ip = parsed
			}

			if ip == nil {
				continue
			}

			value := ip.String()

			if ip.IsLoopback() || seen[value] {
				continue
			}

			seen[value] = true

			if ip.To4() != nil {
				ipv4 = append(ipv4, value)
			} else {
				ipv6 = append(ipv6, value)
			}
		}
	}

	return ipv4, ipv6, mac
}
