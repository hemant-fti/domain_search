package system

import (
	"context"
	"fmt"
	"net"
)

func collectNetworkInfo(ctx context.Context) ([]string, []string, string) {
	info, err := CollectNetworkInfo(ctx)
	if err != nil {
		return []string{}, []string{}, ""
	}
	return info.IPv4, info.IPv6, info.MAC
}

func CollectNetworkInfo(ctx context.Context) (NetworkInfo, error) {
	if err := ctx.Err(); err != nil {
		return NetworkInfo{}, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("collect network interfaces: %w", err)
	}
	ipv4, ipv6, mac := collectNetworkInterfaces(interfaces)
	return NetworkInfo{IPv4: ipv4, IPv6: ipv6, MAC: mac}, nil
}

func collectNetworkInterfaces(interfaces []net.Interface) ([]string, []string, string) {
	ipv4 := []string{}
	ipv6 := []string{}
	mac := ""
	seen := make(map[string]bool)
	for _, iface := range interfaces {
		hardwareAddress := iface.HardwareAddr.String()
		if hardwareAddress != "" && mac == "" {
			mac = hardwareAddress
		}

		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil {
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
