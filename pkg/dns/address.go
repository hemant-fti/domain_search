package dns

import "net/netip"

func parseIP(value string) (netip.Addr, error) {
	return netip.ParseAddr(value)
}

func normalizeIP(address netip.Addr) netip.Addr {
	return address.Unmap()
}

func normalizeIPString(value string) (string, error) {
	address, err := parseIP(value)
	if err != nil {
		return "", err
	}

	return normalizeIP(address).String(), nil
}

func isValidIP(address netip.Addr) bool {
	return address.IsValid()
}
