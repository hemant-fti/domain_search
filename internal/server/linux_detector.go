//go:build linux

package server

import (
	"context"
	"net"
	"os"
	"strings"
)

type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

func (d *Detector) Detect(ctx context.Context) (Info, error) {
	var out Info

	// Hostname
	if err := ctx.Err(); err != nil {
		return out, err
	}

	hostname, err := os.Hostname()
	if err == nil {
		out.Hostname = hostname
	}

	// Operating system information
	if err := ctx.Err(); err != nil {
		return out, err
	}

	osRelease, err := os.ReadFile("/etc/os-release")
	if err == nil {
		out.OperatingSystem = parsePrettyName(string(osRelease))
	}

	// Kernel version
	if err := ctx.Err(); err != nil {
		return out, err
	}

	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err == nil {
		out.Kernel = strings.TrimSpace(string(kernel))
	}

	// Primary IP address
	if err := ctx.Err(); err != nil {
		return out, err
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", "1.1.1.1:80")
	if err == nil {
		defer conn.Close()

		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			out.PrimaryIP = addr.IP.String()
		}
	}

	return out, nil
}

func parsePrettyName(data string) string {
	for _, line := range strings.Split(data, "\n") {
		key, value, found := strings.Cut(line, "=")

		if !found || strings.TrimSpace(key) != "PRETTY_NAME" {
			continue
		}

		value = strings.TrimSpace(value)

		return strings.Trim(value, `"'`)
	}

	return ""
}
