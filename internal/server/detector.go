package server

import (
	"context"
	"strconv"
	"strings"

	osExec "domain-search/internal/os"
)

type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

func (d *Detector) Detect(ctx context.Context, ex osExec.Executor) (Info, error) {
	var out Info

	// Hostname
	hostname, err := ex.Run(ctx, "hostname")
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
	} else {
		out.Hostname = strings.TrimSpace(hostname)
	}

	// Operating system information
	osRelease, err := ex.Run(ctx, "cat /etc/os-release")
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
	} else {
		out.OperatingSystem = parsePrettyName(osRelease)
	}

	// Kernel version
	kernel, err := ex.Run(ctx, "uname -r")
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
	} else {
		out.Kernel = strings.TrimSpace(kernel)
	}

	// Primary IP address
	route, err := ex.Run(ctx, "ip -o route get 1.1.1.1")
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
	} else {
		out.PrimaryIP = parsePrimaryIP(route)
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

		// Remove surrounding quotes and unescape quoted values.
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted
		}

		return strings.Trim(value, `"'`)
	}

	return ""
}

func parsePrimaryIP(output string) string {
	fields := strings.Fields(output)

	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "src" {
			return fields[i+1]
		}
	}

	return ""
}
