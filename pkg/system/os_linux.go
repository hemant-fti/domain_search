//go:build linux

package system

import (
	"os"
	"strings"
)

func OperatingSystem() (string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(key) == "PRETTY_NAME" {
			return strings.Trim(strings.TrimSpace(value), `"'`), nil
		}
	}

	return "", nil
}

func KernelVersion() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}
