//go:build linux

package system

import (
	"os"
	"strings"
	"syscall"
)

func OperatingSystem() (string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && key == "PRETTY_NAME" {
			return strings.Trim(strings.TrimSpace(value), `"'`), nil
		}
	}

	return "", nil
}

func KernelVersion() (string, error) {
	var uts syscall.Utsname

	if err := syscall.Uname(&uts); err != nil {
		return "", err
	}

	return CharsToString(uts.Release[:]), nil
}

func CharsToString(chars []int8) string {
	var result strings.Builder

	for _, c := range chars {
		if c == 0 {
			break
		}

		result.WriteByte(byte(c))
	}

	return result.String()
}
