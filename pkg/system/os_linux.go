//go:build linux

package system

import (
	"domain-search/models"
	"os"
	"runtime"
	"strings"
	"syscall"
)

func DetectOS() (models.OSInfo, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return models.OSInfo{}, err
	}

	values := make(map[string]string)

	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		values[strings.TrimSpace(key)] =
			strings.Trim(strings.TrimSpace(value), `"`)
	}

	name := values["NAME"]
	version := values["VERSION"]

	if name == "" {
		name = values["ID"]
	}

	if version == "" {
		version = values["VERSION_ID"]
	}

	// Remove the codename in parentheses.
	version = strings.TrimSpace(strings.SplitN(version, "(", 2)[0])

	return models.OSInfo{
		Name:         name,
		Family:       values["ID"],
		Version:      version,
		Architecture: runtime.GOARCH,
	}, nil
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
