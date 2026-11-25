//go:build windows

package system

import (
	"fmt"
	"runtime"

	"domain-search/models"

	"golang.org/x/sys/windows"
)

func DetectOS() (models.OSInfo, error) {
	version := windows.RtlGetVersion()
	if version == nil {
		return models.OSInfo{}, fmt.Errorf("unable to retrieve Windows version")
	}

	major := version.MajorVersion
	minor := version.MinorVersion
	build := version.BuildNumber

	name := "Microsoft Windows"
	family := "windows"
	osVersion := fmt.Sprintf("%d.%d.%d", major, minor, build)

	// Identify Windows edition.
	switch {
	case major == 10 && build >= 22000:
		name = "Windows 11"
	case major == 10:
		name = "Windows 10"
	case major == 6 && minor == 3:
		name = "Windows 8.1"
	case major == 6 && minor == 2:
		name = "Windows 8"
	case major == 6 && minor == 1:
		name = "Windows 7"
	case major == 6 && minor == 0:
		name = "Windows Vista"
	}

	return models.OSInfo{
		Name:         name,
		Family:       family,
		Version:      osVersion,
		Architecture: runtime.GOARCH,
	}, nil
}

func KernelVersion() (string, error) {
	version := windows.RtlGetVersion()
	if version == nil {
		return "", fmt.Errorf("unable to retrieve Windows version")
	}

	return fmt.Sprintf(
		"%d.%d.%d",
		version.MajorVersion,
		version.MinorVersion,
		version.BuildNumber,
	), nil
}
