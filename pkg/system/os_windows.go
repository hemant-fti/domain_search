//go:build windows

package system

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func OperatingSystem() (string, error) {
	version := windows.RtlGetVersion()
	if version == nil {
		return "Microsoft Windows", nil
	}

	return fmt.Sprintf(
		"Microsoft Windows %d.%d (Build %d)",
		version.MajorVersion,
		version.MinorVersion,
		version.BuildNumber,
	), nil
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
