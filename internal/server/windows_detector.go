//go:build windows

package server

import (
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/windows"
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

	out.OperatingSystem = windowsOSName()

	// Kernel version
	if err := ctx.Err(); err != nil {
		return out, err
	}

	out.Kernel = windowsKernelVersion()

	// Primary IP address
	if err := ctx.Err(); err != nil {
		return out, err
	}

	out.PrimaryIP, err = primaryWindowsIP(ctx)
	if err != nil && ctx.Err() != nil {
		return out, ctx.Err()
	}

	return out, nil
}

func windowsOSName() string {
	version := windows.RtlGetVersion()

	if version == nil {
		return "Microsoft Windows"
	}

	return fmt.Sprintf(
		"Microsoft Windows %d.%d (Build %d)",
		version.MajorVersion,
		version.MinorVersion,
		version.BuildNumber,
	)
}

func windowsKernelVersion() string {
	version := windows.RtlGetVersion()

	if version == nil {
		return ""
	}

	return fmt.Sprintf(
		"%d.%d.%d",
		version.MajorVersion,
		version.MinorVersion,
		version.BuildNumber,
	)
}

func primaryWindowsIP(ctx context.Context) (string, error) {
	dialer := net.Dialer{}

	conn, err := dialer.DialContext(ctx, "udp", "1.1.1.1:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", fmt.Errorf("unexpected local address type")
	}

	return addr.IP.String(), nil
}
