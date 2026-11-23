//go:build windows

package system

import (
	"os"
	"path/filepath"
	"strings"
)

func systemDiskPath() string {
	drive := strings.TrimSpace(os.Getenv("SystemDrive"))

	if drive == "" {
		drive = "C:"
	}

	return filepath.Clean(drive + `\`)
}
