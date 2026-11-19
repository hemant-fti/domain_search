package inspectors

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func DetectWebServer(ctx context.Context, service string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	var binaries []string

	switch strings.ToLower(service) {
	case "apache":
		binaries = []string{"apachectl", "httpd"}

	case "nginx":
		binaries = []string{"nginx"}

	default:
		return false, fmt.Errorf("unsupported web server: %s", service)
	}

	for _, binary := range binaries {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		if _, err := exec.LookPath(binary); err == nil {
			return true, nil
		}
	}

	return false, nil
}
