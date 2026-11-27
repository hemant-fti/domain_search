//go:build linux

package apache

import (
	"context"
	"os/exec"

	"domain-search/pkg/models"
	"domain-search/pkg/system"
)

// Inspector discovers Apache virtual hosts on Linux.
type Inspector struct{}

// New returns an Apache inspector.
func New() *Inspector { return &Inspector{} }

// Name returns "apache".
func (*Inspector) Name() string { return "apache" }

// Detect reports whether apachectl or httpd is on PATH.
func (*Inspector) Detect(ctx context.Context) (bool, error) {
	for _, binary := range []string{"apachectl", "httpd"} {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if _, err := exec.LookPath(binary); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// Running reports whether an apache2 or httpd process is running.
func (*Inspector) Running(ctx context.Context) (bool, error) {
	return system.ProcessRunning(ctx, "apache2", "httpd")
}

// Discover returns the virtual hosts reported by `apachectl -S`, enriched
// with document roots. Unreadable virtual host files are reported in the
// returned error alongside the domains.
func (*Inspector) Discover(ctx context.Context) ([]models.Domain, error) {
	return discoverApache(ctx)
}
