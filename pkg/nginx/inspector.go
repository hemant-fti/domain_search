//go:build linux

package nginx

import (
	"context"
	"os/exec"
	"time"

	"domain-search/pkg/models"
	"domain-search/pkg/system"
)

// Inspector discovers Nginx virtual hosts on Linux.
type Inspector struct{}

// New returns an Nginx inspector.
func New() *Inspector { return &Inspector{} }

// Name returns "nginx".
func (*Inspector) Name() string { return "nginx" }

// Detect reports whether the nginx executable is on PATH.
func (*Inspector) Detect(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err := exec.LookPath("nginx")
	return err == nil, nil
}

// Running reports whether an nginx process is running.
func (*Inspector) Running(ctx context.Context) (bool, error) {
	return system.ProcessRunning(ctx, "nginx")
}

// Discover returns the configured virtual hosts with their certificate
// files parsed. Certificate files that cannot be read are reported in the
// returned error alongside the domains.
func (*Inspector) Discover(ctx context.Context) ([]models.Domain, error) {
	domains, err := discoverNginx(ctx)
	if err != nil {
		return nil, err
	}
	if domains == nil {
		domains = []models.Domain{}
	}
	certErr := LoadCertificates(domains, time.Now())
	return domains, certErr
}
