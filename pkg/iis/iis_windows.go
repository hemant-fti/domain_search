//go:build windows

package iis

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"domain-search/pkg/iis/config"
	"domain-search/pkg/iis/httpsys"
	"domain-search/pkg/models"
	"domain-search/pkg/ssl/store"
	"domain-search/pkg/ssl/validate"
	"domain-search/pkg/system"
)

// ErrUnsupported is never returned on Windows; it exists for API parity.
var ErrUnsupported = errors.New("IIS inspection is supported only on Windows")

// Detect reports whether IIS is installed: appcmd.exe exists, or the
// HKLM\SOFTWARE\Microsoft\InetStp InstallPath value is set.
func (*Inspector) Detect(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	windowsDir := os.Getenv("windir")
	if windowsDir == "" {
		windowsDir = `C:\Windows`
	}
	if _, err := os.Stat(filepath.Join(windowsDir, "System32", "inetsrv", "appcmd.exe")); err == nil {
		return true, nil
	}
	return system.RegistryValueExists(`SOFTWARE\Microsoft\InetStp`, "InstallPath")
}

// Running reports whether the World Wide Web Publishing Service (W3SVC) runs.
func (*Inspector) Running(ctx context.Context) (bool, error) {
	running, err := system.ServiceRunning(ctx, "W3SVC")
	if errors.Is(err, system.ErrServiceNotInstalled) {
		return false, nil
	}
	return running, err
}

// Discover returns one domain record per IIS website, with the certificate
// HTTP.sys has bound to each HTTPS binding.
//
// Problems that leave the result usable (an unreadable site status, a binding
// without a certificate, a malformed binding) are returned as an error
// together with the domains. A nil domain slice means discovery failed.
func (*Inspector) Discover(ctx context.Context) ([]models.Domain, error) {
	path, err := config.Path()
	if err != nil {
		return nil, err
	}
	sites, parseErr := config.Load(path)
	if sites == nil && parseErr != nil {
		return nil, parseErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	statuses, statusErr := siteStatuses(ctx)
	if statusErr != nil {
		statusErr = fmt.Errorf("IIS site status unavailable: %w", statusErr)
	}

	certs, certErr := boundCertificates(ctx, sites, time.Now())

	localIPs, ipErr := system.LocalIPs()
	if ipErr != nil {
		ipErr = fmt.Errorf("IIS wildcard binding addresses: %w", ipErr)
	}

	domains := buildDomains(siteInput{
		configPath: path,
		sites:      sites,
		statuses:   statuses,
		certs:      certs,
		localIPs:   localIPs,
	})
	if domains == nil {
		domains = []models.Domain{}
	}
	return domains, errors.Join(parseErr, statusErr, certErr, ipErr)
}

// boundCertificates resolves the certificate for every distinct HTTPS
// endpoint. Endpoints that fail still get a record with Installed=false.
func boundCertificates(ctx context.Context, sites []config.Site, now time.Time) (map[bindingKey]models.CertificateResult, error) {
	order, endpoints := httpsEndpoints(sites)
	results := make(map[bindingKey]models.CertificateResult, len(order))
	if len(order) == 0 {
		return results, nil // nothing to look up: do not initialize HTTP.sys
	}

	session, err := httpsys.Open()
	if err != nil {
		return results, fmt.Errorf("IIS certificates: %w", err)
	}
	defer session.Close()

	var errs []error
	for _, k := range order {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		ep := endpoints[k]
		b := ep.binding

		cert, err := lookupCertificate(session, b)
		if err != nil {
			errs = append(errs, fmt.Errorf("IIS certificate for site %q %s:%d (%q): %w", ep.site, b.IP, b.Port, b.Host, err))
			results[k] = notInstalled(b, err)
			continue
		}

		r := validate.Report(cert, now)
		r.IP, r.FQDN, r.Port = b.IP, b.Host, b.Port
		results[k] = r
	}
	return results, errors.Join(errs...)
}

func lookupCertificate(session *httpsys.Session, b config.Binding) (*x509.Certificate, error) {
	bound, err := session.Lookup(b.IP, b.Port, b.Host, b.SSLFlags)
	if err != nil {
		return nil, err
	}
	return store.FindByThumbprint(bound.StoreName, bound.Thumbprint)
}
