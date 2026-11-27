package nginx

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"domain-search/pkg/models"
	"domain-search/pkg/ssl/certificate"
	"domain-search/pkg/ssl/validate"
)

// LoadCertificates reads each domain's ssl_certificate file and attaches the
// leaf certificate's details to domain.Certificates. Each file is read once
// even when several server blocks share it.
//
// Paths that contain nginx variables (e.g. $ssl_server_name) are chosen at
// request time and are skipped. Unreadable files produce a record with
// Installed=false and are reported in the returned error.
func LoadCertificates(domains []models.Domain, now time.Time) error {
	type loaded struct {
		result models.CertificateResult
		err    error
	}
	cache := map[string]loaded{}
	var errs []error

	for i := range domains {
		d := &domains[i]
		path := strings.Trim(strings.TrimSpace(d.SSLCertificate), `"'`)
		if path == "" || strings.Contains(path, "$") || strings.HasPrefix(path, "data:") {
			continue
		}

		entry, ok := cache[path]
		if !ok {
			certs, err := certificate.LoadFile(path)
			if err != nil {
				entry.err = err
				errs = append(errs, fmt.Errorf("nginx certificate %s: %w", path, err))
			} else {
				entry.result = validate.Report(certs[0], now)
			}
			cache[path] = entry
		}

		r := entry.result
		if entry.err != nil {
			r = models.CertificateResult{SANs: []string{}, Error: entry.err.Error()}
		}
		r.FQDN = d.Name
		if slices.Contains(d.Ports, 443) {
			r.Port = 443
		}
		p := path
		r.Paths.Fullchain = &p
		d.Certificates = append(d.Certificates, r)
	}
	return errors.Join(errs...)
}
