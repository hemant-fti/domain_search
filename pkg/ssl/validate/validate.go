// Package validate checks X.509 certificates: expiry, hostname coverage,
// chain building and trust, and certificate/private-key pairing.
//
// All checks delegate to crypto/x509 and crypto/tls; nothing here implements
// cryptography.
package validate

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"domain-search/pkg/models"
	"domain-search/pkg/ssl/certificate"
)

// DefaultRenewalWindow is the remaining lifetime under which a certificate is
// reported as expiring. It matches the common ACME practice of renewing
// 30 days before expiry.
const DefaultRenewalWindow = 30 * 24 * time.Hour

// Expiry describes where a certificate is in its validity period.
type Expiry struct {
	Status        string // one of models.ExpiryStatus*
	DaysRemaining int    // whole days until NotAfter; negative once expired
}

// CheckExpiry classifies cert at time now. A certificate whose remaining
// lifetime is at most warnWithin is "expiring".
func CheckExpiry(cert *x509.Certificate, now time.Time, warnWithin time.Duration) Expiry {
	remaining := cert.NotAfter.Sub(now)
	days := int(remaining / (24 * time.Hour))

	switch {
	case now.Before(cert.NotBefore):
		return Expiry{Status: models.ExpiryStatusNotYetValid, DaysRemaining: days}
	case !now.Before(cert.NotAfter):
		return Expiry{Status: models.ExpiryStatusExpired, DaysRemaining: days}
	case remaining <= warnWithin:
		return Expiry{Status: models.ExpiryStatusExpiring, DaysRemaining: days}
	default:
		return Expiry{Status: models.ExpiryStatusValid, DaysRemaining: days}
	}
}

// Hostname reports whether cert is valid for host (SANs and wildcards,
// per crypto/x509 rules).
func Hostname(cert *x509.Certificate, host string) error {
	if err := cert.VerifyHostname(host); err != nil {
		return fmt.Errorf("certificate does not cover %q: %w", host, err)
	}
	return nil
}

// ErrMissingIntermediate means the leaf could not be chained to a trusted root
// with the intermediates supplied, typically because the server does not send
// its intermediate certificate.
var ErrMissingIntermediate = errors.New("certificate chain is incomplete: issuer not found")

// ChainOptions controls chain verification.
type ChainOptions struct {
	// Roots is the trust store. Nil means the system roots.
	Roots *x509.CertPool
	// DNSName, when set, is also verified against the leaf.
	DNSName string
	// At is the verification time. Zero means now.
	At time.Time
}

// Chain verifies that leaf chains to a trusted root through intermediates and
// returns the verified chains (each ordered leaf first).
func Chain(leaf *x509.Certificate, intermediates []*x509.Certificate, opts ChainOptions) ([][]*x509.Certificate, error) {
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: pool,
		DNSName:       opts.DNSName,
		CurrentTime:   opts.At,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) {
			return nil, fmt.Errorf("%w: %w", ErrMissingIntermediate, err)
		}
		return nil, fmt.Errorf("verify certificate chain: %w", err)
	}
	return chains, nil
}

// KeyPair reports whether the PEM certificate and PEM private key belong
// together.
func KeyPair(certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("certificate and private key do not match: %w", err)
	}
	return nil
}

// Report describes cert (see certificate.Describe) and adds its expiry status
// at time now using DefaultRenewalWindow.
func Report(cert *x509.Certificate, now time.Time) models.CertificateResult {
	result := certificate.Describe(cert)
	expiry := CheckExpiry(cert, now, DefaultRenewalWindow)
	result.ExpiryStatus = expiry.Status
	result.DaysRemaining = expiry.DaysRemaining
	return result
}
