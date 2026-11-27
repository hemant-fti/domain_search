//go:build !windows

package store

import "crypto/x509"

// FindByThumbprint is not supported on this platform.
func FindByThumbprint(string, []byte) (*x509.Certificate, error) {
	return nil, ErrUnsupported
}
