//go:build !windows

package iis

func resolveSSLCertificate(_ IISSite) string {
	return ""
}
