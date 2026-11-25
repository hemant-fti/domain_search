//go:build !windows

package iis

import "domain-search/models"

func resolveSSLCertificate(_ models.IISSite) string {
	return ""
}
