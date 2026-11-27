// Package iis discovers Microsoft IIS websites, their bindings and the TLS
// certificates bound to them.
//
// Sub-packages hold the independent pieces:
//   - iis/config:  applicationHost.config parsing (cross-platform)
//   - iis/httpsys: HTTP.sys certificate binding lookup (Windows)
//
// Certificates are read from the Windows store with ssl/store and described
// with ssl/certificate and ssl/validate.
package iis

// Inspector discovers IIS websites. It is usable only on Windows; on other
// platforms Detect reports false and Discover returns ErrUnsupported.
type Inspector struct{}

// New returns an IIS inspector.
func New() *Inspector { return &Inspector{} }

// Name returns "iis".
func (*Inspector) Name() string { return "iis" }
