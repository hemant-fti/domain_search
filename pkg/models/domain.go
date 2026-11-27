// Package models holds the domain types shared by hostscope's reusable
// packages and its application layer. It depends only on the standard library.
package models

// Domain is one website or virtual host discovered in a web server configuration.
type Domain struct {
	ID          string    `json:"id,omitempty"`
	Name        string    `json:"name"`
	WebsiteName string    `json:"website_name,omitempty"`
	Status      string    `json:"status,omitempty"`
	Bindings    []Binding `json:"bindings,omitempty"`
	Path        string    `json:"path,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`

	Source         string              `json:"source"`
	ConfigPath     string              `json:"config_path"`
	ProxyTarget    string              `json:"proxy_target"`
	SSLCertificate string              `json:"ssl_certificate"`
	Aliases        []string            `json:"aliases"`
	Ports          []int               `json:"ports"`
	Certificates   []CertificateResult `json:"certificates"`
}

// Binding represents an IIS website binding.
type Binding struct {
	Protocol    string   `json:"protocol"`
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	Hostname    string   `json:"hostname,omitempty"`
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
}

// CertificatePaths records where a certificate was loaded from on disk.
type CertificatePaths struct {
	// Fullchain is the certificate file path. It is null for certificates
	// held in a Windows certificate store.
	Fullchain *string `json:"fullchain"`
}

// CertificateResult describes the certificate bound to one endpoint
// (an IIS binding or a web server's configured certificate file).
type CertificateResult struct {
	IP                string           `json:"ip"`
	FQDN              string           `json:"fqdn"`
	Installed         bool             `json:"installed"`
	CommonName        string           `json:"common_name"`
	IssuerDN          string           `json:"issuer_dn"`
	SubjectDN         string           `json:"subject_dn"`
	KeyBits           int              `json:"key_bits"`
	KeyType           string           `json:"key_type"`
	NotAfter          string           `json:"not_after"`
	NotBefore         string           `json:"not_before"`
	Paths             CertificatePaths `json:"paths"`
	SerialHex         string           `json:"serial_hex"`
	SerialNumber      string           `json:"serial_number"`
	SigAlg            string           `json:"sig_alg"`
	SPKISHA256        string           `json:"spki_sha256"`
	FingerprintSHA256 string           `json:"fingerprint_sha256"`
	FingerprintSHA1   string           `json:"fingerprint_sha1"`
	SANs              []string         `json:"sans"`
	Port              int              `json:"port"`

	// ExpiryStatus is one of the ExpiryStatus* constants; empty when the
	// certificate could not be read.
	ExpiryStatus  string   `json:"expiry_status,omitempty"`
	DaysRemaining int      `json:"days_remaining,omitempty"`
	KeyUsage      []string `json:"key_usage,omitempty"`
	ExtKeyUsage   []string `json:"ext_key_usage,omitempty"`
	// Error explains why Installed is false, when known.
	Error string `json:"error,omitempty"`
}

// Certificate expiry statuses.
const (
	ExpiryStatusValid       = "valid"
	ExpiryStatusExpiring    = "expiring"
	ExpiryStatusExpired     = "expired"
	ExpiryStatusNotYetValid = "not_yet_valid"
)
