package models

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

type HTTPSSLCertificateBinding struct {
	IPPort       string
	HostnamePort string
	Hash         string
	StoreName    string
}

// CertificatePaths is kept for output-schema compatibility.
type CertificatePaths struct {
	Fullchain *string `json:"fullchain"` // always null: Windows keeps certs in a store, not in files
}

// CertificateResult is the details of the certificate bound to one IIS binding.
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
}
