package models

type Domain struct {
	ID          string    `json:"id,omitempty"`
	Name        string    `json:"name"`
	WebsiteName string    `json:"website_name,omitempty"`
	Status      string    `json:"status,omitempty"`
	Bindings    []Binding `json:"bindings,omitempty"`
	Path        string    `json:"path,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`

	Source         string   `json:"source"`
	ConfigPath     string   `json:"config_path"`
	ProxyTarget    string   `json:"proxy_target"`
	SSLCertificate string   `json:"ssl_certificate"`
	Aliases        []string `json:"aliases"`
	Ports          []int    `json:"ports"`
}

// Binding represents an IIS website binding.
type Binding struct {
	Protocol    string   `json:"protocol"`
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	Hostname    string   `json:"hostname,omitempty"`
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
}
