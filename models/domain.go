package models

type Domain struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	WebsiteName string   `json:"website_name,omitempty"`
	Status      string   `json:"status,omitempty"`
	Binding     []string `json:"binding,omitempty"`
	Path        string   `json:"path,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`

	Source         string   `json:"source"`
	ConfigPath     string   `json:"config_path"`
	ProxyTarget    string   `json:"proxy_target"`
	SSLCertificate string   `json:"ssl_certificate"`
	Aliases        []string `json:"aliases"`
	Ports          []int    `json:"ports"`
}
