package inspectors

import (
	"context"
	ssh "domain-search/internal/os"
)

type Domain struct {
	Name           string   `json:"name"`
	Source         string   `json:"source"`
	ConfigPath     string   `json:"config_path"`
	DocumentRoot   string   `json:"document_root"`
	ProxyTarget    string   `json:"proxy_target"`
	SSLCertificate string   `json:"ssl_certificate"`
	Aliases        []string `json:"aliases"`
	Ports          []int    `json:"ports"`
}

type Inspector interface {
	Name() string
	Detect(context.Context, ssh.Executor) (bool, error)
	Discover(context.Context, ssh.Executor) ([]Domain, error)
}
