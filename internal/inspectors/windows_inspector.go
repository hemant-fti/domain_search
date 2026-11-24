//go:build windows

package inspectors

import (
	"context"
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
	Detect(context.Context) (bool, error)
	Discover(context.Context) ([]Domain, error)
}
