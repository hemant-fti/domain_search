//go:build linux

package discovery

import (
	"domain-search/internal/inspectors"
	"domain-search/internal/inspectors/apache"
	"domain-search/internal/inspectors/nginx"
)

func platformInspectors() []inspectors.Inspector {
	return []inspectors.Inspector{
		nginx.New(),
		apache.New(),
	}
}