//go:build linux

package scan

import (
	"domain-search/pkg/apache"
	"domain-search/pkg/nginx"
)

func platformInspectors() []Inspector {
	return []Inspector{nginx.New(), apache.New()}
}
