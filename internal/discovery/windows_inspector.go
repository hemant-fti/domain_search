//go:build windows

package discovery

import (
	"domain-search/internal/inspectors"
	"domain-search/internal/inspectors/iis"
)

func platformInspectors() []inspectors.Inspector {
	return []inspectors.Inspector{
		iis.New(),
	}
}
