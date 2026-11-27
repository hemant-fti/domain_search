//go:build windows

package scan

import "domain-search/pkg/iis"

func platformInspectors() []Inspector {
	return []Inspector{iis.New()}
}
