//go:build !windows

package iis

func getIISSiteStatuses() (map[string]string, error) {
	return nil, nil
}
