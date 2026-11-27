//go:build !linux && !windows

package scan

func platformInspectors() []Inspector { return nil }
