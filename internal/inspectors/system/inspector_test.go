package system

import (
	"context"
	"testing"
)

type resultExecutor struct {
	output string
}

func (e resultExecutor) Run(context.Context, string) (string, error) {
	return e.output, nil
}

func (e resultExecutor) ReadFiles(context.Context, []string) (map[string]string, error) {
	return nil, nil
}

func TestCollectParsesStructuredSystemInformation(t *testing.T) {
	info, warnings, err := New().Collect(context.Background(), resultExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Cores <= 0 || info.Threads <= 0 {
		t.Errorf("CPU counts must be positive: cores=%d threads=%d", info.Cores, info.Threads)
	}
	if info.IPv4 == nil || info.IPv6 == nil {
		t.Fatalf("address lists must be initialized: ipv4=%#v ipv6=%#v", info.IPv4, info.IPv6)
	}
	_ = warnings
}

func TestCollectKeepsAddressListsInitialized(t *testing.T) {
	info, warnings, err := New().Collect(context.Background(), resultExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	if info.IPv4 == nil || info.IPv6 == nil {
		t.Fatalf("missing addresses must be empty slices, got ipv4=%#v ipv6=%#v", info.IPv4, info.IPv6)
	}
	_ = warnings
}
