package system

import (
	"context"
	"testing"
)

func TestCollectNetworkInfoUsesInitializedAddressLists(t *testing.T) {
	info, err := CollectNetworkInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.IPv4 == nil || info.IPv6 == nil {
		t.Fatalf("address lists must be initialized: ipv4=%#v ipv6=%#v", info.IPv4, info.IPv6)
	}
}

func TestCollectNetworkInfoHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CollectNetworkInfo(ctx); err == nil {
		t.Fatal("expected canceled context error")
	}
}
