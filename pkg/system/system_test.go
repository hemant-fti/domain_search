package system

import (
	"context"
	"net/netip"
	"slices"
	"testing"
)

func TestLocalIPsAreValidSortedAndUnique(t *testing.T) {
	ips, err := LocalIPs()
	if err != nil {
		t.Skipf("no network interfaces: %v", err)
	}
	parsed := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatalf("invalid address %q", ip)
		}
		if addr.IsLoopback() {
			t.Errorf("loopback address %s returned", ip)
		}
		parsed = append(parsed, addr)
	}
	if !slices.IsSortedFunc(parsed, netip.Addr.Compare) {
		t.Errorf("addresses not sorted: %v", ips)
	}
	if len(slices.Compact(slices.Clone(parsed))) != len(parsed) {
		t.Errorf("duplicate addresses: %v", ips)
	}
}

func TestCollectorsRespectCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := CollectCPUInfo(ctx); err == nil {
		t.Error("CollectCPUInfo ignored cancellation")
	}
	if _, err := CollectMemoryInfo(ctx); err == nil {
		t.Error("CollectMemoryInfo ignored cancellation")
	}
	if _, err := CollectDiskInfo(ctx, ""); err == nil {
		t.Error("CollectDiskInfo ignored cancellation")
	}
	if _, _, err := GetSysInfo(ctx); err == nil {
		t.Error("GetSysInfo ignored cancellation")
	}
}

func TestCollectMemoryAndDisk(t *testing.T) {
	mem, err := CollectMemoryInfo(context.Background())
	if err != nil {
		t.Skipf("memory metrics unavailable: %v", err)
	}
	if mem.TotalGB <= 0 || mem.UsedGB < 0 {
		t.Errorf("memory = %+v", mem)
	}
	disk, err := CollectDiskInfo(context.Background(), "")
	if err != nil {
		t.Skipf("disk metrics unavailable: %v", err)
	}
	if disk.TotalGB <= 0 || disk.UsedGB > disk.TotalGB {
		t.Errorf("disk = %+v", disk)
	}
}
