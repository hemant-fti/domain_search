//go:build windows

package httpsys

import (
	"encoding/binary"
	"reflect"
	"testing"
	"unsafe"
)

func TestIPsToTry(t *testing.T) {
	tests := map[string][]string{
		"":            {"0.0.0.0", "::"},
		"*":           {"0.0.0.0", "::"},
		"192.0.2.1":   {"192.0.2.1", "0.0.0.0"},
		"2001:db8::1": {"2001:db8::1", "::"},
		"0.0.0.0":     {"0.0.0.0"},
		"not-an-ip":   {"not-an-ip"},
	}
	for in, want := range tests {
		if got := ipsToTry(in); !reflect.DeepEqual(got, want) {
			t.Errorf("ipsToTry(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestBuildSockaddr(t *testing.T) {
	sa, err := buildSockaddr("192.0.2.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	raw := (*[128]byte)(unsafe.Pointer(sa))
	if family := binary.LittleEndian.Uint16(raw[0:2]); family != afInet {
		t.Errorf("family = %d, want AF_INET", family)
	}
	if port := binary.BigEndian.Uint16(raw[2:4]); port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	if !reflect.DeepEqual(raw[4:8], []byte{192, 0, 2, 1}) {
		t.Errorf("address = %v", raw[4:8])
	}

	sa6, err := buildSockaddr("2001:db8::1", 8443)
	if err != nil {
		t.Fatal(err)
	}
	raw6 := (*[128]byte)(unsafe.Pointer(sa6))
	if family := binary.LittleEndian.Uint16(raw6[0:2]); family != afInet6 {
		t.Errorf("family = %d, want AF_INET6", family)
	}
	if raw6[8] != 0x20 || raw6[9] != 0x01 || raw6[23] != 0x01 {
		t.Errorf("IPv6 address bytes = %v", raw6[8:24])
	}

	for _, bad := range []struct {
		ip   string
		port int
	}{{"192.0.2.1", 0}, {"192.0.2.1", 70000}, {"*", 443}} {
		if _, err := buildSockaddr(bad.ip, bad.port); err == nil {
			t.Errorf("buildSockaddr(%q, %d) succeeded", bad.ip, bad.port)
		}
	}
}

func TestKernelBufferBoundsChecks(t *testing.T) {
	buf := make(kernelBuffer, 4) // 32 bytes
	base := uintptr(unsafe.Pointer(&buf[0]))

	if _, err := buf.offsetOf(base+30, 4); err == nil {
		t.Error("read past the end was allowed")
	}
	if _, err := buf.offsetOf(base-1, 1); err == nil {
		t.Error("read before the start was allowed")
	}
	if off, err := buf.offsetOf(base+8, 8); err != nil || off != 8 {
		t.Errorf("offsetOf = %d, %v", off, err)
	}
}

func TestClosedSessionLookupFails(t *testing.T) {
	s := &Session{closed: true}
	if _, err := s.Lookup("*", 443, "", 0); err == nil {
		t.Error("Lookup on a closed session succeeded")
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close() = %v", err)
	}
}

func TestCCSBindingIsReported(t *testing.T) {
	s := &Session{}
	if _, err := s.Lookup("*", 443, "x.test", sslFlagCCS); err != ErrCCS {
		t.Errorf("Lookup(CCS) error = %v, want ErrCCS", err)
	}
}
