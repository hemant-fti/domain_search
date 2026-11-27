package dns

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"domain-search/pkg/models"
)

type fakeClient struct {
	addrs []netip.Addr
	err   error
}

func (f fakeClient) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return f.addrs, f.err
}

func addrs(values ...string) []netip.Addr {
	out := make([]netip.Addr, len(values))
	for i, v := range values {
		out[i] = netip.MustParseAddr(v)
	}
	return out
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name      string
		client    fakeClient
		serverIP  string
		want      models.DNSResult
		wantError bool
	}{
		{
			name:     "matches server",
			client:   fakeClient{addrs: addrs("198.51.100.2", "192.0.2.1")},
			serverIP: "192.0.2.1",
			want:     models.DNSResult{ResolvedIPs: []string{"192.0.2.1", "198.51.100.2"}, MatchesServer: true, Status: models.DNSStatusMatchesServer},
		},
		{
			name:     "IPv4-mapped server address matches",
			client:   fakeClient{addrs: addrs("192.0.2.1")},
			serverIP: "::ffff:192.0.2.1",
			want:     models.DNSResult{ResolvedIPs: []string{"192.0.2.1"}, MatchesServer: true, Status: models.DNSStatusMatchesServer},
		},
		{
			name:     "points elsewhere",
			client:   fakeClient{addrs: addrs("203.0.113.9")},
			serverIP: "192.0.2.1",
			want:     models.DNSResult{ResolvedIPs: []string{"203.0.113.9"}, Status: models.DNSStatusResolvedOtherIP},
		},
		{
			name:      "lookup error",
			client:    fakeClient{err: errors.New("no such host")},
			serverIP:  "192.0.2.1",
			want:      models.DNSResult{ResolvedIPs: []string{}, Status: models.DNSStatusUnresolved},
			wantError: true,
		},
		{
			name:      "no addresses",
			client:    fakeClient{},
			serverIP:  "192.0.2.1",
			want:      models.DNSResult{ResolvedIPs: []string{}, Status: models.DNSStatusUnresolved},
			wantError: true,
		},
		{
			name:      "unknown server IP",
			client:    fakeClient{addrs: addrs("192.0.2.1")},
			serverIP:  "",
			want:      models.DNSResult{ResolvedIPs: []string{"192.0.2.1"}, Status: models.DNSStatusInvalidServerIP},
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewResolverWithClient(tt.client).Verify(context.Background(), "example.com", tt.serverIP)
			if (err != nil) != tt.wantError {
				t.Fatalf("error = %v, wantError %v", err, tt.wantError)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Verify = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLookupIPDeduplicatesAndSorts(t *testing.T) {
	r := NewResolverWithClient(fakeClient{addrs: addrs("2001:db8::1", "192.0.2.9", "::ffff:192.0.2.9", "192.0.2.1")})
	got, err := r.LookupIP(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "192.0.2.9", "2001:db8::1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LookupIP = %v, want %v", got, want)
	}
}
