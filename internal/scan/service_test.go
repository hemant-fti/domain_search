package scan

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"domain-search/pkg/dns"
	"domain-search/pkg/models"
)

type testInspector struct {
	name        string
	detected    bool
	running     bool
	domains     []models.Domain
	detectErr   error
	runningErr  error
	discoverErr error
}

func (i *testInspector) Name() string {
	return i.name
}

func (i *testInspector) Detect(context.Context) (bool, error) {
	return i.detected, i.detectErr
}

func (i *testInspector) Running(context.Context) (bool, error) {
	return i.running, i.runningErr
}

func (i *testInspector) Discover(context.Context) ([]models.Domain, error) {
	return i.domains, i.discoverErr
}

func TestInspectUsesSharedInspectorLogic(t *testing.T) {
	service := NewService([]Inspector{
		&testInspector{
			name:     "nginx",
			detected: true,
			running:  true,
			domains: []models.Domain{
				{Name: "example.com", ConfigPath: "/etc/nginx/example.conf"},
			},
		},
	})

	result, err := service.Inspect(context.Background(), "nginx", InspectOptions{
		Domains: true,
		Config:  true,
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !result.Detected || !result.Running {
		t.Fatalf("Inspect() result = %#v, want detected and running", result)
	}
	if len(result.Domains) != 1 || len(result.Configs) != 1 {
		t.Fatalf("Inspect() domains/configs = %d/%d, want 1/1", len(result.Domains), len(result.Configs))
	}
}

func TestInspectRejectsUnsupportedServer(t *testing.T) {
	service := NewService(nil)

	_, err := service.Inspect(context.Background(), "caddy", InspectOptions{
		Domains: true,
		Config:  true,
	})
	if err == nil {
		t.Fatal("Inspect() error = nil, want unsupported server error")
	}
}

func TestInspectKeepsPartialResults(t *testing.T) {
	service := NewService([]Inspector{&testInspector{
		name:        "apache",
		detected:    true,
		domains:     []models.Domain{{Name: "partial.example.com"}},
		discoverErr: errors.New("read /etc/apache2/x.conf: permission denied"),
	}})

	result, err := service.Inspect(context.Background(), "apache", InspectOptions{Domains: true})
	if err != nil {
		t.Fatalf("Inspect() error = %v, want partial result without error", err)
	}
	if len(result.Domains) != 1 || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "permission denied") {
		t.Fatalf("Inspect() = %+v", result)
	}
}

func TestInspectFailsWhenDiscoveryReturnsNothing(t *testing.T) {
	service := NewService([]Inspector{&testInspector{
		name: "nginx", detected: true, discoverErr: errors.New("nginx -T failed"),
	}})
	if _, err := service.Inspect(context.Background(), "nginx", InspectOptions{Domains: true}); err == nil {
		t.Fatal("Inspect() error = nil, want discovery failure")
	}
}

func TestInspectNotDetected(t *testing.T) {
	service := NewService([]Inspector{&testInspector{name: "nginx"}})
	result, err := service.Inspect(context.Background(), "NGINX", InspectOptions{Domains: true})
	if err != nil || result.Detected || len(result.Domains) != 0 {
		t.Fatalf("Inspect() = %+v, %v", result, err)
	}
}

type staticLookup []netip.Addr

func (s staticLookup) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return s, nil
}

func TestDiscoverCollectsDomainsAndWarnings(t *testing.T) {
	service := NewService([]Inspector{
		&testInspector{
			name: "nginx", detected: true, running: true,
			domains: []models.Domain{
				{Name: "Example.com.", Source: "nginx", Ports: []int{443, 80}},
				{Name: "example.com", Source: "nginx", Aliases: []string{"www.example.com"}},
			},
			discoverErr: errors.New("nginx certificate /x.pem: no such file"),
		},
		&testInspector{name: "apache", detectErr: errors.New("probe failed")},
		&testInspector{name: "caddy"},
	})
	service.resolver = dns.NewResolverWithClient(staticLookup{netip.MustParseAddr("192.0.2.1")})

	res, err := service.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(res.DetectedServices) != 1 || res.DetectedServices[0] != "nginx" {
		t.Errorf("DetectedServices = %v", res.DetectedServices)
	}
	if len(res.Servers) != 1 || !res.Servers[0].Running {
		t.Errorf("Servers = %+v", res.Servers)
	}
	if res.TotalDomains != 1 || res.Domains[0].Name != "example.com" {
		t.Fatalf("Domains = %+v, want one normalized example.com", res.Domains)
	}
	if res.Domains[0].DNS.Status == "" || len(res.Domains[0].DNS.ResolvedIPs) != 1 {
		t.Errorf("DNS = %+v", res.Domains[0].DNS)
	}

	joined := strings.Join(res.Warnings, "\n")
	for _, want := range []string{"nginx scan: nginx certificate", "apache detection: probe failed"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings %q missing %q", res.Warnings, want)
		}
	}
	if len(res.ErrorEvents) != len(res.Warnings) {
		t.Errorf("ErrorEvents = %d, Warnings = %d", len(res.ErrorEvents), len(res.Warnings))
	}
}

func TestDiscoverStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewService(nil).Discover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover() error = %v, want context.Canceled", err)
	}
}
