package discovery

import (
	"context"
	"runtime"
	"testing"

	"domain-search/internal/inspectors"
	"domain-search/models"
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
	if runtime.GOOS != "linux" {
		t.Skip("Linux web-server inspection is not available on this platform")
	}
	service := NewService([]inspectors.Inspector{
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
	if runtime.GOOS != "linux" {
		t.Skip("Linux web-server inspection is not available on this platform")
	}
	service := NewService(nil)

	_, err := service.Inspect(context.Background(), "caddy", InspectOptions{
		Domains: true,
		Config:  true,
	})
	if err == nil {
		t.Fatal("Inspect() error = nil, want unsupported server error")
	}
}
