package discovery

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"domain-search/internal/inspectors"
)

type inspectionExecutor struct {
	commands map[string]string
	errors   map[string]error
}

func (e *inspectionExecutor) Run(_ context.Context, command string) (string, error) {
	if err := e.errors[command]; err != nil {
		return "", err
	}
	return e.commands[command], nil
}

func (e *inspectionExecutor) ReadFiles(context.Context, []string) (map[string]string, error) {
	return nil, errors.New("not implemented")
}

type testInspector struct {
	name        string
	detected    bool
	running     bool
	domains     []inspectors.Domain
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

func (i *testInspector) Discover(context.Context) ([]inspectors.Domain, error) {
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
			domains: []inspectors.Domain{
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
