//go:build linux

package system

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessRunning(t *testing.T) {
	root := t.TempDir()
	for pid, comm := range map[string]string{"1": "systemd\n", "42": "nginx\n", "99": "httpd\n"} {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Non-numeric entries and pids without comm are ignored.
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "7"), 0o755); err != nil {
		t.Fatal(err)
	}

	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })

	tests := []struct {
		names []string
		want  bool
	}{
		{[]string{"nginx"}, true},
		{[]string{"apache2", "httpd"}, true},
		{[]string{"caddy"}, false},
		{nil, false},
	}
	for _, tt := range tests {
		got, err := ProcessRunning(context.Background(), tt.names...)
		if err != nil || got != tt.want {
			t.Errorf("ProcessRunning(%v) = %v, %v; want %v", tt.names, got, err, tt.want)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProcessRunning(ctx, "nginx"); err == nil {
		t.Error("cancelled context was ignored")
	}
}

func TestProcessRunningMissingProc(t *testing.T) {
	old := procRoot
	procRoot = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { procRoot = old })

	if _, err := ProcessRunning(context.Background(), "nginx"); err == nil {
		t.Error("expected an error when procfs is unavailable")
	}
}
