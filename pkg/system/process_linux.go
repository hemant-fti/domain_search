//go:build linux

package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procRoot is the procfs mount point; a variable so tests can use a fake tree.
var procRoot = "/proc"

// ProcessRunning reports whether any running process has one of the given
// command names (as in /proc/<pid>/comm).
func ProcessRunning(ctx context.Context, names ...string) (bool, error) {
	if len(names) == 0 {
		return false, nil
	}
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[n] = struct{}{}
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false, fmt.Errorf("read process information: %w", err)
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "comm"))
		if err != nil {
			continue // the process exited, or access is restricted
		}
		if _, ok := want[strings.TrimSpace(string(data))]; ok {
			return true, nil
		}
	}
	return false, nil
}
