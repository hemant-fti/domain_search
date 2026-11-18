package nginx

import (
	"context"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
)

func isNginxRunning(ctx context.Context) (bool, error) {
	processes, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return false, err
	}

	for _, p := range processes {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		name, err := p.NameWithContext(ctx)
		if err != nil {
			continue
		}

		name = strings.ToLower(strings.TrimSpace(name))

		if name == "nginx" || strings.HasPrefix(name, "nginx:") {
			return true, nil
		}
	}

	return false, nil
}
