package nginx

import (
	"context"
	"errors"
	"os/exec"
)

func detectNginx(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	_, err := exec.LookPath("nginx")
	if err == nil {
		return true, nil
	}

	if errors.Is(err, exec.ErrNotFound) {
		return false, nil
	}

	return false, err
}
