package apache

import (
	"context"

	ssh "domain-search/internal/os"
)

func detectApache(ctx context.Context, ex ssh.Executor) (bool, error) {
	if _, err := ex.Run(ctx, "command -v apachectl"); err == nil {
		return true, nil
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	if _, err := ex.Run(ctx, "command -v httpd"); err == nil {
		return true, nil
	}

	if err := ctx.Err(); err != nil {
		return false, err
	}

	return false, nil
}
