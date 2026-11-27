//go:build !windows

package iis

import (
	"context"
	"errors"

	"domain-search/pkg/models"
)

// ErrUnsupported is returned by Discover on non-Windows platforms.
var ErrUnsupported = errors.New("IIS inspection is supported only on Windows")

// Detect always reports false: IIS exists only on Windows.
func (*Inspector) Detect(context.Context) (bool, error) { return false, nil }

// Running always reports false on this platform.
func (*Inspector) Running(context.Context) (bool, error) { return false, nil }

// Discover is not supported on this platform.
func (*Inspector) Discover(context.Context) ([]models.Domain, error) {
	return nil, ErrUnsupported
}
