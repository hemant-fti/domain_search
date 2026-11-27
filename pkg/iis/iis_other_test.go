//go:build !windows

package iis

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedOutsideWindows(t *testing.T) {
	i := New()
	if detected, err := i.Detect(context.Background()); detected || err != nil {
		t.Errorf("Detect = %v, %v", detected, err)
	}
	if _, err := i.Discover(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Discover error = %v, want ErrUnsupported", err)
	}
}
