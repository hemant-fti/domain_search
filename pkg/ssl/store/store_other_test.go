//go:build !windows

package store

import (
	"errors"
	"testing"
)

func TestFindByThumbprintUnsupported(t *testing.T) {
	if _, err := FindByThumbprint(DefaultStore, []byte{1}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
}
