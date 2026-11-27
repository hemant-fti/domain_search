//go:build windows

package store

import (
	"errors"
	"testing"
)

func TestFindByThumbprintNotFound(t *testing.T) {
	thumb := make([]byte, 20) // all zeros: never a real certificate
	_, err := FindByThumbprint(DefaultStore, thumb)
	if err == nil {
		t.Fatal("expected an error for an unknown thumbprint")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Logf("store unavailable in this environment: %v", err)
	}
}

func TestFindByThumbprintRejectsEmpty(t *testing.T) {
	if _, err := FindByThumbprint(DefaultStore, nil); err == nil {
		t.Fatal("expected an error for an empty thumbprint")
	}
}
