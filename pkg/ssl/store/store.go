// Package store reads certificates from an operating-system certificate store.
//
// Only the Windows LocalMachine stores are supported; on other platforms every
// call returns ErrUnsupported.
package store

import "errors"

// ErrUnsupported is returned on platforms without a supported store.
var ErrUnsupported = errors.New("certificate store access is supported only on Windows")

// ErrNotFound is returned when no certificate matches.
var ErrNotFound = errors.New("certificate not found in store")

// DefaultStore is the LocalMachine personal store ("Personal" in the MMC).
const DefaultStore = "MY"
