//go:build windows

package system

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ErrServiceNotInstalled is returned when a Windows service does not exist.
var ErrServiceNotInstalled = errors.New("service is not installed")

// ServiceRunning reports whether the named Windows service is running.
// A service that is not installed returns (false, ErrServiceNotInstalled).
func ServiceRunning(ctx context.Context, name string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	// Request only SC_MANAGER_CONNECT so non-administrators can query status;
	// mgr.Connect asks for full access.
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, fmt.Errorf("connect to service manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, ErrServiceNotInstalled
		}
		return false, fmt.Errorf("open service %s: %w", name, err)
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return false, fmt.Errorf("query service %s: %w", name, err)
	}
	return status.State == svc.Running, nil
}

// RegistryValueExists reports whether HKLM\<path> exists and has value name.
func RegistryValueExists(path, name string) (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("open HKLM\\%s: %w", path, err)
	}
	defer key.Close()

	if _, _, err := key.GetValue(name, nil); err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read HKLM\\%s\\%s: %w", path, name, err)
	}
	return true, nil
}
