package system

import (
	"os/user"
)

func currentUser() string {
	current, err := user.Current()
	if err != nil {
		return ""
	}

	return current.Username
}
