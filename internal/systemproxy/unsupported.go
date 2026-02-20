//go:build !darwin

package systemproxy

import "errors"

func Enable(host string, port int) (string, error) {
	return "", errors.New("system proxy management is supported only on macOS")
}

func Disable() (string, error) {
	return "", errors.New("system proxy management is supported only on macOS")
}

func CurrentStatus() (Status, error) {
	return Status{}, errors.New("system proxy management is supported only on macOS")
}
