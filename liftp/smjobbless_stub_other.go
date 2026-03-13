//go:build !darwin

package liftp

import "errors"

// EnsurePrivilegedHelperInstalled is only meaningful on macOS.
func EnsurePrivilegedHelperInstalled(why string) error {
	_ = why
	return errors.New("SMJobBless is only supported on macOS")
}
