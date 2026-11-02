//go:build !linux

package e2e

import "errors"

// remountWritable is a remount, which runs on Linux alone.
func remountWritable(string) error {
	return errors.New("a remount runs on Linux alone")
}
