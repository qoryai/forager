//go:build !linux

package e2e

import "errors"

// remountWritable is a remount, which runs on Linux alone.
func remountWritable(string) error {
	return errors.New("a remount runs on Linux alone")
}

// clearReadOnly is a mount_setattr call, which runs on Linux alone.
func clearReadOnly(string) error {
	return errors.New("mount_setattr runs on Linux alone")
}
