package e2e

import "syscall"

// remountWritable asks the kernel to bind-remount dir writable, as `mount -o
// remount,bind,rw` does: what a root inside a privileged container would try on a
// workspace bound read-only.
func remountWritable(dir string) error {
	return syscall.Mount("", dir, "", syscall.MS_REMOUNT|syscall.MS_BIND, "")
}
