package session

import "golang.org/x/sys/unix"

// readOnlyMount reports whether p is on a mount that is read-only.
func readOnlyMount(p string) bool {
	var fs unix.Statfs_t
	return unix.Statfs(p, &fs) == nil && fs.Flags&unix.ST_RDONLY != 0
}
