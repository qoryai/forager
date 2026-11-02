package e2e

import "golang.org/x/sys/unix"

// remountWritable asks the kernel to bind-remount dir writable, as `mount -o
// remount,bind,rw` does: what a root inside a privileged container would try on a
// workspace bound read-only. It keeps the mount's other flags, which statfs reports,
// so the kernel does not refuse the call for a change to a locked flag alone.
func remountWritable(dir string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return err
	}
	flags := uint64(st.Flags)
	keep := uintptr(unix.MS_REMOUNT | unix.MS_BIND)
	for stFlag, msFlag := range map[uint64]uintptr{
		unix.ST_NOSUID: unix.MS_NOSUID, unix.ST_NODEV: unix.MS_NODEV, unix.ST_NOEXEC: unix.MS_NOEXEC,
		unix.ST_NOATIME: unix.MS_NOATIME, unix.ST_NODIRATIME: unix.MS_NODIRATIME, unix.ST_RELATIME: unix.MS_RELATIME,
	} {
		if flags&stFlag != 0 {
			keep |= msFlag
		}
	}
	return unix.Mount("", dir, "", keep, "")
}

// clearReadOnly asks the kernel, through mount_setattr, to clear the read-only
// attribute of the mount at dir and nothing else.
func clearReadOnly(dir string) error {
	return unix.MountSetattr(unix.AT_FDCWD, dir, 0, &unix.MountAttr{Attr_clr: unix.MOUNT_ATTR_RDONLY})
}
