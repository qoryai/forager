//go:build !linux

package session

// openBeneath opens slug/name below root for reading, [walkBeneath]: a system without
// openat2 gets the same checks one name at a time.
func openBeneath(root, slug, name string) (int, error) {
	return walkBeneath(root, slug, name)
}
