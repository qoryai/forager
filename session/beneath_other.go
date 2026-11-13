//go:build !linux

package session

// openBeneath opens the path of names below root for reading, [walkBeneath]: a system without
// openat2 gets the same checks one name at a time.
func openBeneath(root string, names []string) (int, error) {
	return walkBeneath(root, names)
}
