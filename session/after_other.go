//go:build !linux

package session

// readOnlyMount reports false outside Linux, where no container runs.
func readOnlyMount(string) bool { return false }
