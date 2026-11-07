//go:build !linux

package session

// closeInherited closes nothing outside Linux, where no enclosure runs.
func closeInherited() {}
