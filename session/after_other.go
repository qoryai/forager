//go:build !linux

package session

import (
	"errors"
	"time"
)

// stopOthers stops nothing outside Linux, where no enclosure runs: After does not
// start.
func stopOthers(bool, time.Duration, []procID) error {
	return errors.New("the helper's exec runs outside Linux, where no container runs, so it stops no process")
}

// readOnlyMount reports false outside Linux, where After does not start.
func readOnlyMount(string) bool { return false }

// procID is a process: outside Linux, Exec lists none.
type procID struct{}

// startingProcesses lists no process outside Linux.
func startingProcesses() []procID { return nil }
