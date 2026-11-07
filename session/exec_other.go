//go:build !linux

package session

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// closeInherited closes nothing outside Linux, where no enclosure runs.
func closeInherited() {}

// raise ends the process by sig where the Go runtime's handler does, as for TERM, INT
// and HUP: it hands sig back to the runtime and sends it to the process. It returns
// when the process outlives the signal.
func raise(sig syscall.Signal) {
	signal.Reset(sig)
	syscall.Kill(os.Getpid(), sig)
	time.Sleep(time.Second)
}
