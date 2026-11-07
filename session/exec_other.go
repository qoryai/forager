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

// undumpable changes nothing outside Linux.
func undumpable() {}

// exited reports false at once outside Linux, where the syscall package has no wait
// that leaves the process to be reaped.
func exited(int) bool { return false }

// ignore keeps sigs from ending the process: they go to a channel that nothing reads.
// Outside Linux raise cannot undo signal.Ignore, since signal.Reset leaves INT and HUP
// ignored after it.
func ignore(sigs []os.Signal) {
	signal.Notify(make(chan os.Signal, 1), sigs...)
}

// raise ends the process by sig where the Go runtime's handler does, as for TERM, INT
// and HUP: it hands sig back to the runtime and sends it to the process. It returns
// when the process outlives the signal.
func raise(sig syscall.Signal) {
	signal.Reset(sig)
	syscall.Kill(os.Getpid(), sig)
	time.Sleep(time.Second)
}
