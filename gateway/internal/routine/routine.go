// Package routine starts the gateway's goroutines, so that a panic in one ends that
// goroutine alone and the gateway serves its runs on.
package routine

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// Go runs f in a new goroutine. A panic in f ends that goroutine alone, once f's
// deferred calls have run: each of closers is closed, the connection f served among
// them, and report gets [Panicked] with the stack. The report never contains the
// panic's value, which may contain a request's header or a credential. A nil report is
// standard error.
func Go(report func(string), f func(), closers ...io.Closer) {
	go func() {
		defer func() {
			if recover() == nil {
				return
			}
			for _, c := range closers {
				c.Close()
			}
			if report == nil {
				report = Stderr
			}
			report(Panicked + "\n" + string(debug.Stack()))
		}()
		f()
	}()
}

// Panicked is the first line of the report of a panic; the stack follows it.
const Panicked = "a goroutine of the gateway panicked and ended, and the gateway serves on; send the stack below to Forager's maintainers"

// ForRun is report with each line after "run <id>: ", as the gateway's lines about a
// run start. A nil report is standard error.
func ForRun(report func(string), run string) func(string) {
	if report == nil {
		report = Stderr
	}
	return func(line string) { report("run " + run + ": " + line) }
}

// Stderr writes line to standard error, where a report goes that nobody set.
func Stderr(line string) { fmt.Fprintln(os.Stderr, line) }
