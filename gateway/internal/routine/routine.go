// Package routine runs the gateway's goroutines, its accept loops' steps and its
// handlers, so that a panic in one ends that one alone and the gateway serves its runs
// on.
package routine

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"time"
)

// Go runs f in a new goroutine, as [Do] runs it: a panic in f ends that goroutine
// alone.
func Go(report func(string), f func(), closers ...io.Closer) {
	go Do(report, f, closers...)
}

// Do runs f and reports whether it panicked. A panic in f ends f, once f's deferred
// calls have run: each of closers is closed, the connection f served among them, and
// report gets [Panicked] with the stack. The report never contains the panic's value,
// which may contain a request's header or a credential. A nil report is standard
// error.
func Do(report func(string), f func(), closers ...io.Closer) (panicked bool) {
	defer func() {
		if recover() == nil {
			return
		}
		panicked = true
		for _, c := range closers {
			c.Close()
		}
		stack(report)
	}()
	f()
	return false
}

// Handler is h with a panic recovered before net/http recovers it, since net/http
// writes the panic's value to the server's error log. report gets [Panicked] with the
// stack, and the handler panics again with [http.ErrAbortHandler], of which net/http
// logs nothing: the connection closes, unless the handler hijacked it. A panic with
// http.ErrAbortHandler goes on unreported.
func Handler(report func(string), h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v != http.ErrAbortHandler {
				stack(report)
			}
			panic(http.ErrAbortHandler)
		}()
		h.ServeHTTP(w, r)
	})
}

// stack reports [Panicked] and the stack of the goroutine that panicked.
func stack(report func(string)) {
	if report == nil {
		report = Stderr
	}
	report(Panicked + "\n" + string(debug.Stack()))
}

// Panicked is the first line of the report of a panic; the stack follows it.
const Panicked = "the gateway recovered from a panic and serves on; send the stack below to Forager's maintainers"

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

// Accept calls take until take returns more false. take accepts one connection, sets
// *c to it and hands it on; failed says the accept failed, and the next call waits as
// http.Server waits after a failed accept: 5 ms, doubled each time up to 1 s. A panic
// in take is reported as [Do] reports one, closes *c when take set it, and counts as a
// failed accept: the loop accepts the next connection.
func Accept(report func(string), take func(c *net.Conn) (more, failed bool)) {
	var backoff time.Duration
	for {
		var c net.Conn
		more, failed := true, false
		if Do(report, func() { more, failed = take(&c) }) {
			if c != nil {
				c.Close()
			}
			failed = true
		}
		if !more {
			return
		}
		if !failed {
			backoff = 0
			continue
		}
		backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
		time.Sleep(backoff)
	}
}
