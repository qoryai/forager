package routine_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/routine"
)

// closer records that it was closed.
type closer chan struct{}

func (c closer) Close() error {
	close(c)
	return nil
}

// TestAPanicEndsItsGoroutineAlone pins that a panic in a goroutine Go started runs the
// goroutine's deferred calls, closes its closers and reports the run's id and the stack
// without the panic's value; and that a goroutine that ends without a panic closes
// nothing and reports nothing.
func TestAPanicEndsItsGoroutineAlone(t *testing.T) {
	reports := make(chan string, 2)
	report := routine.ForRun(func(line string) { reports <- line }, "run-a")
	deferred, closed := make(chan struct{}), make(closer)
	routine.Go(report, func() {
		defer close(deferred)
		panic("Bearer fake-key-0001")
	}, closed)
	var got string
	select {
	case got = <-reports:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reported")
	}
	first, stack, _ := strings.Cut(got, "\n")
	if want := "run run-a: " + routine.Panicked; first != want {
		t.Errorf("the report's first line is %q, want %q", first, want)
	}
	if !strings.Contains(stack, "TestAPanicEndsItsGoroutineAlone") {
		t.Errorf("the report has no stack of the goroutine: %q", stack)
	}
	if strings.Contains(got, "fake-key-0001") {
		t.Errorf("the report contains the panic's value: %q", got)
	}
	for name, ch := range map[string]chan struct{}{"deferred call": deferred, "closer": closed} {
		select {
		case <-ch:
		default:
			t.Errorf("the %s did not run", name)
		}
	}

	done, untouched := make(chan struct{}), make(closer)
	routine.Go(report, func() { close(done) }, untouched)
	<-done
	time.Sleep(10 * time.Millisecond)
	select {
	case <-untouched:
		t.Error("a goroutine without a panic closed its closer")
	case line := <-reports:
		t.Errorf("a goroutine without a panic reported %q", line)
	default:
	}
}

// conn is a connection that records that it was closed.
type conn struct {
	net.Conn
	closed chan struct{}
}

func (c *conn) Close() error {
	close(c.closed)
	return nil
}

// TestAcceptGoesOnAfterAPanic pins that a panic in one step of Accept closes the
// connection the step took, is reported without its value, and that Accept calls the
// next step, until a step returns more false.
func TestAcceptGoesOnAfterAPanic(t *testing.T) {
	var reports []string
	taken := &conn{closed: make(chan struct{})}
	steps := 0
	routine.Accept(func(line string) { reports = append(reports, line) }, func(c *net.Conn) (more, failed bool) {
		steps++
		if steps == 1 {
			*c = taken
			panic("Authorization: Bearer fake-key-0001")
		}
		return false, false
	})
	if steps != 2 {
		t.Errorf("Accept called %d steps, want 2", steps)
	}
	select {
	case <-taken.closed:
	default:
		t.Error("the connection of the step that panicked is open")
	}
	if len(reports) != 1 || !strings.HasPrefix(reports[0], routine.Panicked+"\n") || strings.Contains(reports[0], "fake-key-0001") {
		t.Errorf("the reports: %q", reports)
	}
}
