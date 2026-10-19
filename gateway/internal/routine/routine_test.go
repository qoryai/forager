package routine_test

import (
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
