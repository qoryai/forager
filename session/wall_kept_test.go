package session_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// removeEntry removes the entry among the walled runs still going of the run, which
// stays when a removal of its wall failed.
func removeEntry(t *testing.T, runID string) {
	t.Helper()
	t.Cleanup(func() { os.Remove(filepath.Join(registry(t), runID)) })
}

// TestWallKeptAfterASession pins Closed.WallKept for a run of one session: false with
// no wall and with a wall whose removals succeed, true when Unwrap failed, also with a
// close that succeeded, and true when the close failed on a container or with an error
// of unknown kind, alone or beside a network. A close whose every failure matches
// wall.ErrNoContainerKept, a network or the private directory, also wrapped, leaves it
// false and reports the failure, as every failed close does.
func TestWallKeptAfterASession(t *testing.T) {
	failure := errors.New("wall docker: rm: exit status 1")
	const container = "wall docker: docker rm --force: exit status 1"
	const network = "wall docker: network rm: exit status 1"
	const dir = "RemoveAll /run/qory-x: permission denied"
	for name, c := range map[string]struct {
		wall wall.Wall
		want bool
		// report is the close's report line, empty for none.
		report string
	}{
		"no wall":        {nil, false, ""},
		"nothing failed": {&openWall{}, false, ""},
		"Unwrap failed":  {&keptSetupWall{unwrapErr: failure}, true, ""},
		"the close failed on a container": {
			&runCloseFailing{enginedWall: enginedWall{engine: leftEngine}, closeErr: containerKept(container)},
			true, "removing the wall: " + container,
		},
		"the close failed on a network alone": {
			&runCloseFailing{enginedWall: enginedWall{engine: leftEngine}},
			false, "removing the wall: wall docker: network rm: exit status 1",
		},
		"the close failed on a network and a container": {
			&runCloseFailing{enginedWall: enginedWall{engine: leftEngine}, closeErr: errors.Join(
				noContainerKept(network), containerKept(container))},
			true, "removing the wall: " + network + "\n" + container,
		},
		"the close failed on a network and the private directory": {
			&runCloseFailing{enginedWall: enginedWall{engine: leftEngine}, closeErr: errors.Join(
				noContainerKept(network), fmt.Errorf("wall docker: %w", noContainerKept(dir)))},
			false, "removing the wall: " + network + "\nwall docker: " + dir,
		},
		"the close failed with an error of unknown kind": {
			&runCloseFailing{enginedWall: enginedWall{engine: leftEngine}, closeErr: errors.New(network)},
			true, "removing the wall: " + network,
		},
		"the close failed on a network and with an error of unknown kind": {
			&runCloseFailing{enginedWall: enginedWall{engine: leftEngine}, closeErr: errors.Join(
				noContainerKept(network), errors.New(dir))},
			true, "removing the wall: " + network + "\n" + dir,
		},
		"Unwrap and the close failed": {&closeFailing{enginedWall{engine: leftEngine}}, true, "removing the wall: wall docker: rm: exit status 1"},
	} {
		t.Run(name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			if c.wall != nil {
				sp.Wall, sp.Image = c.wall, "example.com/agent:1"
			}
			var reports []string
			sp.Report = func(s string) { reports = append(reports, s) }
			_, closed, err := runClosed(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			removeEntry(t, closed.RunID)
			if closed.WallKept != c.want {
				t.Errorf("WallKept %v, want %v", closed.WallKept, c.want)
			}
			if c.report != "" && !slices.Contains(reports, c.report) {
				t.Errorf("reports %q, want %q among them", reports, c.report)
			}
		})
	}
}

// unwraplessWall is an open wall with no Unwrap, whose agent's container stays until the
// close, and whose Close returns closeErr.
type unwraplessWall struct {
	openWall
	closeErr error
}

func (w *unwraplessWall) Prepare(ctx context.Context, req wall.Request) (wall.Enclosure, error) {
	w.openWall.Prepare(ctx, req)
	return w, nil
}

func (w *unwraplessWall) Close(ctx context.Context) error {
	w.openWall.Close(ctx)
	return w.closeErr
}

// TestContainerKeptBeforeAndAfterTheClose pins Run.ContainerKept for a run of one
// session: false while the removals succeed, true from a failed Unwrap on, and false
// before a close that fails. A wall with no Unwrap keeps the agent's container until the
// close, so it is true from the session's end until the close. After the close it equals
// Closed.WallKept: true for a container the close could not remove, and false for a
// network alone or a close that succeeded. A call while the session runs returns without
// waiting for the session.
func TestContainerKeptBeforeAndAfterTheClose(t *testing.T) {
	ctx := context.Background()
	failure := errors.New("wall docker: rm: exit status 1")
	for name, c := range map[string]struct {
		wall          wall.Wall
		before, after bool
	}{
		"nothing failed":        {&keptSetupWall{}, false, false},
		"a wall with no Unwrap": {&unwraplessWall{}, true, false},
		"a wall with no Unwrap whose close failed on a container": {
			&unwraplessWall{closeErr: containerKept("wall docker: docker rm --force: exit status 1")}, true, true,
		},
		"Unwrap failed": {&keptSetupWall{unwrapErr: failure}, true, true},
		"the close failed on a network alone": {
			&runCloseFailing{enginedWall: enginedWall{engine: leftEngine}}, false, false,
		},
		"the close failed on a container": {
			&runCloseFailing{
				enginedWall: enginedWall{engine: leftEngine},
				closeErr:    containerKept("wall docker: docker rm --force: exit status 1"),
			}, false, true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			sp.Wall, sp.Image = c.wall, "example.com/agent:1"
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			removeEntry(t, r.ID())
			if r.ContainerKept() {
				t.Error("ContainerKept is true before the first session")
			}
			// Reads while the session runs, which holds the joining lock: under -race they
			// check that ContainerKept takes no lock and races no write.
			done := make(chan struct{})
			read := make(chan struct{})
			go func() {
				defer close(read)
				for {
					r.ContainerKept()
					select {
					case <-done:
						return
					case <-time.After(time.Millisecond):
					}
				}
			}()
			res, err := r.Join(ctx, sp.SessionSpec)
			close(done)
			<-read
			if err != nil {
				t.Fatal(err)
			}
			if got := r.ContainerKept(); got != c.before {
				t.Errorf("ContainerKept before the close %v, want %v", got, c.before)
			}
			closed, err := r.Close(ctx, outcomeOf(res, nil))
			if err != nil {
				t.Fatal(err)
			}
			if got := r.ContainerKept(); got != c.after || got != closed.WallKept {
				t.Errorf("ContainerKept after the close %v, want %v and WallKept %v", got, c.after, closed.WallKept)
			}
		})
	}
}

// TestWallKeptAfterRemoveSetup pins Closed.WallKept and Run.ContainerKept, before and
// after the close, for the setup container: true when RemoveSetup failed, also when a
// later call succeeded, and false when RemoveSetup succeeded and after a setup command
// that failed, where no removal ran. After a start of the setup container that failed,
// RemoveSetup still calls the removal, and a removal that fails there sets both. The
// error of a failed removal matches wall.ErrContainerKept after the run's masker
// replaced a secret in its text.
func TestWallKeptAfterRemoveSetup(t *testing.T) {
	const token = "fake-error-token-0123"
	failure := wall.ContainerKeptError(errors.New("wall docker: docker rm --force: exit status 1: " + token))
	started := errors.New("wall docker: start qory-x-setup: context canceled")
	ctx := context.Background()
	for _, c := range []struct {
		name string
		w    *setupWall
		// removals are the errors RemoveSetup returns, one per call.
		removals []error
		want     bool
	}{
		{name: "the removal succeeded", w: &setupWall{}, removals: []error{nil}, want: false},
		{name: "the removal failed", w: &setupWall{}, removals: []error{failure}, want: true},
		{name: "a later removal succeeded", w: &setupWall{}, removals: []error{failure, nil}, want: true},
		{name: "a setup command failed", w: &setupWall{codes: map[string]int{"make": 2}}, want: false},
		{name: "a start that failed, then a removal", w: &setupWall{startErr: started}, removals: []error{nil}, want: false},
		{name: "a start that failed, then a removal that failed", w: &setupWall{startErr: started}, removals: []error{failure}, want: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			sp.Wall, sp.Image = c.w, "example.com/agent:1"
			sp.Masker = maskerOf(t, token)
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			removeEntry(t, r.ID())
			setupFails := c.w.codes != nil || c.w.startErr != nil
			if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); (err != nil) != setupFails {
				t.Fatalf("the setup: %v", err)
			}
			for _, removal := range c.removals {
				c.w.removeErr = removal
				err := r.RemoveSetup(ctx)
				if (err != nil) != (removal != nil) {
					t.Fatalf("RemoveSetup: %v, want an error: %v", err, removal != nil)
				}
				if err == nil {
					continue
				}
				if !errors.Is(err, wall.ErrContainerKept) {
					t.Errorf("RemoveSetup's error %v does not match wall.ErrContainerKept", err)
				}
				if want := "Close the run: the setup container may still run, so no session can join: wall docker: docker rm --force: exit status 1: ***"; err.Error() != want {
					t.Errorf("RemoveSetup: %v, want %q", err, want)
				}
			}
			if c.w.removes != len(c.removals) {
				t.Errorf("the wall tried %d removals, want %d", c.w.removes, len(c.removals))
			}
			if got := r.ContainerKept(); got != c.want {
				t.Errorf("ContainerKept before the close %v, want %v", got, c.want)
			}
			closed, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1})
			if err != nil {
				t.Fatal(err)
			}
			if closed.WallKept != c.want {
				t.Errorf("WallKept %v, want %v", closed.WallKept, c.want)
			}
			if got := r.ContainerKept(); got != c.want {
				t.Errorf("ContainerKept after the close %v, want %v", got, c.want)
			}
		})
	}
}

// TestWallKeptOnARunTheGatewayClosed pins Closed.WallKept on a run the gateway closed
// with a 410: the close still removes the wall, and a failure there shows.
func TestWallKeptOnARunTheGatewayClosed(t *testing.T) {
	for name, c := range map[string]struct {
		wall wall.Wall
		want bool
	}{
		"nothing failed": {&openWall{}, false},
		"the close failed on a container": {&runCloseFailing{
			enginedWall: enginedWall{engine: leftEngine},
			closeErr:    containerKept("wall docker: docker rm --force: exit status 1"),
		}, true},
		"the close failed on a network alone": {&runCloseFailing{enginedWall: enginedWall{engine: leftEngine}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			sp, g := specGateway(t)
			sleeps(&sp, 30*time.Second)
			sp.StopGrace = time.Second
			sp.Wall, sp.Image = c.wall, "example.com/agent:1"
			reply := *gone("stopped", "cancelled", "no_longer_needed")
			g.OnBatch(func([]map[string]any) linktest.Reply { return reply })
			_, closed, err := runClosed(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			removeEntry(t, closed.RunID)
			if !closed.RunClosed || closed.WallKept != c.want {
				t.Errorf("closed %+v, want RunClosed and WallKept %v", closed, c.want)
			}
		})
	}
}
