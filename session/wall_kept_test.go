package session_test

import (
	"context"
	"errors"
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
// close that succeeded, and true when the close failed on a container. A close that
// failed on a network alone leaves it false and reports the failure, as every failed
// close does.
func TestWallKeptAfterASession(t *testing.T) {
	failure := errors.New("wall docker: rm: exit status 1")
	const container = "wall docker: docker rm --force: exit status 1"
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
				errors.New("wall docker: network rm: exit status 1"), containerKept(container))},
			true, "removing the wall: wall docker: network rm: exit status 1\n" + container,
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

// TestWallKeptAfterRemoveSetup pins Closed.WallKept for the setup container: true when
// RemoveSetup failed, also when a later call succeeded, and false when RemoveSetup
// succeeded and after a setup command that failed, where no removal ran.
func TestWallKeptAfterRemoveSetup(t *testing.T) {
	failure := errors.New("wall docker: docker rm --force: exit status 1")
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
	} {
		t.Run(c.name, func(t *testing.T) {
			sp := spec(t, "FAKE_EXIT=0")
			sp.Wall, sp.Image = c.w, "example.com/agent:1"
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			removeEntry(t, r.ID())
			if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands[:1]}); (err != nil) != (c.w.codes != nil) {
				t.Fatalf("the setup: %v", err)
			}
			for _, removal := range c.removals {
				c.w.removeErr = removal
				if err := r.RemoveSetup(ctx); (err != nil) != (removal != nil) {
					t.Fatalf("RemoveSetup: %v, want an error: %v", err, removal != nil)
				}
			}
			if c.w.removes != len(c.removals) {
				t.Errorf("the wall tried %d removals, want %d", c.w.removes, len(c.removals))
			}
			closed, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1})
			if err != nil {
				t.Fatal(err)
			}
			if closed.WallKept != c.want {
				t.Errorf("WallKept %v, want %v", closed.WallKept, c.want)
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
