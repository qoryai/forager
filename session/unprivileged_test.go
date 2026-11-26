package session_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session"
)

// TestAnUnprivilegedSetupEndsItsWindowAtTheJoin pins a setup with Unprivileged in a run
// with a control plane: the setup container gets no QORY_RUN_API; a join while it runs
// is refused and writes nothing; after RemoveSetup the first join starts the relay again
// with a new token, which the agent's container's launch gets, and a second join does
// not start it again.
func TestAnUnprivilegedSetupEndsItsWindowAtTheJoin(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	hasRunAPI(g)
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.RunID = event.NewRunID()
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands, Unprivileged: true}); err != nil {
		t.Fatal(err)
	}
	if got := entriesOf(w.setup.Env, session.EnvRunAPI); len(got) != 0 {
		t.Errorf("the unprivileged setup container's environment has %v", got)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err == nil || err.Error() != "Call RemoveSetup before the join: the setup container runs with Unprivileged." {
		t.Fatalf("a join beside the unprivileged setup container: %v", err)
	}
	if len(w.restarts) != 0 || w.wrapped {
		t.Fatalf("the refused join restarted the relay %d times, wrapped %v", len(w.restarts), w.wrapped)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if res, err := r.Join(ctx, sp.SessionSpec); err != nil || res.ExitCode != 0 {
			t.Fatalf("a join after RemoveSetup: %v, %+v", err, res)
		}
	}
	if len(w.restarts) != 1 || w.restarts[0] == w.setup.ProxyToken || w.got.ProxyToken != w.restarts[0] {
		t.Errorf("restarts %d; the new token differs from the setup's %v, the agent's launch has it %v", len(w.restarts), w.restarts[0] != w.setup.ProxyToken, w.got.ProxyToken == w.restarts[0])
	}
}

// TestAFailedRestartFailsTheJoin pins a join after an unprivileged setup whose restart of
// the relay fails: the session fails in the wall step with the fix first and the agent's
// container never starts; the next join restarts the relay again and runs.
func TestAFailedRestartFailsTheJoin(t *testing.T) {
	sp, _ := specGateway(t, "FAKE_EXIT=0")
	w := &setupWall{restartErr: errors.New("docker start: told to fail")}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands, Unprivileged: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.RemoveSetup(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := r.Join(ctx, sp.SessionSpec)
	if err == nil || !strings.HasPrefix(err.Error(), "Run the join again, or close the run: the relay did not start again") || w.wrapped {
		t.Fatalf("a join whose restart fails: %v, %+v, wrapped %v", err, res, w.wrapped)
	}
	w.mu.Lock()
	w.restartErr = nil
	w.mu.Unlock()
	if res, err := r.Join(ctx, sp.SessionSpec); err != nil || res.ExitCode != 0 || len(w.restarts) != 2 {
		t.Fatalf("the next join: %v, %+v, %d restarts", err, res, len(w.restarts))
	}
}

// TestAPrivilegedSetupStartsNoRestart pins that a setup without Unprivileged in a run
// with a control plane gets QORY_RUN_API, and that neither it nor the join after it
// starts the relay again: no window opened.
func TestAPrivilegedSetupStartsNoRestart(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	hasRunAPI(g)
	w := &setupWall{}
	sp.Wall, sp.Image = w, "example.com/agent:1"
	sp.RunID = event.NewRunID()
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	if err := r.Setup(ctx, session.SetupSpec{Dir: sp.Dir, Commands: twoCommands}); err != nil {
		t.Fatal(err)
	}
	if got := entriesOf(w.setup.Env, session.EnvRunAPI); len(got) != 1 || got[0] != session.EnvRunAPI+"="+link.RunAPIURL(sp.RunID) {
		t.Errorf("the setup container's environment has %v", got)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	if len(w.restarts) != 0 {
		t.Errorf("the relay started again %d times", len(w.restarts))
	}
}
