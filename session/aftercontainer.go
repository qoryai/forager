package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// afterKillWait is how long After's process group gets between SIGTERM at
// AfterTimeout and SIGKILL: time for git to remove its index.lock.
const afterKillWait = 5 * time.Second

// afterStartWait is how long the session allows the engine to start the After container,
// past AfterTimeout, before it cuts the step off.
const afterStartWait = time.Minute

// afterOutputLimit is how many bytes of the docker command's output the session keeps,
// to show when the container ends with no exit record.
const afterOutputLimit = 4096

// errAfterWindow ends an After that ran past its window.
var errAfterWindow = errors.New("the after step's window")

// afterWindow is how long the session allows After, from the moment the runtime's exit
// is observed: the agent's container's removal, the start of the After container,
// AfterTimeout, the 5 s between SIGTERM and SIGKILL, and the last second of output.
// After a stop from outside, the context's end, it is the stop's grace instead.
var afterWindow = func(timeout time.Duration) time.Duration {
	return timeout + afterKillWait + afterStartWait + setupOutputGrace
}

// afterRun is what the session passes [Run.runAfter].
type afterRun struct {
	ctx, runCtx context.Context
	spec        runSpec
	enclosure   wall.Enclosure
	// unwrapAgent removes the agent's container of the session.
	unwrapAgent func(context.Context) error
	steps       *setupSteps
	// dir and mounts are the launch's, as the enclosure shows them.
	dir    string
	mounts []wall.Mount
	proxy  string
	// words are SessionSpec.After as the enclosure has them.
	words []string
	// grace is the stop grace, which bounds After after a stop from outside.
	grace   time.Duration
	session int
}

// runAfter runs the session's After in a new container, once the runtime exited: it
// removes the agent's container, starts the After container, reads the step's records
// and removes the container. Every failure ends the after step failed, with a line, and
// changes nothing else of the session.
//
// The step starts first, so a failure of the removal or the start is in it. The whole of
// it runs under a context that the caller's end does not cancel, within [afterWindow]; a
// caller's end that comes while it runs cuts the window to the stop grace from then, and
// the run's close cuts it at once, the step then ending cancelled with -1. A window that
// ends the step cancelled with -1, and with reason timeout when no stop from outside came.
func (r *Run) runAfter(a afterRun) {
	steps := a.steps
	wrapper := a.enclosure.(wall.AfterWrapper)
	timeout := a.spec.AfterTimeout
	window := afterWindow(timeout)
	ctx, cancel := context.WithCancelCause(context.WithoutCancel(a.ctx))
	defer cancel(nil)
	deadline := time.Now().Add(window)
	timer := time.AfterFunc(window, func() { cancel(errAfterWindow) })
	defer timer.Stop()
	var outside atomic.Bool
	stopWatch := context.AfterFunc(a.runCtx, func() {
		outside.Store(true)
		if errors.Is(context.Cause(a.runCtx), errRunClosed) {
			cancel(errRunClosed)
			return
		}
		timer.Reset(max(min(time.Until(deadline), a.grace), 0))
	})
	defer stopWatch()

	steps.handle(runtimes.Record{Source: runtimes.SourceAfter, Record: map[string]any{"event": setupStarted}})
	fail := func(text string) {
		steps.handle(runtimes.Record{Source: runtimes.SourceAfter, Record: map[string]any{"event": setupLine, "stream": "stderr", "bytes": encode([]byte(text + "\n")), "runner": true}})
		steps.finish(ctx.Err() != nil)
	}
	if err := a.unwrapAgent(ctx); err != nil {
		fail(fmt.Sprintf("Close the run to remove the agent's container, which may still run.\nAfter did not run: the removal failed: %v.", accesskey.ShownError(err)))
		return
	}
	sock, err := socket.ListenAfter(a.spec.SocketGrace)
	if err != nil {
		fail(fmt.Sprintf("Free space in the temporary directory, or allow writes to it.\nAfter did not run: the socket for its records could not be opened: %v.", err))
		return
	}
	defer sock.Close()
	go sock.ServeFirst(steps.handle, func(err error) { r.open.Report("socket: " + accesskey.ShownError(err).Error()) }, window+setupOutputGrace)
	command, args := afterCommand(a.spec.Exec, afterLaunch{words: a.words, timeout: timeout})
	launch, err := wrapper.WrapAfter(ctx, wall.Launch{
		Command: command, Args: args, Dir: a.dir,
		CA: r.authority, Proxy: a.proxy, ProxyToken: r.relayToken, Socket: sock.Path(),
		Mounts: mountHolding(a.mounts, a.dir), Limits: a.spec.Limits,
	})
	if err != nil {
		fail(fmt.Sprintf("Fix the cause on the next line, then run the session again.\nAfter did not run: its container could not be set up: %v.", accesskey.ShownError(err)))
		return
	}
	defer func() {
		if err := wrapper.UnwrapAfter(context.WithoutCancel(a.ctx)); err != nil {
			r.open.Report("removing the wall: " + accesskey.ShownError(err).Error())
			r.listed.keep()
			r.keptBy = a.session
			r.wallFailed.Store(true)
		}
	}()
	out := &limitedBuffer{limit: afterOutputLimit}
	cmd := exec.Command(launch.Command, launch.Args...)
	cmd.Env, cmd.Dir, cmd.Stdout, cmd.Stderr = launch.Env, launch.Dir, out, out
	if err := cmd.Start(); err != nil {
		fail(fmt.Sprintf("Fix the cause on the next line, then run the session again.\nAfter did not run: its container could not be started: %v.", accesskey.ShownError(err)))
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		// The window ended, or the run was closed: removing the container ends the
		// docker command.
		wrapper.UnwrapAfter(context.WithoutCancel(a.ctx))
		waitErr = <-done
	}
	sock.Close()
	cause := context.Cause(ctx)
	switch {
	case cause == nil:
		if steps.running() {
			text := strings.TrimSpace(out.String())
			if waitErr != nil {
				text = fmt.Sprintf("%v: %s", waitErr, text)
			}
			fail(fmt.Sprintf("Fix what the next line shows, then run the session again.\nAfter's container ended with no exit status for After: %s.", accesskey.ShownValue(text, false)))
		}
	case steps.running():
		reason := ""
		if errors.Is(cause, errAfterWindow) && !outside.Load() {
			reason = afterReasonTimeout
		}
		steps.finishWith(true, reason)
	}
}

// mountHolding returns the mount of mounts that shows dir, the one the After container
// binds: the others, such as the harness home and the run directory, are the agent's.
func mountHolding(mounts []wall.Mount, dir string) []wall.Mount {
	for _, m := range mounts {
		shown := m.Path
		if m.Target != "" {
			shown = m.Target
		}
		if rel, err := filepath.Rel(filepath.Clean(shown), filepath.Clean(dir)); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return []wall.Mount{m}
		}
	}
	return nil
}

// limitedBuffer keeps the first limit bytes written to it and discards the rest.
type limitedBuffer struct {
	mu    sync.Mutex
	limit int
	buf   bytes.Buffer
}

// Write keeps what fits.
func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.limit - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// String returns what was kept.
func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
