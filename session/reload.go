package session

import (
	"context"
	"errors"
	"sync"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
)

// reloader keeps the run's policy current from the run-configuration digests its
// gateway's answers carry: a digest other than the one the run holds means the gateway
// has put another configuration in force, which the session fetches with the link's
// reload and records. The gateway has applied it already; the session decides none of
// it. One reload runs at a time; digests that arrive during one are coalesced into the
// next pass.
type reloader struct {
	link          *server.Link
	runURL, runID string
	report        func(string)
	// answered is the run-configuration digest of the link's last answer to a reload.
	answered func() string
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	mu sync.Mutex
	// held is the digest of the run configuration the run holds: the run answer's, then
	// each reload's.
	held string
	// want is what the gateway's answers last said is in force.
	want string
	// tried is the digest that last led to a reload the gateway refused: it is not asked
	// for again until the answers change.
	tried string
	// apply records a reload's answer and the digest the run now holds; ended ends the
	// run on a 410; both nil until the run has started.
	apply          func(*server.LinkReloadAnswer, string)
	ended          func(server.RunEnd)
	running, dirty bool
}

// newReloader returns the reload of a run that holds the run configuration of digest
// held.
func newReloader(ctx context.Context, k *server.Link, runURL, runID, held string, answered func() string, report func(string)) *reloader {
	l := &reloader{link: k, runURL: runURL, runID: runID, held: held, answered: answered, report: report}
	l.ctx, l.cancel = context.WithCancel(ctx)
	return l
}

// start arms the reload with what records an answer and what ends the run, once the
// run has started.
func (l *reloader) start(apply func(a *server.LinkReloadAnswer, held string), ended func(server.RunEnd)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.apply, l.ended = apply, ended
	l.kick()
}

// digests takes what an answer said is in force, on the sink's goroutine, and
// schedules a reload when it differs from what the run holds. A digest an answer did
// not carry means nothing.
func (l *reloader) digests(d server.Digests) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if d.RunConfiguration != "" {
		l.want = d.RunConfiguration
	}
	l.kick()
}

// kick starts the reload loop when something differs and none runs, or marks a
// running one to go again. Called with the lock held.
func (l *reloader) kick() {
	if l.apply == nil || l.ctx.Err() != nil || !l.stale() {
		return
	}
	if l.running {
		l.dirty = true
		return
	}
	l.running = true
	l.wg.Add(1)
	go l.loop()
}

// stale reports whether what the gateway said is in force differs from what the run
// holds. Called with the lock held.
func (l *reloader) stale() bool {
	return l.want != "" && l.want != l.held && l.want != l.tried
}

// loop runs passes until nothing is marked dirty or the run ends.
func (l *reloader) loop() {
	defer l.wg.Done()
	for {
		l.pass()
		l.mu.Lock()
		if !l.dirty || l.ctx.Err() != nil {
			l.running = false
			l.mu.Unlock()
			return
		}
		l.dirty = false
		l.mu.Unlock()
	}
}

// pass fetches the run's configuration when it differs from what the run holds, and
// records it. A 410 ends the run. A refusal with a code is the gateway's, which told
// the user itself, and is not asked for again until the digest changes; a reload the
// gateway did not answer is reported and asked for again on the next answer.
func (l *reloader) pass() {
	l.mu.Lock()
	if !l.stale() {
		l.mu.Unlock()
		return
	}
	want, apply, ended := l.want, l.apply, l.ended
	l.mu.Unlock()
	a, err := l.link.Reload(l.ctx, l.runURL, l.runID)
	if err != nil {
		if e, ok := server.Ended(err); ok {
			ended(e)
			return
		}
		var r *accesskey.Refusal
		if errors.As(err, &r) {
			l.mu.Lock()
			l.tried = want
			l.mu.Unlock()
			return
		}
		if l.ctx.Err() == nil {
			l.report("the reload failed: " + err.Error())
		}
		return
	}
	held := l.answered()
	if held == "" {
		held = want
	}
	l.mu.Lock()
	if l.ctx.Err() != nil {
		l.mu.Unlock()
		return
	}
	l.held = held
	l.mu.Unlock()
	apply(a, held)
}

// stop ends the reload: no pass starts after it, and one in flight is cancelled and
// waited for. It may be called more than once.
func (l *reloader) stop() {
	l.mu.Lock()
	l.cancel()
	l.mu.Unlock()
	l.wg.Wait()
}
