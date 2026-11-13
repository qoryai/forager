package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/gateway/internal/stream"
	"github.com/qoryai/forager/sink"
)

// reopenable reports whether a request on the one address for runID, of a run the
// gateway neither holds nor keeps as spent, may reopen it: the gateway has Listen, and
// the run's record has request.json, which only a gateway that keeps its runs writes.
// [Gateway.reopen] checks the rest.
func (g *Gateway) reopenable(runID string) bool {
	if g.svc == nil {
		return false
	}
	_, err := os.Lstat(filepath.Join(g.stream.Dir(runID), requestFile))
	return err == nil
}

// reopenRun reopens the suspended run runID for a request of it whose run key is p, and
// waits for that within ctx. One reopen of a run runs at a time, on the gateway's
// context: a request that comes while it runs waits for the same one. It returns the
// run once it is open; else final is true when the reopen failed for good, and false
// when it is still going, failed in a way that may pass, or the gateway is closing.
func (g *Gateway) reopenRun(ctx context.Context, runID string, p presented) (lr *linkRun, final bool) {
	g.mu.Lock()
	if lr := g.runs[runID]; lr != nil {
		g.mu.Unlock()
		return lr, false
	}
	if g.closing {
		g.mu.Unlock()
		return nil, false
	}
	c := g.reopening[runID]
	if c == nil {
		c = &reopenCall{done: make(chan struct{})}
		g.reopening[runID] = c
		g.reopens.Add(1)
		report := routine.ForRun(g.report, runID)
		routine.Go(report, func() {
			defer g.reopens.Done()
			g.reopen(c, runID, p)
		})
	}
	g.mu.Unlock()
	select {
	case <-c.done:
		return c.lr, c.final
	case <-ctx.Done():
		return nil, false
	}
}

// reopen runs the reopen c of runID and ends it: the run goes into the gateway's runs
// and is armed; a reopen that failed for good leaves the run spent, so its later
// requests are a 410 run_closed with no reopen, for [keepEnded]. Either way c leaves
// the reopens in flight, then its waiters are woken.
func (g *Gateway) reopen(c *reopenCall, runID string, p presented) {
	var lr *linkRun
	final := false
	defer func() {
		g.mu.Lock()
		delete(g.reopening, runID)
		if lr != nil {
			g.runs[runID] = lr
			g.used[runID] = true
		}
		if final {
			g.spent[runID] = spentRun{end: runEnd{code: accesskey.CodeRunClosed, from: accesskey.FromGateway}, until: time.Now().Add(keepEnded)}
		}
		g.mu.Unlock()
		if lr != nil {
			lr.arm()
		}
		c.lr, c.final = lr, final
		close(c.done)
	}()
	var err error
	lr, final, err = g.reopenSteps(runID, p)
	if err != nil {
		how := "it may open at the session's next request"
		if final {
			how = "the run ends"
		}
		g.report(fmt.Sprintf("run %s: reopening it after the gateway's restart failed, %s: %v", runID, how, accesskey.ShownError(err)))
	}
}

// reopenSteps reopens the run runID a gateway with Listen suspended at its stop, in a
// gateway that started again on the same directory, for a request whose run key is p:
//
//  1. the run's stream, from its record ([stream.Stream.Reopen]), which refuses a
//     record not marked answered, one with a final event and one the server stopped;
//  2. what the gateway holds of the run, from the record: the joins of joins.jsonl
//     with the session.started and session.exited the record has, the members given of
//     given.jsonl, run.started's id and time, and the ids numbered;
//  3. the run's attach again, with p and the gateway's instance id, through the tries
//     of an open ([Gateway.attach]); nothing of its answer is written to the record;
//  4. a sink for the run, then each event the server wants and did not accept, sent
//     again in order before any new event;
//  5. and 6. the run decided by request.json and the run configuration of the attach,
//     with fresh values, as an open does ([linkRun.decide]), its proxy ending TLS with
//     the CA of the record's files; the key group passed again when the record has the
//     mark of a passed limit refusal; and the proxy's model key that of the open join;
//  7. the stack proxy when no join is numbered, else the harness credentials closed;
//  8. the members given made again; when none given before equals them, every
//     run.egress waits for the session's policy_applied of them, as a reload's does.
//
// final is true for a failure that does not pass with time: a record that cannot be
// reopened, a run configuration Forager refuses or an attach refused with a code. A
// failure that may pass leaves the record as Suspend leaves it; one that does not
// removes its CA files too.
func (g *Gateway) reopenSteps(runID string, p presented) (lr *linkRun, final bool, err error) {
	if g.client == nil {
		return nil, true, errors.New("the gateway has no server")
	}
	dir := g.stream.Dir(runID)
	req, err := readRequest(dir)
	if err != nil {
		return nil, true, err
	}
	conf, confDigest := g.config()
	re, err := g.stream.Reopen(runID, sink.Target{Types: conf.Events.Types}.Wants)
	if err != nil {
		// A record another process holds may be free at the next request.
		return nil, !errors.Is(err, stream.ErrRunning) && !errors.Is(err, stream.ErrOpen), err
	}
	st := re.Run
	ctx, cancel := context.WithCancel(g.base)
	lr = &linkRun{g: g, id: runID, wall: req.Wall, labels: map[string]string{}, remote: true, st: st, ctx: ctx, cancel: cancel, seen: map[string]bool{}, done: make(chan struct{})}
	fail := func(final bool, err error) (*linkRun, bool, error) {
		lr.release()
		if _, serr := st.Suspend(g.base); serr != nil {
			g.report(fmt.Sprintf("run %s: closing its record: %v", runID, accesskey.ShownError(serr)))
		}
		if final {
			if rerr := proxy.RemoveCA(dir); rerr != nil {
				g.report(fmt.Sprintf("run %s: removing its CA files: %v", runID, rerr))
			}
		}
		cancel()
		return nil, final, err
	}
	joins, _, err := readJoins(dir)
	if err != nil {
		return fail(true, err)
	}
	given, _, err := readGiven(dir)
	if err != nil {
		return fail(true, err)
	}
	if err := lr.rebuild(re.Record, joins, given); err != nil {
		return fail(true, err)
	}

	// The attach's tries end when the gateway's Close starts.
	ask, stopAsk := context.WithCancel(g.stopping)
	defer stopAsk()
	how := opening{remote: true, runKey: p.raw, key: p.key, deadline: g.openDeadline()}
	rc, digest, _, labels, err := g.attach(ask, conf, runID, how)
	if err != nil {
		return fail(ask.Err() == nil && !passing(err), codeless(err))
	}

	lr.mu.Lock()
	lr.registeredAt = time.Now()
	lr.mu.Unlock()
	lr.live = newLive(ctx, g.client, conf, confDigest, runID, g.report)
	lr.live.onConf = g.setConfig
	lr.posts = sink.New(sink.Config{To: g.client, Target: sink.Target{URL: conf.Events.URL, Types: conf.Events.Types}, Spool: dir, Report: g.report,
		OnDigests: lr.live.digests, OnServerEnd: lr.serverEnd})
	lr.live.posts = lr.posts
	if err := st.Deliver(lr.posts); err != nil {
		lr.posts.Close(g.base)
		return fail(true, err)
	}
	for _, l := range re.Owed {
		if !lr.posts.Resend(ask, l.Bytes, l.Sequence) {
			if lr.posts.Stopped() {
				return fail(true, errors.New("the server stopped the run's events"))
			}
			return fail(false, ask.Err())
		}
	}

	ca, err := lr.decide(ctx, decision{wall: req.Wall, narrowing: req.Narrowing, images: req.Images, fetched: &run.Fetched{URL: conf.Run.URL, Digest: digest, Document: rc}, labels: labels},
		func(*run.Run) (*proxy.CA, error) { return proxy.ReadCA(dir) })
	if err != nil {
		var mayPass holdError
		return fail(!errors.As(err, &mayPass), err)
	}
	marked, err := limitMarked(dir)
	if err != nil {
		return fail(true, err)
	}
	if marked {
		// The proxy passed a limit refusal to the session before the stop: the first
		// batch's answer has stop again.
		lr.keys.Pass()
	}
	lr.mu.Lock()
	open := lr.openJoin()
	numbered := len(lr.joins) > 0
	lr.mu.Unlock()
	switch held := lr.r.Held(); {
	case open != nil && open.noKey && held != nil && held.Start != "":
		lr.px.SetNoModelKey()
	case open != nil && open.model != "":
		lr.px.SetModelKey(open.model)
	}
	if numbered {
		// The run's first join request closed the stack proxy.
		lr.r.CloseHarness()
	} else if err := lr.openStack(true, ca); err != nil {
		return fail(true, err)
	}

	lr.mu.Lock()
	// A run with a join numbered gives the members of a join, without the harness's.
	lr.opened = numbered
	n := len(lr.given)
	err = lr.refresh()
	fresh := slices.Clone(lr.given[n:])
	lr.opened = true
	lr.last = time.Now()
	lr.mu.Unlock()
	if err != nil {
		g.report(fmt.Sprintf("run %s: writing its policy members to its record: %v", runID, err))
	}
	if !givenBefore(given, fresh[len(fresh)-1]) {
		// A policy put in force while the gateway was stopped: as a reload's, every
		// run.egress waits for the session's policy_applied of it.
		hold := st.Hold()
		st.Await(hold, appliedIs(fresh[len(fresh)-1]), event.RunEgress)
	}
	return lr, false, nil
}

// givenBefore reports whether the members a are among those given.
func givenBefore(given []map[string]any, a map[string]any) bool {
	return slices.ContainsFunc(given, func(b map[string]any) bool { return reflect.DeepEqual(a, b) })
}

// rebuild sets what the gateway holds of a reopened run from its record, every whole
// event in sequence order, its join decisions and the members given: the joins, with
// their session.started and session.exited; the members given; run.started's id and
// time; and every id numbered, so a batch the session sends again is numbered once.
// A join out of order in joins is an error.
func (lr *linkRun) rebuild(record []stream.Line, joins []keptJoin, given []map[string]any) error {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	for i, k := range joins {
		if k.Session != i+1 {
			return fmt.Errorf("line %d of %s is session %d", i+1, joinsFile, k.Session)
		}
		lr.joins = append(lr.joins, k.join())
	}
	lr.given = given
	for _, l := range record {
		if l.ID != "" {
			lr.seen[l.ID] = true
		}
		switch l.Type {
		case event.RunStarted:
			lr.startedID = l.ID
			lr.startedAt, _ = time.Parse(time.RFC3339Nano, l.Time)
		case event.SessionStarted, event.SessionExited:
			var data map[string]any
			if json.Unmarshal(l.Data, &data) != nil {
				continue
			}
			n := sessionOf(data)
			if n < 1 || n > len(lr.joins) {
				continue
			}
			j := lr.joins[n-1]
			if l.Type == event.SessionExited {
				j.exited = true
				j.reason, _ = data["reason"].(string)
				continue
			}
			j.started = true
			j.startedAt, _ = time.Parse(time.RFC3339Nano, l.Time)
		}
	}
	return nil
}
