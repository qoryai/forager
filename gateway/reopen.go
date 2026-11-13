package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// reopenable reports whether a request on the one address for runID, of a run the
// gateway neither holds nor keeps as spent, may reopen it: the gateway has Listen, and
// the run's record has request.json, which only a gateway that keeps its runs writes.
// [Gateway.reopen] checks the rest. It reads the Config's Listen, not g.svc: a request
// may come before Start sets g.svc.
func (g *Gateway) reopenable(runID string) bool {
	if g.cfg.Listen == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(g.stream.Dir(runID), requestFile))
	return err == nil
}

// reopenRun reopens the suspended run runID for a request of it whose run key is p, and
// waits for that within ctx. One reopen of a run runs at a time, on the gateway's
// context: a request that comes while it runs waits for the same one. It returns the
// run once it is open; else final is true when the reopen failed for good or the run
// is spent, both read with g.mu held, and false when the reopen is still going, failed
// in a way that may pass, the sweep removes the record's files now, or the gateway is
// closing: the start of Close ends the wait at once, whatever ctx allows.
func (g *Gateway) reopenRun(ctx context.Context, runID string, p presented) (lr *linkRun, final bool) {
	g.mu.Lock()
	if lr := g.runs[runID]; lr != nil {
		g.mu.Unlock()
		return lr, false
	}
	g.lapse(time.Now())
	if _, ok := g.spent[runID]; ok {
		// The run ended, or a reopen of it failed for good, since the caller looked.
		g.mu.Unlock()
		return nil, true
	}
	if g.closing || g.sweeping[runID] {
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
	case <-g.openCtx.Done():
		return nil, false
	}
}

// reopen runs the reopen c of runID and ends it: the run goes into the gateway's runs
// and is armed, or, once Close started, suspended at once; a reopen that failed for
// good leaves the run spent, so its later requests are a 410 run_closed with no reopen,
// for [keepEnded]. Either way c leaves the reopens in flight, then its waiters are
// woken.
func (g *Gateway) reopen(c *reopenCall, runID string, p presented) {
	var lr *linkRun
	final := false
	defer func() {
		if lr != nil {
			lr.mu.Lock()
			lr.answering = true
			lr.mu.Unlock()
		}
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
			g.settle(lr)
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
//  1. the run's stream, from its record ([stream.Stream.Reopen]), which fails on a
//     record not marked answered, one with a final event and one the server stopped;
//  2. what the gateway holds of the run, from the record: the joins of joins.jsonl
//     with the session.started and session.exited the record has, the members given of
//     given.jsonl, run.started's id and time, and the ids numbered; and the run's CA,
//     from its files, when the record has them;
//  3. the run's attach again, with p and the gateway's instance id, through the tries
//     of an open ([Gateway.attach]), each failure tried again when [reopenRetried]
//     returns true; nothing of its answer is written to the record;
//  4. a sink for the run, then each event the server wants and did not accept, sent
//     again in order before any new event, within the deadline of the attach's tries;
//  5. and 6. the run decided by request.json and the run configuration of the attach,
//     with fresh values, as an open does ([linkRun.decide]), its proxy ending TLS with
//     the CA of step 2; the key group passed again when the record has the mark of a
//     passed limit refusal; and the proxy's model key that of the open join;
//  7. the stack proxy when no join is numbered, else the harness credentials closed;
//  8. the members given made again; when they differ from the members in force at the
//     suspend ([inForce]), every run.egress waits for the session's policy_applied of
//     them, as a reload's does.
//
// final is true for a failure that does not pass with time ([reopenFinal] for the
// attach): a record that cannot be reopened, a run configuration Forager does not
// accept, or an attach that ends the run. A failure that may pass leaves the record as
// Suspend leaves it; one that does not removes every file kept to reopen it too
// ([stream.RemoveKept]). After a panic past step 1, the run's stream, tools, proxy
// and key reporter are let go of, as for a failure that may pass, and the panic goes
// on.
func (g *Gateway) reopenSteps(runID string, p presented) (lr *linkRun, final bool, err error) {
	dir := g.stream.Dir(runID)
	if g.client == nil {
		return nil, true, g.dropKept(runID, dir, errors.New("the gateway has no server"))
	}
	req, err := readRequest(dir)
	if err != nil {
		return nil, true, g.dropKept(runID, dir, err)
	}
	conf, confDigest := g.config()
	re, err := g.stream.Reopen(runID, sink.Target{Types: conf.Events.Types}.Wants)
	if err != nil {
		if errors.Is(err, stream.ErrRunning) || errors.Is(err, stream.ErrOpen) {
			// A record another process holds may be free at the next request.
			return nil, false, err
		}
		return nil, true, g.dropKept(runID, dir, err)
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
			g.dropKept(runID, dir, nil)
		}
		cancel()
		return nil, final, err
	}
	defer func() {
		if v := recover(); v != nil {
			// The stream, tools, proxy and key reporter go, so the next request may
			// reopen the run; the panic goes on to the reopen's routine, which reports
			// it.
			fail(false, nil)
			panic(v)
		}
	}()
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
	numbered := len(joins) > 0
	// The run's authority, read before the attach, so a record whose CA files do not
	// read back ends the run before the gateway sends Qory Apiary an attach or an event
	// again.
	ca, err := readKeptCA(dir, runID)
	if err != nil {
		return fail(true, err)
	}

	// The attach's tries end when the gateway's Close starts. Only the result of the
	// tries decides: a final refusal keeps its 410, even when Close started after it,
	// and tries that Close cut end in a failure that may pass, a 503.
	ask, stopAsk := context.WithCancel(g.openCtx)
	defer stopAsk()
	how := opening{remote: true, runKey: p.raw, key: p.key, deadline: g.openDeadline(), retry: reopenRetried}
	rc, digest, _, labels, err := g.attach(ask, conf, runID, how)
	if err != nil {
		return fail(reopenFinal(err, ask.Err() != nil), codeless(err))
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
	// The owed events within the deadline of the attach's tries: a server that takes
	// none by then fails the reopen in a way that may pass, so the session's next
	// request tries again.
	resend, stopResend := context.WithDeadline(ask, how.deadline)
	defer stopResend()
	for _, l := range re.Owed {
		if !lr.posts.Resend(resend, l.Bytes, l.Sequence) {
			if lr.posts.Stopped() {
				return fail(true, errors.New("the server stopped the run's events"))
			}
			return fail(false, fmt.Errorf("resending the events Qory Apiary did not accept before the stop: %w", resend.Err()))
		}
	}

	// The steps past the attach end when Close starts too, with ask: a reopen Close cuts
	// fails in a way that may pass, and the record stays for the next gateway.
	ca, err = lr.decide(ctx, ask, decision{wall: req.Wall, narrowing: req.Narrowing, images: req.Images, fetched: &run.Fetched{URL: conf.Run.URL, Digest: digest, Document: rc}, labels: labels},
		func(*run.Run) (*proxy.CA, error) {
			if ca == nil {
				return nil, fmt.Errorf("start a new run: this run needs its certificate authority, and its record has no %s or %s", proxy.CACertFile, proxy.CAKeyFile)
			}
			return ca, nil
		})
	if g.openCtx.Err() != nil {
		return fail(false, closing(err))
	}
	if err != nil {
		var mayPass holdError
		return fail(!errors.As(err, &mayPass), err)
	}
	marked, err := limitMarked(dir)
	if err != nil {
		return fail(true, err)
	}
	if marked && lr.keys != nil {
		// The proxy passed a limit refusal to the session before the stop: the first
		// batch's answer has stop again. A run configuration with no key group now has
		// no key to stop.
		lr.keys.Pass()
	}
	lr.mu.Lock()
	open := lr.openJoin()
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
	fresh := lr.refresh()
	lr.opened = true
	lr.last = time.Now()
	lr.mu.Unlock()
	if err := lr.keep(fresh); err != nil {
		g.report(fmt.Sprintf("run %s: writing its policy members to its record: %v", runID, err))
	}
	if now := fresh[len(fresh)-1]; !reflect.DeepEqual(inForce(given, numbered), now) {
		// A policy put in force while the gateway was stopped: as a reload's, every
		// run.egress waits for the session's policy_applied of it.
		hold := st.Hold()
		st.Await(hold, appliedIs(now), event.RunEgress)
	}
	return lr, false, nil
}

// dropKept removes the files kept to reopen a run from the record dir of the run
// runID, whose reopen failed for good ([stream.RemoveKept]), reports a removal that
// fails, and returns err.
func (g *Gateway) dropKept(runID, dir string, err error) error {
	if rerr := stream.RemoveKept(dir); rerr != nil {
		g.report(keptNotRemoved(runID, dir, rerr))
	}
	return err
}

// readKeptCA reads the CA of the run runID from its record dir ([proxy.ReadCA]); nil
// when the record has neither of its files, a run whose policy needed no CA at its open.
func readKeptCA(dir, runID string) (*proxy.CA, error) {
	kept, err := newestOf(dir, proxy.CACertFile, proxy.CAKeyFile)
	if err != nil {
		return nil, accesskey.ShownError(err)
	}
	if kept.IsZero() {
		return nil, nil
	}
	return proxy.ReadCA(dir, runID)
}

// inForce are the members of dev.qory.run.policy_applied in force at the run's
// suspend, of those given in order: the last, or, when a join is numbered, the last
// without a harness credential, since a join's members list none. nil for none.
func inForce(given []map[string]any, numbered bool) map[string]any {
	for i := len(given) - 1; i >= 0; i-- {
		if !numbered || !hasHarness(given[i]) {
			return given[i]
		}
	}
	return nil
}

// hasHarness reports whether the members a list a harness credential.
func hasHarness(a map[string]any) bool {
	listed, _ := a["credentials"].([]any)
	return slices.ContainsFunc(listed, func(c any) bool {
		m, _ := c.(map[string]any)
		return m["purpose"] == server.PurposeHarness
	})
}

// codeWorkspaceNotServed is Qory Apiary's refusal of an attach of a run whose workspace
// the gateway does not serve.
const codeWorkspaceNotServed = "workspace_not_served"

// The codes of a signed refusal of a reopen's attach that end the run at once, beside
// a signed 410: the run is attached at another gateway's address, the run key is for
// another gateway, or the gateway no longer serves the run's workspace.
var reopenEndCodes = []string{codeRunAttached, codeWrongGateway, codeWorkspaceNotServed}

// reopenRetried reports whether a failed try of a reopen's attach is tried again
// within the tries' window: every failure but those [endsReopen] reports.
func reopenRetried(err error) bool { return !endsReopen(err) }

// reopenFinal reports whether the attach of a reopen failed for good with err once its
// tries ended, cut when Close cut them. The rule, which the README's restart paragraph
// states too:
//
//   - final at once: a signed 410, with a code or none; a signed refusal with a code
//     of reopenEndCodes; and a run configuration Forager does not accept;
//   - any other signed 4xx is tried again within the tries' window, and is final when
//     the window ends on it; a 429 rate_limited is not final;
//   - a 5xx, an answer that is not signed, and a failure with no answer are never
//     final: the request gets a 503, and the session's next request tries again.
func reopenFinal(err error, cut bool) bool {
	return endsReopen(err) || (!cut && signed4xx(err))
}

// endsReopen reports whether err, a failed try of a reopen's attach, ends the run at
// once: a signed 410, a signed refusal with a code of reopenEndCodes, or a run
// configuration Forager does not accept.
func endsReopen(err error) bool {
	var document *server.DocumentError
	var ref *accesskey.Refusal
	var uncoded *server.AnswerError
	switch {
	case errors.As(err, &document):
		return true
	case errors.As(err, &ref):
		return ref.Code != accesskey.CodeAnswerUnsigned && (ref.Status == http.StatusGone || slices.Contains(reopenEndCodes, ref.Code))
	case errors.As(err, &uncoded):
		return uncoded.Status == http.StatusGone
	case errors.Is(err, server.ErrNotAccepted):
		// A signed 410 to the attach.
		return true
	}
	return false
}

// signed4xx reports whether err is a signed 4xx other than a 429 rate_limited, with a
// code or none. A 401 counts, whether signed or not.
func signed4xx(err error) bool {
	var ref *accesskey.Refusal
	var uncoded *server.AnswerError
	switch {
	case errors.As(err, &ref):
		return ref.Code != accesskey.CodeAnswerUnsigned && ref.Status >= 400 && ref.Status < 500 && ref.Code != accesskey.CodeRateLimited
	case errors.As(err, &uncoded):
		return uncoded.Status >= 400 && uncoded.Status < 500
	}
	return false
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
