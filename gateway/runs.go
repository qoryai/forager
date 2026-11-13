package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/gateway/internal/stream"
	"github.com/qoryai/forager/gateway/internal/tool"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/sink"
)

// linkRun is one run a session opened on the link: what the gateway holds for it, and
// how it stands.
type linkRun struct {
	g      *Gateway
	id     string
	wall   bool
	labels map[string]string
	r      *run.Run
	st     *stream.Run
	px     *proxy.Proxy
	// keys is the run's key group, nil when the run has none: the start key's, from the
	// run configuration's credentials.
	keys *modelkey.Group
	// secret is the run's proxy secret, held so that no print of the run shows it.
	secret secretValue
	tools  *tool.Set
	posts  *sink.Server
	live   *live
	ctx    context.Context
	cancel context.CancelFunc

	// remote says the run opened on the one address, by its run key, which names it in
	// every request of the run; it has no proxy secret.
	remote bool

	// stack is the run's stack proxy, and stackSecret its secret on the local link, held
	// so that no print of the run shows it; both nil from the run's first join request
	// on, under mu ([linkRun.closeStack]).
	stack       *proxy.Proxy
	stackSecret secretValue

	// batch takes one batch of the session's at a time.
	batch sync.Mutex
	// joining takes one join, or one reload's decision and commit, at a time, so a
	// join's passes are checked against the placeholders of the policy in force and a
	// reload against the passes of every open join.
	joining sync.Mutex

	mu sync.Mutex
	// opened says the run answer is made.
	opened bool
	// registeredAt is when the server accepted the run's registration, zero without a
	// server: its heartbeats count from then.
	registeredAt time.Time
	// seen are the ids of the session's events numbered so far; startedID is its
	// run.started's, startedAt that event's time; final says its run.exited or
	// run.refused is numbered.
	seen      map[string]bool
	startedID string
	startedAt time.Time
	final     bool
	// joins are the run's joins the gateway answered 200 or 403, by their session
	// numbers, from 1, in the order they arrived.
	joins []*join
	// given are the members of dev.qory.run.policy_applied the gateway decides, for each
	// policy it put in force for the run, as the answers carry them.
	given []map[string]any
	// reloadBody is the reload answer as it stands, and reloadDigest its digest, the
	// X-Qory-Run-Configuration of every answer for the run.
	reloadBody   []byte
	reloadDigest string
	// answer is the run answer, made once; it contains the proxy secret and the stack
	// proxy secret, so no print of the run shows it.
	answer secretValue
	// last is when the session last asked anything of the run; timer ends the run when
	// it asks nothing for the gateway's quiet time.
	last  time.Time
	timer *time.Timer
	// ended says the run ended at the gateway: how is its 410, and the state and the
	// reason of the gateway's dev.qory.run.exited of it, and closed says it was not the
	// session that ended it.
	ended  bool
	how    runEnd
	closed bool
	// discarded says the run's session gave up before it had the run answer: the run
	// ends as if it never opened, [Gateway.discard].
	discarded bool
	// suspended is true once the gateway's Close suspended the run ([linkRun.suspend]):
	// it does not end here, and a gateway that starts again reopens it.
	suspended bool

	// done is closed once the run's gateway side is over and its stream flushed; result
	// and err are then set.
	done   chan struct{}
	result stream.Result
	err    error
}

// ending is how a run ends at the gateway.
type ending struct {
	// reason is the reason of the dev.qory.run.exited the gateway writes, empty for none,
	// and state its state: succeeded, failed or cancelled.
	reason, state string
	// code and from are the 410 the session's later requests get.
	code, from string
	// closed says the run ended before its session ended it.
	closed bool
	// keep is true for the end of [Gateway.Close]: the run's record keeps its CA files,
	// so a gateway that starts again on its directory can reopen the run. Every other
	// end removes them on the one address.
	keep bool
}

// gatewayClosed ends a run as [Gateway.Close] does: no run.exited, a 410 run_closed to
// its later requests, and its CA files kept.
var gatewayClosed = ending{code: accesskey.CodeRunClosed, from: accesskey.FromGateway, keep: true}

// runEnd is how a run ended at the gateway, as its later requests learn it: the code and
// the from of its 410, and the state and the reason of the gateway's
// dev.qory.run.exited of it, the state empty for an end that writes none, run_closed,
// and the reason for one without a reason.
type runEnd struct {
	code, from, state, reason string
}

// sessionLost ends a run whose session the gateway no longer hears: its later requests
// are a 410 session_lost.
var sessionLost = ending{reason: event.ReasonSessionLost, state: stateFailed, code: event.ReasonSessionLost, from: accesskey.FromGateway, closed: true}

// sessionGone ends a run whose session gave up before it had the run answer: nothing
// more is written of it.
var sessionGone = ending{code: event.ReasonSessionLost, from: accesskey.FromGateway}

// batchRefused ends a run whose session's batch the gateway refused, failed: its record
// says batch_refused, and its later requests are a 410 batch_refused.
var batchRefused = ending{reason: event.ReasonBatchRefused, state: stateFailed, code: event.ReasonBatchRefused, from: accesskey.FromGateway, closed: true}

// stoppedBy ends a run with the outcome its starter gave, as the server's end member
// brings it: its record's dev.qory.run.exited has the outcome's state and reason, and
// its later requests are a 410 stopped carrying them. An end cancelled with no reason,
// the run's starter ending it with no outcome, has the reason stopped.
func stoppedBy(end server.ServerEnd) ending {
	reason := end.Reason
	if end.State == event.StateCancelled && reason == "" {
		reason = event.ReasonStopped
	}
	return ending{reason: reason, state: end.State, code: event.ReasonStopped, from: accesskey.FromGateway, closed: true}
}

// runEnd is how the ending answers the run's later requests.
func (e ending) runEnd() runEnd {
	return runEnd{code: e.code, from: e.from, state: e.state, reason: e.reason}
}

// The states of the dev.qory.run.exited the gateway writes.
const stateFailed = event.StateFailed

// reasonWords are the words a person reads of Forager's own reasons of
// dev.qory.run.exited where a line says how a run ended, those Qory Apiary shows; any
// other reason is the run's starter's, read with spaces for its underscores.
var reasonWords = map[string]string{
	event.ReasonTimeout:      "time limit reached",
	event.ReasonStopped:      "no outcome given",
	event.ReasonSessionLost:  "stopped responding",
	event.ReasonGatewayLost:  "end not recorded",
	event.ReasonBatchRefused: "events refused",
}

// endWords is how a line says a run ended: the state, and the reason's words after a
// comma when it has one.
func endWords(end runEnd) string {
	if end.reason == "" {
		return end.state
	}
	words, ok := reasonWords[end.reason]
	if !ok {
		words = strings.ReplaceAll(end.reason, "_", " ")
	}
	return end.state + ", " + words
}

// opening is how a run opens: on the local link, or on the one address with the run
// key of its request.
type opening struct {
	// remote says the request came to the gateway's one address, whose runs' proxies
	// are guarded whatever their wall, and which the gateway attaches at the server.
	remote bool
	// runKey is the run key of the request on the one address, as it came, which the
	// attach carries, and key what it verified to; empty on the local link.
	runKey string
	key    runkey.Key
	// request, when not nil, is the context of the session's run request: once it ends,
	// the session no longer waits for its answer, and the run does not open.
	request context.Context
	// deadline is the latest a try of the run's registration with Qory Apiary may start
	// again: [openWindow] after the run request came.
	deadline time.Time
	// retry reports whether a failed try of the attach is tried again; nil is
	// [passing]. A reopen sets [reopenRetried].
	retry func(error) bool
}

// The tries of the run's registration with Qory Apiary, or its attach, as a run opens:
// the waits between them are openWaits, the last of them repeated, each counted from
// the end of the try before, and a try starts again only within openWindow of the run
// request's arrival. A Qory Apiary that restarts within those 120 seconds therefore
// registers the run once it is back. The last try may start just before the window
// ends and has [server.Timeout] for its answer, which leaves 10 seconds of
// [server.OpenWait] for the rest of the open. Those 10 seconds do not cover every open.
// Behind a separate gateway, a run with credentials after a late attach makes its
// reload, which shares the window and then gets one try, and its secrets request, up
// to [server.Timeout] each, so its open may take about 150 seconds and the start of
// its tools. On the local link, a run that requests its secrets after a late
// registration may take 140 seconds and the start of its tools. Either passes the
// session's wait.
var (
	openWaits  = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second}
	openWindow = 120 * time.Second
)

// openDeadline is the deadline of a run's open that starts now.
func (g *Gateway) openDeadline() time.Time {
	window := openWindow
	if g.cfg.openWindow != 0 {
		window = g.cfg.openWindow
	}
	return time.Now().Add(window)
}

// passing reports whether a failure to ask Qory Apiary as a run opens may pass, and is
// asked again: no answer, a 5xx, signed or not, and a signed 429 rate_limited. A
// refusal with any other code, a signed answer with another status and no code, a
// signed 410 to the registration whatever its code, and a document Forager refuses are
// final.
func passing(err error) bool {
	var document *server.DocumentError
	var ref *accesskey.Refusal
	var uncoded *server.AnswerError
	switch {
	case errors.As(err, &document):
		return false
	case errors.As(err, &ref):
		return ref.Status >= 500 || (ref.From == accesskey.FromApiary && ref.Code == accesskey.CodeRateLimited)
	case errors.As(err, &uncoded):
		return uncoded.Status >= 500
	case errors.Is(err, server.ErrNotAccepted):
		// A signed 410 to the registration: the server takes no run here.
		return false
	}
	return true
}

// errClosing is the failure of a run whose tries of Qory Apiary Close stopped: the run
// did not open, and its run request gets a 503.
var errClosing = errors.New("the gateway closes")

// stoppedByClose reports whether the tries of a run's registration or attach ended with
// err because Close stopped them: err is a failure, Close started, the session's run
// request is there, nil being one that is, and err is a failure the tries would have
// tried again. A final refusal that came before Close keeps its answer. Only the
// result of the tries is judged so; a failure after them is no stop by Close.
func stoppedByClose(request, opens context.Context, err error) bool {
	return err != nil && (request == nil || request.Err() == nil) && opens != nil && opens.Err() != nil && passing(err)
}

// closing is err as the failure of a run whose tries Close stopped.
func closing(err error) error {
	if err == nil {
		return errClosing
	}
	return fmt.Errorf("%w: %w", errClosing, err)
}

// openClock is how the tries of a run's open read the time and wait: now, and wait,
// which returns false when ctx ends first.
type openClock struct {
	now  func() time.Time
	wait func(ctx context.Context, d time.Duration) bool
}

// wallClock is the clock of the tries outside tests.
var wallClock = openClock{now: time.Now, wait: func(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}}

// tries asks Qory Apiary with ask, again after a failure for which retry returns true,
// [passing] when retry is nil, [openWaits] apart, until a try returns a final result,
// the next try would start past deadline, or ctx ends; the last try's error is the
// result.
func (g *Gateway) tries(ctx context.Context, deadline time.Time, retry func(error) bool, ask func() error) error {
	waits := openWaits
	if g.cfg.openWaits != nil {
		waits = g.cfg.openWaits
	}
	if retry == nil {
		retry = passing
	}
	return tryOpen(ctx, wallClock, waits, deadline, retry, ask)
}

// tryOpen is [Gateway.tries] with the clock and the waits: the wait after try n+1 is
// waits[n], or the last of waits once they run out.
func tryOpen(ctx context.Context, clock openClock, waits []time.Duration, deadline time.Time, retry func(error) bool, ask func() error) error {
	for n := 0; ; n++ {
		err := ask()
		if err == nil || !retry(err) || len(waits) == 0 || ctx.Err() != nil {
			return err
		}
		wait := waits[min(n, len(waits)-1)]
		if clock.now().Add(wait).After(deadline) || !clock.wait(ctx, wait) {
			return err
		}
	}
}

// open opens a run for a request the link accepted: with a server, the run's
// registration, or on the one address its attach, whose answer is its run
// configuration, the policy in force, the credentials and the tools, the run's proxy,
// under a fresh secret on the local link, and its record. On the one address its proxy
// is guarded whatever its wall, and a record of the run whose session never got its run
// answer, of a gateway that stopped as it opened, is removed first, so the run
// attaches again ([stream.Stream.Reclaim]). A refusal is an [*accesskey.Refusal];
// recorded says the run's record was made, so its id is used from now on.
func (g *Gateway) open(req *server.LinkRunRequest, how opening) (lr *linkRun, recorded bool, err error) {
	remote := how.remote
	if remote {
		if _, err := g.stream.Reclaim(req.RunID); err != nil {
			return nil, false, err
		}
	}
	st, err := g.stream.Open(req.RunID)
	if err != nil {
		return nil, false, err
	}
	ctx, cancel := context.WithCancel(g.base)
	labels := maps.Clone(req.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	lr = &linkRun{g: g, id: req.RunID, wall: req.Wall, labels: labels, remote: remote, st: st, ctx: ctx, cancel: cancel, seen: map[string]bool{}, done: make(chan struct{})}
	fail := func(err error) (*linkRun, bool, error) {
		lr.release()
		err = codeless(err)
		if _, cerr := st.Close(g.base); cerr != nil {
			g.report(fmt.Sprintf("run %s: closing its record: %v", req.RunID, accesskey.ShownError(cerr)))
		}
		if remote {
			// A run that did not open is never reopened: its CA key and run request go
			// from the disk.
			if rerr := stream.RemoveKept(st.Dir()); rerr != nil {
				g.report(fmt.Sprintf("run %s: removing its CA files and run request: %v", req.RunID, rerr))
			}
		}
		cancel()
		return nil, true, err
	}
	// ask is the context of the run's registration or attach: it ends when the
	// gateway's Close starts, so Close does not wait for the tries.
	ask, stopAsk := context.WithCancel(ctx)
	defer stopAsk()
	defer context.AfterFunc(g.openCtx, stopAsk)()
	if how.request != nil {
		// Once the session's run request goes, or Close stops the tries of the run's
		// registration, the run does not open: nothing more is written of it, and what
		// its stream wrote goes too, so a retry of the run id opens.
		failed := fail
		fail = func(err error) (*linkRun, bool, error) {
			gone := how.request.Err()
			if errors.Is(err, errClosing) {
				gone = errClosing
			}
			if gone == nil {
				return failed(err)
			}
			if err == nil {
				// No failure comes without an error now; should one, the session's going
				// is the error, so no caller takes the missing run for one that opened.
				err = gone
			}
			lr.release()
			if derr := st.Discard(g.base); derr != nil {
				g.report(fmt.Sprintf("run %s: closing its record: %v", req.RunID, accesskey.ShownError(derr)))
			}
			cancel()
			return nil, false, err
		}
		defer context.AfterFunc(how.request, stopAsk)()
	}
	var fetched *run.Fetched
	// decideLabels are the labels the run is decided by: on the one address, those the
	// attach's answer gives back of the starter's registration, which the run's selection
	// takes its arguments from.
	decideLabels := labels
	if g.client != nil {
		conf, confDigest := g.config()
		var rc *server.RunConfiguration
		var digest string
		var regErr error
		// The record's first line: the registration the server accepted, never posted.
		var registered map[string]any
		if remote {
			rc, digest, registered, decideLabels, regErr = g.attach(ask, conf, req.RunID, how)
			var accepted *server.DocumentError
			if registered == nil || (regErr != nil && !errors.As(regErr, &accepted)) {
				// The run never attached: nothing of it is kept, so a later run request
				// attaches it again, which the server answers alike for the same gateway.
				lr.release()
				if derr := st.Discard(g.base); derr != nil {
					g.report(fmt.Sprintf("run %s: closing its record: %v", req.RunID, accesskey.ShownError(derr)))
				}
				cancel()
				if stoppedByClose(how.request, g.openCtx, regErr) {
					return nil, false, closing(codeless(regErr))
				}
				return nil, false, codeless(regErr)
			}
		} else {
			// The registration: built once, so every try sends the same bytes, its time
			// included, which Qory Apiary answers alike. Its answer is the run's run
			// configuration: its policy, narrowed by the node's, or the node's own when it
			// has none, and its variables.
			reg := server.Registration{
				Version: 1, RunID: req.RunID, Labels: labels, About: server.ReportedAbout(req.About),
				ForagerVersion: g.cfg.Version, ContractVersion: server.Revision, IntervalSeconds: g.interval, Events: conf.Events.Types,
				Time: server.RegistrationTime(time.Now()),
			}
			body, err := g.registration(reg)
			if err != nil {
				return fail(err)
			}
			regErr = g.tries(ask, how.deadline, nil, func() (err error) {
				rc, digest, err = g.client.Register(ask, conf.Run.URL, body)
				return err
			})
			if stoppedByClose(how.request, g.openCtx, regErr) {
				regErr = closing(regErr)
			}
			// A gateway's key has no workspaces: a conforming server refuses its direct
			// registration, and an acceptance fails run.registered's schema, not the
			// gateway.
			ws := ""
			if len(conf.Workspaces) == 1 {
				ws = conf.Workspaces[0]
			}
			registered = map[string]any{"workspace": ws, "node_id": conf.NodeID, "instance_id": g.client.InstanceID, "forager_version": reg.ForagerVersion, "events": reg.Events, "contract_version": reg.ContractVersion, "interval_seconds": reg.IntervalSeconds}
		}
		// A signed 200 whose run configuration Forager refuses is a registration the
		// server accepted: the record gets its run.registered, then the run is refused
		// without a code, so no run.refused is written and nothing of the refusal reaches
		// the server.
		var refusedDocument *server.DocumentError
		if regErr != nil && !errors.As(regErr, &refusedDocument) {
			return fail(regErr)
		}
		lr.mu.Lock()
		lr.registeredAt = time.Now()
		lr.mu.Unlock()
		if _, err := st.Registered(registered); err != nil {
			return fail(err)
		}
		lr.live = newLive(ctx, g.client, conf, confDigest, req.RunID, g.report)
		lr.live.onConf = g.setConfig
		lr.posts = sink.New(sink.Config{To: g.client, Target: sink.Target{URL: conf.Events.URL, Types: conf.Events.Types}, Spool: st.Dir(), Report: g.report,
			OnDigests: lr.live.digests, OnServerEnd: lr.serverEnd})
		lr.live.posts = lr.posts
		if err := st.Deliver(lr.posts); err != nil {
			lr.posts.Close(g.base)
			return fail(err)
		}
		if regErr != nil {
			return fail(regErr)
		}
		fetched = &run.Fetched{URL: conf.Run.URL, Digest: digest, Document: rc}
	}
	if how.request != nil && how.request.Err() != nil {
		return fail(how.request.Err())
	}
	var ca *proxy.CA
	ca, err = lr.decide(ctx, decision{wall: req.Wall, narrowing: req.Narrowing, images: req.Images, fetched: fetched, labels: decideLabels}, func(*run.Run) (*proxy.CA, error) {
		ca, err := proxy.NewCA(req.RunID)
		if err != nil || !remote {
			return ca, err
		}
		// The authority's files, read back by a gateway that starts again; removed at
		// the run's end ([linkRun.end]).
		if err := ca.Write(st.Dir()); err != nil {
			return nil, fmt.Errorf("run %s: writing its CA to its record: %w", req.RunID, err)
		}
		return ca, nil
	})
	if err != nil {
		return fail(err)
	}
	if remote {
		// What Decide read of the run request, for a gateway that starts again.
		if err := writeRequest(st.Dir(), req); err != nil {
			return fail(fmt.Errorf("run %s: writing its run request to its record: %w", req.RunID, err))
		}
	}
	var authority []byte
	if ca != nil {
		authority = ca.PEM()
	}
	if !remote {
		// On the one address the run key opens the run's proxy, bound to its connection.
		secret, err := proxy.NewSecret()
		if err != nil {
			return fail(err)
		}
		lr.secret = newSecretValue(secret)
		if err := g.proxies.Register(secret, lr.px); err != nil {
			return fail(err)
		}
	}
	if err := lr.openStack(req.Wall || remote, ca); err != nil {
		return fail(err)
	}
	lr.mu.Lock()
	given := lr.refresh()
	lr.opened = true
	lr.last = time.Now()
	lr.mu.Unlock()
	if err := lr.keep(given); err != nil {
		return fail(fmt.Errorf("run %s: writing its policy members to its record: %w", req.RunID, err))
	}
	lr.mu.Lock()
	lr.answer = newSecretValue(string(lr.runAnswer(authority)))
	lr.mu.Unlock()
	return lr, true, nil
}

// decision is what a run is decided by besides the gateway's configuration: the run
// request's wall, narrowing and images, the run configuration the server answered, nil
// with no server, and the labels the run is decided by.
type decision struct {
	wall      bool
	narrowing *server.LinkNarrowing
	images    *server.LinkImages
	fetched   *run.Fetched
	labels    map[string]string
	// revoked are the model keys a reopened run's record has out after a 401
	// ([run.Config.Revoked]); nil for an open.
	revoked []string
}

// holdError is a failure of [run.Run.Hold] that may pass: a fetch of the run's values
// from the server that no answer refused.
type holdError struct{ error }

func (e holdError) Unwrap() error { return e.error }

// decide decides the run by d and starts what the gateway holds of it, for an open and
// for a reopen alike: the run's values ([run.Run.Hold], whose failure that may pass is a
// [holdError]), its tools, its proxy, guarded on a wall or the one address, with the
// run API, its limits and the node's path rules; the run's authority from authority,
// called when the run's policy needs one, which the proxy ends TLS with; the start key;
// and the key group, which on the one address keeps the mark of a passed limit refusal
// in the run's record ([markLimit]). It returns the authority, nil for none. ctx is the
// run's: the tools stop when it ends.
func (lr *linkRun) decide(ctx context.Context, d decision, authority func(*run.Run) (*proxy.CA, error)) (*proxy.CA, error) {
	g := lr.g
	var selects []run.Selection
	if lr.remote {
		// The gateway's selection is for a run that attached with a run key alone.
		selects = g.cfg.Selects
	}
	var secrets func(context.Context, string, []string, []string) (sealed.Values, error)
	if g.client != nil {
		secrets = g.secrets(lr.id)
	}
	r, err := run.Decide(run.Config{
		RunID: lr.id, Node: g.cfg.Policy, Server: g.client != nil, Fetched: d.fetched, Labels: d.labels, Wall: d.wall,
		Credentials: g.cfg.Credentials, Tools: g.cfg.Tools, Selects: selects, Images: images(d.images), Passes: lr.passing, Report: g.report,
		Narrowing: narrowingOf(d.narrowing), Secrets: secrets, Log: lr.logLine, Clock: g.cfg.renewClock, StackHosts: g.cfg.StackHosts,
		Revoked: d.revoked,
	})
	if err != nil {
		return nil, err
	}
	lr.r = r
	if lr.live != nil {
		lr.live.read = r.Read
		lr.live.holds(r.RunConfiguration())
		lr.posts.SetRunDigest(r.RunConfiguration())
	}
	if err := r.Hold(ctx); err != nil {
		if passing(err) {
			return nil, holdError{err}
		}
		return nil, err
	}
	// The tools, started before the proxy is: a tool that does not listen is no run.
	// They are stopped after the proxy is closed, so no request reaches a tool that is
	// gone.
	if lr.tools, err = r.StartTools(ctx); err != nil {
		return nil, err
	}
	pol := r.Policy()
	if lr.px, err = proxy.New(pol.Policy.Egress.Mode, pol.Policy.Egress.Allow, pol.Policy.Egress.Deny, lr.observe); err != nil {
		return nil, err
	}
	lr.px.ReportPanics(routine.ForRun(g.report, lr.id))
	lr.px.AllowFirst(pol.Policy.Egress.AllowFirst)
	if g.client != nil {
		runID := lr.id
		lr.px.SetRunAPI(&proxy.RunAPI{RunID: runID, Limits: &g.runAPILimits, Send: func(ctx context.Context, method, path string, body []byte, file bool) (*server.RunAPIAnswer, error) {
			conf, _ := g.config()
			return g.client.RunAPI(ctx, conf.Run.URL, runID, method, path, body, file)
		}})
	}
	// Each run has a set of counters that no other run shares, at the limits Start
	// checked.
	lr.px.SetLimits(proxy.Limits{Connections: g.cfg.RunLimits.Connections, RequestsPerSecond: g.cfg.RunLimits.RequestsPerSecond, Burst: g.cfg.RunLimits.Burst})
	if g.cfg.upstreamRoots != nil {
		lr.px.TrustUpstream(g.cfg.upstreamRoots)
	}
	if d.wall || lr.remote {
		// The proxy serves something that is not on this machine, so the addresses of
		// this machine and the private network addresses are not its to reach: an
		// enclosure, or another machine. The names are entries of the node's policy,
		// never of a server's policy or a session's narrowing: neither opens any of
		// these addresses.
		lr.px.Guard(r.GuardNames())
	}
	// The node's path rules, beside a server's, and those put beside the node's policy:
	// fixed for the run, so a reload that brings a server's policy is narrowed by them
	// as the start is.
	if sides := r.NodePaths(); len(sides) > 0 {
		lr.px.NodePaths(sides...)
	}
	var ca *proxy.CA
	if r.NeedsCA() {
		if ca, err = authority(r); err != nil {
			return nil, err
		}
		lr.px.Terminate(ca, r.Uses(), pol.Policy.Egress.Paths, run.ProxyTools(lr.tools))
	}
	if held := r.Held(); held != nil && held.Start != "" {
		// Before any session joins, and between sessions, the proxy sets the start key;
		// of a key group, the group's active key.
		lr.px.SetModelKey(held.Start)
	}
	if keys := r.ModelKeys(); len(keys) > 0 {
		// The run's key group: the proxy sets its active key, sends a refused request
		// again with the next key, for a format other than openai-responses, whose
		// active key changes only at a join, and the reporter shares each key's state
		// with the control plane.
		lr.keys = modelkey.New(keys, r.Held().Start, nil)
		for _, name := range r.KeysOut() {
			lr.keys.Out(name)
		}
		format, stream := r.ModelAPI()
		lr.keys.SetFormat(format)
		// A key the model provider returns 401 for is renewed as unauthorized.
		r.SetKeyGroup(lr.keys)
		if lr.remote {
			// The mark that the proxy passed a limit refusal or a 401 to the session,
			// with the stop's reason once an answer has it, and the keys out of use
			// after a 401, for a gateway that starts again. Called on the proxy's
			// request path, the batch's and the renewal's: a write that fails is
			// reported, and the request goes on.
			dir, runID := lr.st.Dir(), lr.id
			lr.keys.OnPassed(func(passed bool) {
				if err := markLimit(dir, passed); err != nil {
					g.report(fmt.Sprintf("run %s: writing its model key mark: %v", runID, err))
				}
			})
			lr.keys.OnStop(func(reason string) {
				if err := markStop(dir, reason); err != nil {
					g.report(fmt.Sprintf("run %s: writing its model key mark: %v", runID, err))
				}
			})
			lr.keys.OnUnauthorized(func(keys []modelkey.Unauthorized) {
				if err := writeUnauthorized(dir, keys); err != nil {
					g.report(fmt.Sprintf("run %s: check the run's record directory: writing its model keys after a 401 failed: %v", runID, err))
				}
			})
		}
		runID := lr.id
		lr.px.SetKeyGroup(lr.keys, format, stream, func(line string) { g.report("run " + runID + ": " + line) })
		if g.client != nil {
			conf, _ := g.config()
			rep := newKeyReporter(runID, conf.Run.URL, lr.keys, func(ctx context.Context, m server.ModelKeysReport) ([]server.ModelKeyState, error) {
				conf, _ := g.config()
				return g.client.PostModelKeys(ctx, conf.Run.URL, runID, m)
			}, g.report, lr.logLine)
			routine.Go(routine.ForRun(g.report, runID), func() { rep.run(ctx) })
		}
	}
	return ca, nil
}

// keepRegistration is how long a registration built for a run id is kept for a retry
// of the run id, by the wall clock from the time it holds: half the window a server
// holds its time to, so a retry's time is still within it.
const keepRegistration = server.Window / 2

// keptRegistration is a registration built for a run id: its members, its bytes and
// the time it holds, read back, which carries no monotonic clock reading.
type keptRegistration struct {
	reg  server.Registration
	body []byte
	at   time.Time
}

// registration is the bytes of a run's registration: those built for the run id within
// [keepRegistration] when every member but the time is the same, the retry of a run id
// whose session gave up as it opened, else new ones, kept.
func (g *Gateway) registration(reg server.Registration) ([]byte, error) {
	return g.registrationAt(reg, time.Now())
}

// registrationAt is [Gateway.registration] at now. A kept registration's age is
// measured by the wall clock, its monotonic reading stripped, from the time it holds,
// so a host that slept does not keep one the server would refuse as stale; a negative
// age, a clock set back, has it expire as well.
func (g *Gateway) registrationAt(reg server.Registration, now time.Time) ([]byte, error) {
	g.regMu.Lock()
	defer g.regMu.Unlock()
	now = now.Round(0)
	for id, k := range g.registrations {
		if age := now.Sub(k.at); age < 0 || age > keepRegistration {
			delete(g.registrations, id)
		}
	}
	if k, ok := g.registrations[reg.RunID]; ok {
		same := reg
		same.Time = k.reg.Time
		if reflect.DeepEqual(same, k.reg) {
			return k.body, nil
		}
	}
	body, err := reg.Body()
	if err != nil {
		return nil, err
	}
	if g.registrations == nil {
		g.registrations = map[string]keptRegistration{}
	}
	at, err := time.Parse(time.RFC3339, reg.Time)
	if err != nil {
		// A time that does not read back is not kept: a retry builds its own.
		return body, nil
	}
	reg.Labels = maps.Clone(reg.Labels)
	g.registrations[reg.RunID] = keptRegistration{reg: reg, body: body, at: at}
	return body, nil
}

// arm starts the run's liveness and its reload, once the session has its answer.
func (lr *linkRun) arm() {
	lr.mu.Lock()
	lr.last = time.Now()
	if !lr.ended {
		lr.timer = lr.watchAfter(lr.g.quiet)
	}
	lr.mu.Unlock()
	if lr.live != nil {
		lr.live.start(lr.apply)
	}
}

// serverEnd ends the run with the outcome its starter gave, the end member of a signed
// 2xx toward the server, on the sink's goroutine: the first one ends it, and any later
// end, or one after the run ended otherwise, is ignored. It never blocks.
func (lr *linkRun) serverEnd(end server.ServerEnd) { lr.end(stoppedBy(end)) }

// release lets go of what the run holds on the gateway's side: its stack proxy, its
// secret and proxy first, so an ended run's secrets are refused at once, even while a
// reload in flight winds down; then its reload, its tools and its credentials. Each may
// be absent.
func (lr *linkRun) release() {
	lr.cancel()
	lr.closeStack()
	if lr.secret != nil {
		lr.g.proxies.Unregister(lr.secret.reveal())
	}
	if lr.px != nil {
		lr.px.Close()
	}
	if lr.live != nil {
		lr.live.stop()
	}
	lr.tools.Close()
	if lr.r != nil {
		lr.r.Close()
	}
}

// observe numbers one decision of the run's proxy as dev.qory.run.egress; the stream
// holds it until run.started is numbered.
func (lr *linkRun) observe(d proxy.Decision) { lr.st.Emit(event.RunEgress, run.Egress(d)) }

// logLine numbers one line of the gateway's in the run's record as a dev.qory.run.log of
// stream stderr, with no session: a value of the run configuration's credentials that
// expired with no renewal.
func (lr *linkRun) logLine(line string) {
	lr.st.Emit(event.RunLog, map[string]any{"stream": "stderr", "bytes": base64.StdEncoding.EncodeToString([]byte(line + "\n"))})
}

// openStack makes the run's stack proxy, for qory's fetch of the harness definition
// before the run's first session: in enforce mode, allowing the hosts of
// [Config.StackHosts], and each host of the run configuration's stack_hosts that the
// node's policy allows ([run.Run.StackChecked]), with no model key, at the run's limits
// with counters apart from the run's proxy. With the run configuration's harness
// credentials ([run.Run.StackUses]), it ends TLS for their hosts with ca, the run's
// authority, and sets each credential on the paths of its items; every other path of
// such a host passes with no credential, as a tunnel's would. Without them it has no
// certificate authority and no credential. When
// guarded is true it is guarded as the run's proxy is: this machine's addresses and the
// private network addresses are reached only for a host that the node's policy's allow
// list and StackHosts both list by name, not by a *. pattern, and a link-local or cloud
// metadata address for none, so the run configuration's entries open none of these.
// The run's policy is not read. Each decision is a line of the gateway's report
// ([stackLine]) and a dev.qory.run.egress with channel stack ([stackEgress]). On the
// local link it is registered under
// a fresh secret, the run answer's stack_proxy_secret, which no other proxy has; on
// the one address the run key opens it, after [link.StackPreamble].
func (lr *linkRun) openStack(guarded bool, ca *proxy.CA) error {
	report := routine.ForRun(lr.g.report, lr.id)
	yaml := slices.Clone(lr.g.cfg.StackHosts)
	// forager.yaml's entries come first, so a host both lists allow is reported as
	// forager.yaml's.
	hosts := slices.Clone(yaml)
	for _, entry := range lr.r.StackHosts() {
		if !slices.Contains(hosts, entry) {
			hosts = append(hosts, entry)
		}
	}
	hidden := lr.r.HarnessHidden()
	px, err := proxy.New(policy.Enforce, hosts, nil, func(d proxy.Decision) {
		report(stackLine(d, yaml, lr.r.StackChecked))
		lr.st.Emit(event.RunEgress, stackEgress(d, hidden))
	})
	if err != nil {
		return err
	}
	px.ReportPanics(report)
	if lr.g.cfg.upstreamRoots != nil {
		px.TrustUpstream(lr.g.cfg.upstreamRoots)
	}
	if uses := lr.r.StackUses(); len(uses) > 0 && ca != nil {
		// Every path of a harness credential's host passes, as before the credential
		// was set: the credential is set on its items' paths alone.
		every := map[string][]string{}
		for _, u := range uses {
			for _, h := range u.Hosts {
				every[h] = []string{"/*"}
			}
		}
		px.Terminate(ca, uses, every, nil)
	}
	px.SetLimits(proxy.Limits{Connections: lr.g.cfg.RunLimits.Connections, RequestsPerSecond: lr.g.cfg.RunLimits.RequestsPerSecond, Burst: lr.g.cfg.RunLimits.Burst, Stack: true})
	// A host of the run configuration's entries alone passes when the node's policy
	// allows it; forager.yaml's entries are not checked.
	px.Admit(func(host, rule string) bool {
		return slices.Contains(yaml, rule) || lr.r.StackChecked(host) == run.StackAllowed
	})
	px.Unlisted(func(host string, port int) string { return stackRefused(host, port, lr.r.StackChecked(host)) })
	if guarded {
		// The names are the node's policy's allow entries that StackHosts lists exactly,
		// so a *. entry of StackHosts opens nothing: both lists name the host itself.
		var names []string
		if node := lr.g.cfg.Policy; node != nil {
			for _, entry := range node.Egress.Allow {
				if _, ok := policy.Exact(lr.g.cfg.StackHosts, entry); ok {
					names = append(names, entry)
				}
			}
		}
		px.Guard(names)
		px.GuardRefused(stackGuarded)
	}
	lr.mu.Lock()
	lr.stack = px
	lr.mu.Unlock()
	if lr.remote {
		return nil
	}
	secret, err := proxy.NewSecret()
	if err != nil {
		return err
	}
	lr.mu.Lock()
	lr.stackSecret = newSecretValue(secret)
	lr.mu.Unlock()
	return lr.g.proxies.Register(secret, px)
}

// stackProxy is the run's stack proxy, nil from the run's first join request on.
func (lr *linkRun) stackProxy() *proxy.Proxy {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return lr.stack
}

// closeStack closes the run's stack proxy, once, at the run's first join request and as
// the run lets go of what it holds: its secret is refused from then on, and every
// connection through it closes, one opened before the call among them. Then the
// renewals of the harness credentials stop and their values are overwritten with
// zeros, before any session joins.
func (lr *linkRun) closeStack() {
	lr.mu.Lock()
	px, secret := lr.stack, lr.stackSecret
	lr.stack, lr.stackSecret = nil, nil
	lr.mu.Unlock()
	if secret != nil {
		lr.g.proxies.Unregister(secret.reveal())
	}
	if px != nil {
		px.Close()
	}
	if lr.r != nil {
		lr.r.CloseHarness()
	}
}

// stackEgress is the data of the dev.qory.run.egress of one decision of a run's stack
// proxy: [run.Egress] with channel stack, and without the request's path and path rule
// when the run's harness is hidden.
func stackEgress(d proxy.Decision, hidden bool) map[string]any {
	data := run.Egress(d)
	data["channel"] = "stack"
	if hidden {
		delete(data, "path")
		delete(data, "path_rule")
	}
	return data
}

// stackLine is the gateway's report of one decision of a run's stack proxy, after
// "run <run id>: ". An allowed host's rule is an entry of yaml, [Config.StackHosts], or
// else of the run configuration's stack_hosts; checked is the node's decision on a host
// for the run configuration's entries.
func stackLine(d proxy.Decision, yaml []string, checked func(string) run.StackCheck) string {
	host := accesskey.ShownValue(d.Host, false)
	if d.Rule == proxy.HostForm && !accesskey.ContainsSecret(d.Host) {
		host = strconv.QuoteToASCII(d.Host)
	}
	to := fmt.Sprintf("stack fetch to %s:%d", host, d.Port)
	list := "gateway.stack_hosts"
	if !slices.Contains(yaml, d.Rule) {
		list = "the run configuration's stack_hosts"
	}
	switch {
	case !d.Allowed && strings.HasPrefix(d.PathRule, "wall:"):
		// A request to a harness credential's host that a rule of the gateway's refuses,
		// such as wall:echo-method for a TRACE.
		return fmt.Sprintf("%s denied by the gateway's rule %s", to, d.PathRule)
	case d.Allowed && d.Outcome == proxy.DialFailed:
		return fmt.Sprintf("%s allowed by %s entry %s; the dial failed", to, list, d.Rule)
	case d.Allowed:
		return fmt.Sprintf("%s allowed by %s entry %s", to, list, d.Rule)
	case d.Rule == "":
		switch checked(d.Host) {
		case run.StackNodeRefuses:
			return to + " denied: the node's policy does not allow this host of the run configuration's stack_hosts"
		case run.StackNodePaths:
			return to + " denied: the node's policy has path rules for this host, which the stack proxy does not check"
		}
		return to + " denied: the host is in neither stack_hosts list"
	}
	return fmt.Sprintf("%s denied by the gateway's rule %s", to, d.Rule)
}

// stackRefused is the body of the 403 a run's stack proxy answers for a host that
// [Config.StackHosts] does not list, by checked, the node's decision on it for the run
// configuration's stack_hosts: a host the node's policy does not allow, one it has path
// rules for, or one in neither list.
func stackRefused(host string, port int, checked run.StackCheck) string {
	switch checked {
	case run.StackNodeRefuses:
		return fmt.Sprintf("qory: allow %s in the node's policy, or list it in gateway.stack_hosts.\n"+
			"qory: egress to %s:%d denied by the gateway: the node's policy does not allow this host of the run configuration's stack_hosts\n", host, host, port)
	case run.StackNodePaths:
		return fmt.Sprintf("qory: list %s in gateway.stack_hosts: the node's path rules cover it.\n"+
			"qory: egress to %s:%d denied by the gateway: the node's policy has path rules for this host, which the stack proxy does not check\n", host, host, port)
	}
	return fmt.Sprintf("qory: add %s to stack_hosts in forager.yaml or in the run configuration.\n"+
		"qory: egress to %s:%d denied by the gateway: the host is in neither stack_hosts list\n", host, host, port)
}

// stackGuarded is the body of the 403 a run's guarded stack proxy answers for a host
// the guard refuses, by number or at dial time: never for a link-local or cloud
// metadata address, which no entry opens, and otherwise this machine's address or a
// private network address.
func stackGuarded(host string, port int, never bool) string {
	if never {
		return fmt.Sprintf("qory: fetch the harness definition from another host: the gateway never reaches a link-local or cloud metadata address, and %s is one or resolves to one.\n"+
			"qory: egress to %s:%d denied by the gateway: no entry of gateway.stack_hosts or of the node's policy opens a link-local or cloud metadata address\n", host, host, port)
	}
	return fmt.Sprintf("qory: to fetch the harness definition from the gateway's machine or a private network address, list %s by name, not a *. pattern, in the allow list of the node's policy and in gateway.stack_hosts in forager.yaml.\n"+
		"qory: egress to %s:%d denied by the gateway: the stack proxy reaches such an address only for a host listed by name in both, and never a link-local or cloud metadata address\n", host, host, port)
}

// touch says the session asked something of the run now.
func (lr *linkRun) touch() {
	lr.mu.Lock()
	lr.last = time.Now()
	lr.mu.Unlock()
}

// watchAfter runs watch after d, a panic in it reported under the run's id.
func (lr *linkRun) watchAfter(d time.Duration) *time.Timer {
	return time.AfterFunc(d, func() { routine.Do(routine.ForRun(lr.g.report, lr.id), lr.watch) })
}

// watch ends the run when its session has asked nothing of it for the quiet time, and
// otherwise looks again when that time would be up.
func (lr *linkRun) watch() {
	lr.mu.Lock()
	if lr.ended {
		lr.mu.Unlock()
		return
	}
	if idle := time.Since(lr.last); idle < lr.g.quiet {
		lr.timer = lr.watchAfter(lr.g.quiet - idle)
		lr.mu.Unlock()
		return
	}
	lr.mu.Unlock()
	lr.g.report(fmt.Sprintf("run %s: its session sent nothing for %s; the run ends: %s", lr.id, lr.g.quiet, sessionLost.state))
	lr.end(sessionLost)
}

// gone reports how the run ended at the gateway, when it has.
func (lr *linkRun) gone() (runEnd, bool) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return lr.how, lr.ended
}

// end ends the run at the gateway, once: the session's later requests are a 410, and
// in the background its secret is refused, its proxy, tools and credentials go, the
// gateway's own run.exited is numbered when the ending has a state, and its stream is
// flushed and closed. It never blocks.
func (lr *linkRun) end(e ending) {
	lr.mu.Lock()
	if lr.ended || !lr.opened || lr.suspended {
		lr.mu.Unlock()
		return
	}
	lr.ended, lr.how, lr.closed = true, e.runEnd(), e.closed
	if lr.timer != nil {
		lr.timer.Stop()
	}
	startedAt := lr.startedAt
	discarded := lr.discarded
	lr.mu.Unlock()
	report := routine.ForRun(lr.g.report, lr.id)
	routine.Go(report, func() {
		defer close(lr.done)
		// A panic while the run lets go of what it holds still flushes its record and,
		// on the one address, retires it.
		routine.Do(report, lr.release)
		if discarded {
			if err := lr.st.Discard(lr.g.base); err != nil {
				lr.g.report(fmt.Sprintf("run %s: closing its record: %v", lr.id, accesskey.ShownError(err)))
			}
			lr.cancel()
			return
		}
		if e.state != "" && lr.st.Started() {
			// A join still open with its session.started: its session's end comes first,
			// with the run's state and reason, as each session.exited follows its
			// session.started. An open join with no session.started gets no event. No batch
			// and no join is numbered from here on, the run having ended.
			lr.batch.Lock()
			lr.mu.Lock()
			var open *join
			if j := lr.openJoin(); j != nil && j.started {
				c := *j
				open = &c
			}
			lr.mu.Unlock()
			lr.batch.Unlock()
			if open != nil {
				lr.st.Emit(event.SessionExited, ended(e, open.session, open.startedAt))
			}
			// The gateway holds no exit status of a session's runtime.
			lr.st.Emit(event.RunExited, ended(e, 0, startedAt))
		}
		lr.result, lr.err = lr.st.Close(lr.g.base)
		if lr.remote && !e.keep {
			// The run ended for good: no gateway reopens it, and its CA key and run
			// request go from the disk.
			if err := stream.RemoveKept(lr.st.Dir()); err != nil {
				lr.g.report(fmt.Sprintf("run %s: removing its CA files and run request: %v", lr.id, err))
			}
		}
		lr.cancel()
		if lr.remote {
			// Flushed: the gateway lets go of it.
			lr.g.retire(lr)
		}
	})
}

// suspend ends the run's gateway side at the stop of a gateway with Listen, without
// ending the run, once: the run is not ended or suspended here, its timer stops, and in
// the background it lets go of what it holds, as [linkRun.end] does, then its stream
// is suspended under lr.batch, so no batch is numbered meanwhile ([stream.Run.Suspend]):
// no session.exited, no run.exited, and its record's files kept. It never blocks.
func (lr *linkRun) suspend() {
	lr.mu.Lock()
	if lr.ended || !lr.opened || lr.suspended {
		lr.mu.Unlock()
		return
	}
	lr.suspended = true
	if lr.timer != nil {
		lr.timer.Stop()
	}
	lr.mu.Unlock()
	report := routine.ForRun(lr.g.report, lr.id)
	routine.Go(report, func() {
		defer close(lr.done)
		routine.Do(report, lr.release)
		lr.batch.Lock()
		lr.result, lr.err = lr.st.Suspend(lr.g.base)
		lr.batch.Unlock()
		lr.cancel()
	})
}

// isSuspended reports whether the run is suspended ([linkRun.suspend]).
func (lr *linkRun) isSuspended() bool {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return lr.suspended
}

// ended is the data of the gateway's dev.qory.run.exited of the ending e, or with a
// session of 1 or more that of the session's dev.qory.session.exited: the ending's
// state and reason, exit_code -1, and the milliseconds since from, 0 when from is zero.
func ended(e ending, session int, from time.Time) map[string]any {
	var ran int64
	if !from.IsZero() {
		ran = max(time.Since(from).Milliseconds(), 0)
	}
	data := map[string]any{"state": e.state, "duration_ms": ran, "exit_code": -1}
	if session > 0 {
		data["session"] = session
	}
	if e.reason != "" {
		data["reason"] = e.reason
	}
	return data
}

// runAnswerDoc is the run answer as the gateway writes it,
// contracts/forager/v1/link-run-answer.schema.json: on the one address without the
// labels, the proxy secret and the stack proxy secret.
type runAnswerDoc struct {
	Version              int                          `json:"version"`
	RunID                string                       `json:"run_id"`
	Labels               map[string]string            `json:"labels,omitzero"`
	Policy               json.RawMessage              `json:"policy,omitempty"`
	Digest               string                       `json:"digest,omitempty"`
	Variables            map[string]server.Variable   `json:"variables,omitempty"`
	ProxySecret          string                       `json:"proxy_secret,omitempty"`
	StackProxySecret     string                       `json:"stack_proxy_secret,omitempty"`
	CertificateAuthority string                       `json:"certificate_authority,omitempty"`
	Placeholders         []string                     `json:"placeholders,omitempty"`
	Reserved             []string                     `json:"reserved,omitempty"`
	CredentialHosts      []server.LinkCredentialHosts `json:"credential_hosts,omitempty"`
	ModelCredential      string                       `json:"model_credential,omitempty"`
	Image                *server.LinkImage            `json:"image,omitempty"`
	RelayImage           string                       `json:"relay_image,omitempty"`
	RunAPI               string                       `json:"run_api,omitempty"`
	Resume               *server.LinkResume           `json:"resume,omitempty"`
	Applied              map[string]any               `json:"applied"`
}

// reloadAnswerDoc is the reload answer as the gateway writes it,
// contracts/forager/v1/link-reload-answer.schema.json.
type reloadAnswerDoc struct {
	Version      int                        `json:"version"`
	Policy       json.RawMessage            `json:"policy,omitempty"`
	Digest       string                     `json:"digest,omitempty"`
	Variables    map[string]server.Variable `json:"variables,omitempty"`
	Placeholders []string                   `json:"placeholders,omitempty"`
	Reserved     []string                   `json:"reserved,omitempty"`
	Image        *server.LinkImage          `json:"image,omitempty"`
	Applied      map[string]any             `json:"applied"`
}

// refresh makes the reload answer of the policy in force, adds the members of its
// dev.qory.run.policy_applied the gateway decides to those it gave the run, and returns
// the members it added, for [linkRun.keep] once lr.mu is free. Called with lr.mu held.
func (lr *linkRun) refresh() []map[string]any {
	f := lr.compute()
	lr.publish(f)
	return f.given
}

// refreshed is what [linkRun.compute] makes of the policy in force: the members of its
// dev.qory.run.policy_applied the gateway decides, one or two, and the body and digest
// of the reload answer.
type refreshed struct {
	given  []map[string]any
	body   []byte
	digest string
}

// publish adds f's members to those the gateway gave the run and puts f's reload
// answer in force, which a request's answer headers then contain. Called with lr.mu
// held.
func (lr *linkRun) publish(f refreshed) {
	lr.given = append(lr.given, f.given...)
	lr.reloadBody, lr.reloadDigest = f.body, f.digest
}

// compute makes the reload answer of the policy in force and the members of its
// dev.qory.run.policy_applied the gateway decides, and changes nothing of lr. Called
// with lr.mu held.
func (lr *linkRun) compute() refreshed {
	var given []map[string]any
	pol := lr.r.Policy()
	applied := appliedOf(pol, lr.r.Beside(), lr.r.Held(), lr.r.Chosen(), lr.px.Terminated())
	if hosts := lr.r.StackHosts(); !lr.opened && len(hosts) > 0 {
		// The open's record lists the run configuration's stack_hosts, which the stack
		// proxy allows until the run's first join request, in JSON's types as the rest.
		listed := make([]any, len(hosts))
		for i, h := range hosts {
			listed[i] = h
		}
		applied["stack_hosts"] = listed
	}
	if harness := harnessApplied(lr.r.StackUses(), lr.r.HarnessHidden()); !lr.opened && len(harness) > 0 {
		// A join's record lists no harness credential, whose value is gone by then: the
		// members without them come first, and the open's, with them, last.
		given = append(given, applied)
		withHarness := maps.Clone(applied)
		listed, _ := applied["credentials"].([]any)
		withHarness["credentials"] = append(slices.Clone(listed), harness...)
		applied = withHarness
	}
	given = append(given, applied)
	doc, digest := policyDocument(pol)
	body, _ := json.Marshal(reloadAnswerDoc{
		Version: 1, Policy: doc, Digest: digest, Variables: variables(lr.r.Variables()),
		Placeholders: lr.r.Placeholders(), Reserved: lr.r.Reserved(), Image: lr.image(), Applied: applied,
	})
	sum := sha256.Sum256(body)
	return refreshed{given: given, body: body, digest: "sha256=" + hex.EncodeToString(sum[:])}
}

// keep adds each of given, the members [linkRun.refresh] added, to the record's
// given.jsonl on the one address, in order; the error is the first write's that
// failed. It writes with lr.mu free, so no request of the run waits on the disk: the
// open and the reopen call it before the run is held, and a reload under lr.joining,
// so the lines of two calls never interleave.
func (lr *linkRun) keep(given []map[string]any) error {
	if !lr.remote {
		return nil
	}
	for _, a := range given {
		// Shown names and values alone, as the event's data: no credential's value.
		if err := appendKept(lr.st.Dir(), givenFile, a); err != nil {
			return err
		}
	}
	return nil
}

// runAnswer is the run answer, with the run's authority when it has one. Called with
// lr.mu held, after refresh.
func (lr *linkRun) runAnswer(authority []byte) []byte {
	pol := lr.r.Policy()
	doc, digest := policyDocument(pol)
	a := runAnswerDoc{
		Version: 1, RunID: lr.id, Labels: lr.labels, Policy: doc, Digest: digest, Variables: variables(lr.r.Variables()),
		ProxySecret: lr.secret.reveal(), StackProxySecret: lr.stackSecret.reveal(), CertificateAuthority: string(authority), Placeholders: lr.r.Placeholders(), Reserved: lr.r.Reserved(),
		CredentialHosts: credentialHosts(lr.r.Held()), Image: lr.image(), Applied: lr.given[len(lr.given)-1],
	}
	if held := lr.r.Held(); held != nil {
		a.ModelCredential = held.Start
	}
	if lr.wall {
		a.RelayImage = lr.r.RelayImage()
	}
	if lr.g.client != nil {
		a.RunAPI = link.RunAPIURL(lr.id)
	}
	a.Resume = lr.r.Resume()
	if lr.remote {
		a.Labels = nil
	} else if a.Labels == nil {
		a.Labels = map[string]string{}
	}
	b, _ := json.Marshal(a)
	return b
}

// credentialHosts are the run answer's credential_hosts: one entry per credential held,
// and per apply item of a host credential from the server, from the same uses as
// appliedOf's credentials, with the auth of a credential from the
// server and of a model key, and the format and endpoint of a model key; nil when the
// run holds none.
func credentialHosts(held *credential.Held) []server.LinkCredentialHosts {
	if held == nil {
		return nil
	}
	var out []server.LinkCredentialHosts
	for _, c := range held.Credentials() {
		if c.Stored && c.Format == "" {
			// A host credential from the server: one entry per item, each with its
			// hosts and auth, the placeholders on the first alone.
			for i, it := range c.Items {
				e := server.LinkCredentialHosts{Name: c.Name, Hosts: it.Hosts, Placeholders: []string{},
					Auth: &server.Auth{Scheme: it.Scheme, Header: it.Header, Username: it.Username}}
				if i == 0 {
					e.Placeholders = c.Placeholders
				}
				out = append(out, e)
			}
			continue
		}
		e := server.LinkCredentialHosts{Name: c.Name, Hosts: c.Hosts, Placeholders: c.Placeholders, Format: c.Format, Endpoint: c.Endpoint}
		if c.Stored || c.Format != "" {
			e.Auth = &server.Auth{Scheme: c.Scheme, Header: c.Header, Username: c.Username, OAuth: c.OAuth}
		}
		out = append(out, e)
	}
	return out
}

// image is the image the run gets, behind a wall, when it has a reference.
func (lr *linkRun) image() *server.LinkImage {
	img := lr.r.Image()
	if !lr.wall || img.Ref == "" {
		return nil
	}
	return &server.LinkImage{Name: img.Name, Ref: img.Ref, Runtime: img.Runtime, Docker: img.Docker, Reference: img.Reference}
}

// policyDocument is the policy in force as policy.schema.json defines it, and its
// digest; neither when no policy is, source none.
func policyDocument(pol *policy.Loaded) (json.RawMessage, string) {
	if pol.Source == "none" {
		return nil, ""
	}
	p := pol.Policy
	if p.Egress.Allow == nil {
		p.Egress.Allow = []string{}
	}
	b, _ := json.Marshal(p)
	return b, pol.Digest
}

// variables are the run's variables as a run configuration contains them; nil for none.
func variables(values map[string]string) map[string]server.Variable {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]server.Variable, len(values))
	for name, v := range values {
		out[name] = server.Variable{Value: v}
	}
	return out
}

// images are the session's images as the run's policy selects among them.
func images(li *server.LinkImages) run.Images {
	if li == nil {
		return run.Images{}
	}
	out := run.Images{Default: li.Default, Allow: li.Allow}
	for _, d := range li.Definitions {
		out.Defined = append(out.Defined, run.Image{Name: d.Name, Ref: d.Ref, Runtime: d.Runtime, Docker: d.Docker})
	}
	return out
}

// appliedOf is what dev.qory.run.policy_applied records of a policy that the gateway
// decides, as today's session writes it: every member but the variables, the
// credential variables and the harness's hosts, which are the session's. beside are the sides of path rules
// [Policy.Under] put beside the run's policy, its ceiling_paths. It is in JSON's types,
// as an event's data decodes.
func appliedOf(pol *policy.Loaded, beside []map[string][]string, held *credential.Held, chosen []tool.Chosen, terminated []string) map[string]any {
	allow, deny := pol.Policy.Egress.Allow, pol.Policy.Egress.Deny
	if allow == nil {
		allow = []string{}
	}
	if deny == nil {
		deny = []string{}
	}
	a := map[string]any{"mode": string(pol.Policy.Egress.Mode), "allow": allow, "deny": deny, "source": pol.Source}
	if len(pol.Policy.Egress.AllowFirst) > 0 {
		a["allow_first"] = pol.Policy.Egress.AllowFirst
	}
	if pol.Source != "none" {
		a["digest"] = pol.Digest
	}
	if pol.URL != "" {
		// server.Client.Discover refuses a run.url that contains qak_, qrk_, qecr_, qecn_, qecp_,
		// qecg_, qeci_ or qecd_, which no phrase can stand in for: the schema's url is a URI.
		a["url"], a["run_configuration"] = pol.URL, pol.RunConfiguration
	}
	if pol.Node != nil {
		np := map[string]any{"digest": pol.Node.Digest}
		if len(pol.Node.Paths) > 0 {
			np["paths"] = shownPaths(pol.Node.Paths)
		}
		a["node_policy"] = np
	}
	if len(pol.Policy.Egress.Paths) > 0 {
		a["paths"] = shownPaths(pol.Policy.Egress.Paths)
	}
	if len(beside) > 0 {
		sides := make([]map[string][]string, len(beside))
		for i, side := range beside {
			sides[i] = shownPaths(side)
		}
		a["ceiling_paths"] = sides
	}
	if held != nil && len(held.Uses) > 0 {
		uses := make([]map[string]any, len(held.Uses))
		for i, u := range held.Uses {
			// A name or an argument that contains qak_, qrk_, qecr_, qecn_, qecp_, qecg_, qeci_
			// or qecd_ in any case is sent as accesskey.ShownName's phrase in its place. A host
			// or a path is accesskey.ShownValue's phrase in place of one that contains any of
			// them.
			uses[i] = map[string]any{"name": accesskey.ShownName(u.Name, false), "hosts": shownValues(u.Hosts), "scheme": u.Scheme}
			if u.Argument != "" {
				uses[i]["argument"] = accesskey.ShownName(u.Argument, false)
			}
			if u.Paths != nil {
				uses[i]["paths"] = shownValues(u.Paths)
			}
		}
		a["credentials"] = uses
	}
	if len(chosen) > 0 {
		used := make([]map[string]any, len(chosen))
		for i, c := range chosen {
			// As the credentials' name and argument.
			used[i] = map[string]any{"name": accesskey.ShownName(c.Name, false), "hosts": c.Serves}
			if c.Argument != "" {
				used[i]["argument"] = accesskey.ShownName(c.Argument, false)
			}
		}
		a["tools"] = used
	}
	if pol.Policy.Image != "" {
		a["image"] = accesskey.ShownName(pol.Policy.Image, false)
	}
	if len(terminated) > 0 {
		a["terminated"] = shownValues(terminated)
	}
	b, _ := json.Marshal(a)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out
}

// harnessApplied are the entries of dev.qory.run.policy_applied's credentials of the
// run configuration's harness credentials, from uses, [run.Run.StackUses], in JSON's
// types as appliedOf's: one per item, with its hosts, scheme and paths and purpose
// harness; under hidden, one per credential, with its name and purpose alone.
func harnessApplied(uses []proxy.Credential, hidden bool) []any {
	var out []any
	var seen []string
	for _, u := range uses {
		name := accesskey.ShownName(u.Name, false)
		if hidden {
			if !slices.Contains(seen, u.Name) {
				seen = append(seen, u.Name)
				out = append(out, map[string]any{"name": name, "purpose": server.PurposeHarness})
			}
			continue
		}
		e := map[string]any{"name": name, "hosts": anyOf(shownValues(u.Hosts)), "scheme": u.Scheme, "purpose": server.PurposeHarness}
		if u.Paths != nil {
			e["paths"] = anyOf(shownValues(u.Paths))
		}
		out = append(out, e)
	}
	return out
}

// anyOf is values in JSON's types, as an event's data decodes.
func anyOf(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

// shownValues are values as an event sends them: each as accesskey.ShownValue shows it,
// in order.
func shownValues(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = accesskey.ShownValue(v, false)
	}
	return out
}

// shownPaths are path rules by host as an event sends them: each path as
// accesskey.ShownValue shows it. A host's form has no underscore, so it is as it is.
func shownPaths(paths map[string][]string) map[string][]string {
	out := make(map[string][]string, len(paths))
	for host, p := range paths {
		out[host] = shownValues(p)
	}
	return out
}

// apply puts a policy the reload fetched in force, as today's session does: decided as
// strictly as a start, then set on the run's proxy in one step and committed. The
// session fetches the new policy with its reload and writes its
// dev.qory.run.policy_applied; the tunnels the new policy closed, and every connection
// after the switch, are recorded right after it, today's order, or before the run's
// final event when it never comes.
func (lr *linkRun) apply(next *policy.Loaded) error {
	// The open joins' passes stay as they are while the reload is decided and put in
	// force: a join waits for it.
	lr.joining.Lock()
	defer lr.joining.Unlock()
	d, err := lr.r.Reload(lr.ctx, next)
	if err != nil {
		return err
	}
	if d.Unchanged {
		return nil
	}
	in := d.Policy.Policy.Egress
	// Every run.egress from here on waits for the session's policy_applied of the new
	// policy: held before the proxy decides by it, so no connection decided under it is
	// numbered first, as today's session switched the policy and wrote its event in one
	// step under its record's lock.
	hold := lr.st.Hold()
	refused := lr.px.SetPolicyOpening(in.Mode, in.AllowFirst, in.Allow, in.Deny, d.Guard, in.Paths, d.Uses)
	lr.r.Commit(d)
	lr.posts.SetRunDigest(d.Policy.RunConfiguration)
	lr.mu.Lock()
	f := lr.compute()
	lr.mu.Unlock()
	// The record has the members before the session can see the new digest, so a
	// gateway that stops after the session's reload finds them when it starts again,
	// and holds no run.egress for a policy_applied the session already wrote.
	if err := lr.keep(f.given); err != nil {
		// The policy is in force: the run goes on, and a gateway that starts again
		// misses these members.
		lr.g.report(fmt.Sprintf("run %s: writing its policy members to its record: %v", lr.id, err))
	}
	lr.mu.Lock()
	lr.publish(f)
	// Before the session can see the new digest, so its policy_applied finds the hold
	// waiting for it; the tunnels the policy closed go first.
	data := make([]any, len(refused))
	for i, dec := range refused {
		data[i] = run.Egress(dec)
	}
	lr.st.Await(hold, appliedIs(lr.given[len(lr.given)-1]), event.RunEgress, data...)
	lr.mu.Unlock()
	return nil
}

// appliedIs matches the session's dev.qory.run.policy_applied whose members the gateway
// decides are a.
func appliedIs(a map[string]any) func(*event.Event) bool {
	return func(ev *event.Event) bool {
		if ev.Type != event.PolicyApplied {
			return false
		}
		raw, ok := ev.Data.(json.RawMessage)
		if !ok {
			return false
		}
		var data map[string]any
		if json.Unmarshal(raw, &data) != nil {
			return false
		}
		return reflect.DeepEqual(decided(data), a)
	}
}

// decided are the members of a dev.qory.run.policy_applied's data the gateway decides:
// all but those the session adds.
func decided(data map[string]any) map[string]any {
	own := map[string]any{}
	for k, v := range data {
		if k != "harness_hosts" && k != "variables" && k != "credential_variables" {
			own[k] = v
		}
	}
	return own
}
