package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/gateway/internal/stream"
	"github.com/qoryai/forager/gateway/internal/tool"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/runcredential"
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
	// secret is the run's proxy secret, held so that no print of the run shows it.
	secret secretValue
	tools  *tool.Set
	posts  *sink.Server
	live   *live
	ctx    context.Context
	cancel context.CancelFunc

	// cred is what the run credential decides of a run on the one address, nil for a
	// run of the local link; client says the run has no session: a client's proxy
	// login opened it.
	cred   *runCred
	client bool

	// runSecret is the run's secret, which the run answer gives its session alone and
	// every reload and batch of the run carries; runSecretSum is its SHA-256, by which
	// the gateway finds the run. A run with no session has neither.
	runSecret    secretValue
	runSecretSum [sha256.Size]byte

	// batch takes one batch of the session's at a time.
	batch sync.Mutex

	mu sync.Mutex
	// opened says the run answer is made; serverClosed that the server closed the run,
	// a signed 410 run_closed.
	opened, serverClosed bool
	// pingAt is when the gateway's ping for the run was numbered, zero without a server.
	pingAt time.Time
	// seen are the ids of the session's events numbered so far; startedID is its
	// run.started's, startedAt that event's time; final says its run.exited or
	// run.refused is numbered.
	seen      map[string]bool
	startedID string
	startedAt time.Time
	final     bool
	// given are the members of dev.qory.run.policy_applied the gateway decides, for each
	// policy it put in force for the run, as the answers carry them.
	given []map[string]any
	// reloadBody is the reload answer as it stands, and reloadDigest its digest, the
	// X-Qory-Run-Configuration of every answer for the run.
	reloadBody   []byte
	reloadDigest string
	// answer is the run answer, given once; it holds the proxy secret and the run's
	// secret, so no print of the run shows it.
	answer secretValue
	// last is when the session last asked anything of the run; timer ends the run when
	// it asks nothing for the gateway's quiet time.
	last  time.Time
	timer *time.Timer
	// ended says the run ended at the gateway: endCode and endFrom are its 410, and
	// closed says it was not the session that ended it.
	ended            bool
	endCode, endFrom string
	closed           bool
	// discarded says the run's session gave up before it had the run answer: the run
	// ends as if it never opened, [Gateway.discard].
	discarded bool
	// conns are the connections a run with no session has open, lastConn when one last
	// opened or closed, and quiet the timer that ends the run once it has had none for
	// the gateway's quiet time; asked is when the issuer was last asked of it.
	conns    int
	lastConn time.Time
	quiet    *time.Timer
	asked    time.Time

	// done is closed once the run's gateway side is over and its stream flushed; result
	// and err are then set.
	done   chan struct{}
	result stream.Result
	err    error
}

// runCred is what the run credential decides of a run on the gateway's one address.
type runCred struct {
	// key is the run's run key, of its issuer; details are the keys of about.details
	// the run credential decides.
	key     runKeyID
	details map[string]string

	// The rest is held under the run's mu. expires is the latest exp of a run
	// credential presented for the run, and expiry the timer that ends the run then;
	// active asks the issuer of the latest run credential presented, nil for an issuer
	// without introspection, and cache is how long its answer holds.
	expires time.Time
	expiry  *time.Timer
	active  func(context.Context) bool
	cache   time.Duration
}

// ending is how a run ends at the gateway.
type ending struct {
	// reason is the reason of the dev.qory.run.exited the gateway writes, empty for none.
	reason string
	// code and from are the 410 the session's later requests get.
	code, from string
	// closed says the run ended before its session ended it.
	closed bool
	// quietSeconds is the quiet period of a run with no session that ended quiet.
	quietSeconds int
}

// sessionLost ends a run whose session the gateway no longer hears: its later requests
// are a 410 session_lost.
var sessionLost = ending{reason: event.ReasonSessionLost, code: event.ReasonSessionLost, from: accesskey.FromGateway, closed: true}

// sessionGone ends a run whose session gave up before it had the run answer: nothing
// more is written of it.
var sessionGone = ending{code: event.ReasonSessionLost, from: accesskey.FromGateway}

// batchRefused ends a run whose session's batch the gateway refused: its record says
// session_lost, as for a session it no longer hears, and its later requests are a 410
// batch_refused.
var batchRefused = ending{reason: event.ReasonSessionLost, code: event.ReasonBatchRefused, from: accesskey.FromGateway, closed: true}

// serverClosed ends a run the server closed.
var serverClosedRun = ending{reason: event.ReasonRunClosed, code: accesskey.CodeRunClosed, from: accesskey.FromApiary, closed: true}

// credentialExpired ends a run on the one address whose run credential's exp passed
// with no fresh one; endedAtIssuer one whose issuer no longer holds its run credential
// active, or ended another run of its run key.
var (
	credentialExpired = ending{reason: event.ReasonCredentialExpired, code: event.ReasonCredentialExpired, from: accesskey.FromGateway, closed: true}
	endedAtIssuer     = ending{reason: event.ReasonRunEndedAtIssuer, code: event.ReasonRunEndedAtIssuer, from: accesskey.FromGateway, closed: true}
)

// opening is how a run opens: on the one address with the run credential's identity,
// and with no session, for a client's proxy login.
type opening struct {
	// remote says the request came to the gateway's one address, whose runs' proxies
	// are guarded whatever their wall.
	remote bool
	// id is the run credential's run, on the one address; nil on the local link.
	id *runIdentity
	// client says the run has no session.
	client bool
	// request, when not nil, is the context of the session's run request: once it ends,
	// the session no longer waits for its answer, and the run does not open.
	request context.Context
}

// open opens a run for a request the link accepted: the ping and the run configuration
// with a server, the policy in force, the credentials and the tools, the run's proxy
// under a fresh secret, and its record. On the one address the run's labels are the run
// credential's, and its proxy guarded whatever its wall. A run with no session gets no
// proxy secret and no answer: its proxy reads inside HTTPS with the gateway's own
// authority, and the gateway writes its run.started and run.policy_applied. A refusal
// is an [*accesskey.Refusal]; recorded says the run's record was made, so its id is
// used from now on.
func (g *Gateway) open(req *server.LinkRunRequest, how opening) (lr *linkRun, recorded bool, err error) {
	remote := how.remote
	st, err := g.stream.Open(req.RunID)
	if err != nil {
		return nil, false, err
	}
	ctx, cancel := context.WithCancel(g.base)
	labels := maps.Clone(req.Labels)
	if how.id != nil {
		// A run's labels on the one address come from the run credential alone.
		labels = maps.Clone(how.id.Labels)
	}
	if labels == nil {
		labels = map[string]string{}
	}
	lr = &linkRun{g: g, id: req.RunID, wall: req.Wall, labels: labels, st: st, ctx: ctx, cancel: cancel, seen: map[string]bool{}, done: make(chan struct{}), client: how.client}
	if id := how.id; id != nil {
		lr.cred = &runCred{key: keyOf(*id), details: maps.Clone(id.Details), expires: id.Expires, active: id.active, cache: id.cache}
	}
	fail := func(err error) (*linkRun, bool, error) {
		lr.release()
		lr.mu.Lock()
		closed := lr.serverClosed
		lr.mu.Unlock()
		if closed {
			// The server closed the run before it started: dev.qory.run.refused, which
			// reaches the record alone, as today's session records it.
			st.Emit(event.RunRefused, map[string]any{"code": accesskey.CodeRunClosed, "status": 410})
			err = &accesskey.Refusal{Code: accesskey.CodeRunClosed, Status: 410, Detail: "the server closed the run before it started", From: accesskey.FromApiary}
		} else if ref := (*accesskey.Refusal)(nil); how.client && errors.As(err, &ref) && ref.Code != "" {
			// No session tells of a run with no session that did not open: the gateway
			// does, its dev.qory.run.refused right after the ping, with the refusal's
			// code, as the session writes one of its own. A failure without a code is
			// told to no one but the operator, as the session's is.
			data := map[string]any{"code": ref.Code}
			if len(ref.Names) > 0 {
				data["names"] = ref.Names
			}
			if ref.From == accesskey.FromApiary && ref.Status != 0 {
				data["status"] = ref.Status
			}
			st.Emit(event.RunRefused, data)
		}
		if _, cerr := st.Close(g.base); cerr != nil {
			g.report(fmt.Sprintf("run %s: closing its record: %v", req.RunID, cerr))
		}
		cancel()
		return nil, true, err
	}
	ask := ctx
	if how.request != nil {
		// Once the session's run request goes, the server's ping and run configuration
		// are asked no longer, and the run does not open: nothing more is written of
		// it, and what its stream wrote goes too, so a retry of the run id opens.
		failed := fail
		fail = func(err error) (*linkRun, bool, error) {
			if how.request.Err() == nil {
				return failed(err)
			}
			if err == nil {
				// A run the server closed as it opened fails without an error of its
				// own: the session's going is the error, so no caller takes the
				// missing run for one that opened.
				err = how.request.Err()
			}
			lr.release()
			if derr := st.Discard(g.base); derr != nil {
				g.report(fmt.Sprintf("run %s: closing its record: %v", req.RunID, derr))
			}
			cancel()
			return nil, false, err
		}
		var stopAsk context.CancelFunc
		ask, stopAsk = context.WithCancel(ctx)
		defer stopAsk()
		defer context.AfterFunc(how.request, stopAsk)()
	}
	var fetched *run.Fetched
	if g.client != nil {
		ping, err := st.Ping(map[string]any{"forager_version": g.cfg.Version, "events": g.conf.Events.Types, "contract_version": server.Revision, "interval_seconds": g.interval})
		if err != nil {
			return fail(err)
		}
		lr.mu.Lock()
		lr.pingAt = time.Now()
		lr.mu.Unlock()
		body, _ := ping.JSON()
		pingID := event.NewID()
		if err := g.client.Ping(ask, g.conf.Events.URL, pingID, []byte("["+string(body)+"]")); err != nil {
			return fail(err)
		}
		lr.live = newLive(ctx, g.client, g.conf, g.confDigest, labels, g.report)
		lr.posts = sink.NewServer(g.client, sink.Target{URL: g.conf.Events.URL, Types: g.conf.Events.Types}, st.Dir(), g.report, lr.live.digests, lr.onServerClosed)
		lr.live.posts = lr.posts
		if err := st.Deliver(lr.posts, pingID); err != nil {
			lr.posts.Close(g.base)
			return fail(err)
		}
		// The run configuration, when the server names one: its policy, narrowed by
		// the node's, or the node's own when it has none, and its variables.
		if g.conf.Run != nil {
			rc, digest, err := g.client.RunConfiguration(ask, g.conf.Run.URL, labels)
			if err != nil {
				return fail(err)
			}
			fetched = &run.Fetched{URL: g.conf.Run.URL, Digest: digest, Document: rc}
		}
	}
	if how.request != nil && how.request.Err() != nil {
		return fail(how.request.Err())
	}
	var narrowing *run.Narrowing
	if n := req.Narrowing; n != nil {
		narrowing = &run.Narrowing{Allow: n.Egress.Allow, Deny: n.Egress.Deny}
	}
	r, err := run.Decide(run.Config{
		RunID: req.RunID, Node: g.cfg.Policy, Server: g.client != nil, Fetched: fetched, Labels: labels, Wall: req.Wall,
		Credentials: g.cfg.Credentials, Tools: g.cfg.Tools, Images: images(req.Images), Passes: run.Passing(req.Passes), Report: g.report,
		Narrowing: narrowing,
	})
	if err != nil {
		return fail(err)
	}
	lr.r = r
	if lr.live != nil {
		lr.live.read = r.Read
		lr.live.holds(r.RunConfiguration())
		lr.posts.SetRunDigest(r.RunConfiguration())
	}
	if err := r.Hold(ctx); err != nil {
		return fail(err)
	}
	// The tools, started before the proxy is: a tool that does not listen is no run.
	// They are stopped after the proxy is closed, so no request reaches a tool that is
	// gone.
	if lr.tools, err = r.StartTools(ctx); err != nil {
		return fail(err)
	}
	pol := r.Policy()
	if lr.px, err = proxy.New(pol.Policy.Egress.Mode, pol.Policy.Egress.Allow, pol.Policy.Egress.Deny, lr.observe); err != nil {
		return fail(err)
	}
	if req.Wall || remote {
		// The proxy serves something that is not on this machine, so this machine's own
		// addresses are not its to reach: an enclosure, or another machine.
		// The names are the policy's own, never a session's narrowing's, which only
		// narrows: a narrowing opens none of this machine's addresses.
		lr.px.Guard(r.GuardNames())
	}
	// The node's path rules, beside a server's: fixed for the run, so a reload that
	// brings a server's policy is narrowed by them as the start is.
	if paths := r.NodePaths(); paths != nil {
		lr.px.NodePaths(paths)
	}
	var authority []byte
	if r.NeedsCA() {
		if how.client {
			// The clients with no session trust the gateway's own authority, which the
			// operator installs on their machines.
			lr.px.Terminate(g.authority, r.Uses(), pol.Policy.Egress.Paths, run.ProxyTools(lr.tools))
		} else {
			ca, err := proxy.NewCA(req.RunID)
			if err != nil {
				return fail(err)
			}
			lr.px.Terminate(ca, r.Uses(), pol.Policy.Egress.Paths, run.ProxyTools(lr.tools))
			authority = ca.PEM()
		}
	}
	if !how.client {
		secret, err := proxy.NewSecret()
		if err != nil {
			return fail(err)
		}
		lr.secret = newSecretValue(secret)
		if err := g.proxies.Register(secret, lr.px); err != nil {
			return fail(err)
		}
		// The run's secret, apart from the proxy secret, which reaches the agent's side.
		runSecret, err := proxy.NewSecret()
		if err != nil {
			return fail(err)
		}
		lr.runSecret, lr.runSecretSum = newSecretValue(runSecret), sha256.Sum256([]byte(runSecret))
	}
	if g.cfg.closesAtOpen != nil && g.cfg.closesAtOpen() {
		lr.onServerClosed()
	}
	lr.mu.Lock()
	lr.refresh()
	closed := lr.serverClosed
	lr.opened = !closed
	lr.last = time.Now()
	lr.mu.Unlock()
	if closed {
		return fail(nil)
	}
	if how.client {
		lr.begin()
		return lr, true, nil
	}
	if !req.Wall {
		authority = nil
	}
	lr.mu.Lock()
	lr.answer = newSecretValue(string(lr.runAnswer(authority)))
	lr.mu.Unlock()
	return lr, true, nil
}

// begin writes what a session writes of a run that opens, for a run with no session:
// its dev.qory.run.started, opened by the gateway, with the run credential's labels
// and the about.details its mapping makes, and its dev.qory.run.policy_applied, the
// members the gateway decides alone. The run has no process, so run.started has none
// of the members of one.
func (lr *linkRun) begin() {
	data := map[string]any{"opened_by": event.OpenedByGateway, "credential": lr.credential(), "forager_version": lr.g.cfg.Version, "labels": lr.labels}
	if len(lr.cred.details) > 0 {
		data["about"] = map[string]any{"details": lr.cred.details}
	}
	lr.mu.Lock()
	lr.startedAt = time.Now()
	given := lr.given[len(lr.given)-1]
	lr.mu.Unlock()
	lr.st.Emit(event.RunStarted, data)
	lr.st.Emit(event.PolicyApplied, given)
}

// arm starts the run's liveness and its reload, once the session has its answer, and
// on the one address the end at its run credential's exp. A run with no session has
// no session to hear: it lives while it has connections, [linkRun.armClient].
func (lr *linkRun) arm() {
	lr.mu.Lock()
	lr.last = time.Now()
	if !lr.ended {
		if lr.client {
			lr.lastConn = time.Now()
			lr.quiet = time.AfterFunc(lr.g.runsQuiet, lr.watchQuiet)
		} else {
			lr.timer = time.AfterFunc(lr.g.quiet, lr.watch)
		}
		if lr.cred != nil {
			lr.cred.expiry = time.AfterFunc(time.Until(lr.cred.expires), lr.expire)
		}
	}
	lr.mu.Unlock()
	if lr.client {
		go lr.keep()
	}
	if lr.live != nil {
		lr.live.start(lr.apply)
	}
}

// expire ends the run once the latest exp of a run credential presented for it has
// passed, credential_expired, and otherwise looks again when that exp would be up.
func (lr *linkRun) expire() {
	lr.mu.Lock()
	if lr.ended {
		lr.mu.Unlock()
		return
	}
	if left := time.Until(lr.cred.expires); left > 0 {
		lr.cred.expiry = time.AfterFunc(left, lr.expire)
		lr.mu.Unlock()
		return
	}
	lr.mu.Unlock()
	lr.g.report(fmt.Sprintf("run %s: its run credential expired with no fresh one; the run ends, credential_expired", lr.id))
	lr.end(credentialExpired)
}

// differs is the refusal of a run credential presented for the run whose labels or
// about.details differ from the run's, which its first run credential made: a forge or
// a repository that differs is target_differs_from_credential, any other label or key
// of about.details differs_from_credential, a key the run has and the run credential
// leaves out among them, each named with the run credential's value. Nil when they are
// the same.
func (lr *linkRun) differs(id runIdentity) *accesskey.Refusal {
	details := map[string]any{}
	for k, v := range lr.cred.details {
		details[k] = v
	}
	if ref := runcredential.Compare(lr.labels, details, id.Labels, id.Details); ref != nil {
		return ref
	}
	var names []string
	for _, k := range slices.Sorted(maps.Keys(lr.labels)) {
		if _, ok := id.Labels[k]; !ok {
			names = append(names, "labels."+k+"=")
		}
	}
	for _, k := range slices.Sorted(maps.Keys(lr.cred.details)) {
		if _, ok := id.Details[k]; !ok {
			names = append(names, "about.details."+k+"=")
		}
	}
	if len(names) > 0 {
		return refusal.New(refusal.DiffersFromCredential, names, "the run credential leaves out a key of the run's")
	}
	return nil
}

// renew takes a run credential presented for the run, verified, of its run key: one
// with a later exp keeps the run going until then, and the issuer is asked of the
// latest one presented from now on.
func (lr *linkRun) renew(id runIdentity) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if lr.ended {
		return
	}
	if id.Expires.After(lr.cred.expires) {
		lr.cred.expires = id.Expires
	}
	if id.active != nil {
		lr.cred.active, lr.cred.cache = id.active, id.cache
	}
}

// stillActive asks the issuer whether the latest run credential presented for the run
// is still active, and ends the run, run_ended_at_issuer, when it is not, any answer
// but active and a failure to ask among it; it reports whether the run goes on. An
// issuer without introspection is never asked.
func (lr *linkRun) stillActive(ctx context.Context) bool {
	lr.mu.Lock()
	active := lr.cred.active
	lr.asked = time.Now()
	lr.mu.Unlock()
	if active == nil || active(ctx) {
		return true
	}
	if ctx.Err() != nil || lr.ctx.Err() != nil {
		// The request went, or the run ended, while the issuer was asked: no answer,
		// and this request alone is not served.
		return false
	}
	lr.g.report(fmt.Sprintf("run %s: the issuer no longer holds its run credential active; the run ends, run_ended_at_issuer", lr.id))
	lr.end(endedAtIssuer)
	return false
}

// release lets go of what the run holds on the gateway's side: its secret and proxy
// first, so an ended run's secret is refused at once, even while a reload in flight
// winds down; then its reload, its tools and its credentials. Each may be absent.
func (lr *linkRun) release() {
	lr.cancel()
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

// onServerClosed hears the server's signed 410 run_closed, on the sink's goroutine:
// the run ends at the gateway, and the session's next request is a 410 from apiary.
func (lr *linkRun) onServerClosed() {
	lr.mu.Lock()
	lr.serverClosed = true
	opened := lr.opened
	lr.mu.Unlock()
	if opened {
		// The sink tells the user, as today.
		lr.end(serverClosedRun)
	}
}

// touch says the session asked something of the run now.
func (lr *linkRun) touch() {
	lr.mu.Lock()
	lr.last = time.Now()
	lr.mu.Unlock()
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
		lr.timer = time.AfterFunc(lr.g.quiet-idle, lr.watch)
		lr.mu.Unlock()
		return
	}
	lr.mu.Unlock()
	lr.g.report(fmt.Sprintf("run %s: its session sent nothing for %s; the run ends, session_lost", lr.id, lr.g.quiet))
	lr.end(sessionLost)
}

// gone reports how the run ended at the gateway, when it has.
func (lr *linkRun) gone() (code, from string, ended bool) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return lr.endCode, lr.endFrom, lr.ended
}

// end ends the run at the gateway, once: the session's later requests are a 410, and
// in the background its secret is refused, its proxy, tools and credentials go, the
// gateway's own run.exited is numbered when the ending writes one, and its stream is
// flushed and closed. It never blocks, but to keep the run key the gateway refuses
// after the issuer's end.
func (lr *linkRun) end(e ending) {
	if e.blocks() {
		// After the issuer's end, the gateway refuses the run key until the latest exp of
		// the run credentials of the run key it still holds, and of any presented during
		// the hold, kept in its directory so a restart refuses it too: kept before the
		// run is seen to end, so no request that sees the end opens a run of it.
		// Outside the run's lock, which is taken under the gateway's.
		lr.mu.Lock()
		live := !lr.ended && lr.opened && lr.cred != nil
		var key runKeyID
		var expires time.Time
		if live {
			key, expires = lr.cred.key, lr.cred.expires
		}
		lr.mu.Unlock()
		if live {
			lr.g.endKey(key, lr.g.heldTo(key, expires))
		}
	}
	lr.mu.Lock()
	if lr.ended || !lr.opened {
		lr.mu.Unlock()
		return
	}
	lr.ended, lr.endCode, lr.endFrom, lr.closed = true, e.code, e.from, e.closed
	for _, t := range []*time.Timer{lr.timer, lr.quiet} {
		if t != nil {
			t.Stop()
		}
	}
	var key runKeyID
	var expires time.Time
	if lr.cred != nil {
		if lr.cred.expiry != nil {
			lr.cred.expiry.Stop()
		}
		key, expires = lr.cred.key, lr.cred.expires
	}
	startedAt := lr.startedAt
	discarded := lr.discarded
	lr.mu.Unlock()
	if lr.cred != nil && e.blocks() {
		// A run credential with a later exp presented since: the refusal lasts to it.
		lr.g.endKey(key, lr.g.heldTo(key, expires))
	}
	go func() {
		defer close(lr.done)
		lr.release()
		if discarded {
			if err := lr.st.Discard(lr.g.base); err != nil {
				lr.g.report(fmt.Sprintf("run %s: closing its record: %v", lr.id, err))
			}
			lr.cancel()
			return
		}
		if e.reason != "" {
			switch {
			case lr.st.Started():
				var ran int64
				if !startedAt.IsZero() {
					ran = max(time.Since(startedAt).Milliseconds(), 0)
				}
				data := map[string]any{"reason": e.reason, "duration_ms": ran}
				if !lr.client {
					// A session's run: the gateway holds no exit status of its runtime.
					data["state"], data["exit_code"] = "failed", -1
				}
				if e.reason == event.ReasonQuiet {
					data["quiet_seconds"] = e.quietSeconds
				}
				lr.st.Emit(event.RunExited, data)
			case e.from == accesskey.FromApiary:
				// Closed before it started: what today's session records then.
				lr.st.Emit(event.RunRefused, map[string]any{"code": accesskey.CodeRunClosed, "status": 410})
			}
		}
		lr.result, lr.err = lr.st.Close(lr.g.base)
		lr.cancel()
		if lr.cred != nil {
			// Flushed: the gateway lets go of it. After the issuer's end, the refused run
			// keys refuse its run key whether or not they could be written.
			lr.g.retire(lr, key, expires)
		}
	}()
}

// runAnswerDoc is the run answer as the gateway writes it,
// contracts/forager/v1/link-run-answer.schema.json.
type runAnswerDoc struct {
	Version              int                        `json:"version"`
	RunID                string                     `json:"run_id"`
	Credential           string                     `json:"credential"`
	Labels               map[string]string          `json:"labels"`
	Policy               json.RawMessage            `json:"policy,omitempty"`
	Digest               string                     `json:"digest,omitempty"`
	Variables            map[string]server.Variable `json:"variables,omitempty"`
	Details              map[string]string          `json:"details,omitempty"`
	ProxySecret          string                     `json:"proxy_secret"`
	RunSecret            string                     `json:"run_secret"`
	CertificateAuthority string                     `json:"certificate_authority,omitempty"`
	Placeholders         []string                   `json:"placeholders,omitempty"`
	Reserved             []string                   `json:"reserved,omitempty"`
	Image                *server.LinkImage          `json:"image,omitempty"`
	Applied              map[string]any             `json:"applied"`
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

// refresh makes the reload answer of the policy in force, and adds the members of its
// dev.qory.run.policy_applied the gateway decides to those it gave the run. Called with
// lr.mu held.
func (lr *linkRun) refresh() {
	pol := lr.r.Policy()
	applied := appliedOf(pol, lr.r.Held(), lr.r.Chosen(), lr.px.Terminated())
	lr.given = append(lr.given, applied)
	doc, digest := policyDocument(pol)
	lr.reloadBody, _ = json.Marshal(reloadAnswerDoc{
		Version: 1, Policy: doc, Digest: digest, Variables: variables(lr.r.Variables()),
		Placeholders: lr.r.Placeholders(), Reserved: lr.r.Reserved(), Image: lr.image(), Applied: applied,
	})
	sum := sha256.Sum256(lr.reloadBody)
	lr.reloadDigest = "sha256=" + hex.EncodeToString(sum[:])
}

// runAnswer is the run answer, with the run's authority when it has one. Called with
// lr.mu held, after refresh.
func (lr *linkRun) runAnswer(authority []byte) []byte {
	pol := lr.r.Policy()
	doc, digest := policyDocument(pol)
	var details map[string]string
	if lr.cred != nil && len(lr.cred.details) > 0 {
		details = lr.cred.details
	}
	b, _ := json.Marshal(runAnswerDoc{
		Version: 1, RunID: lr.id, Credential: lr.credential(), Labels: lr.labels, Details: details, Policy: doc, Digest: digest, Variables: variables(lr.r.Variables()),
		ProxySecret: lr.secret.reveal(), RunSecret: lr.runSecret.reveal(), CertificateAuthority: string(authority), Placeholders: lr.r.Placeholders(), Reserved: lr.r.Reserved(),
		Image: lr.image(), Applied: lr.given[len(lr.given)-1],
	})
	return b
}

// credential is where the run's credential came from, the credential of its
// run.started: an issuer, for a run on the one address, which a run credential opened;
// none on the local link.
func (lr *linkRun) credential() string {
	if lr.cred != nil {
		return event.CredentialIssuer
	}
	return event.CredentialNone
}

// image is the image the run gets, behind a wall, when it has a reference.
func (lr *linkRun) image() *server.LinkImage {
	img := lr.r.Image()
	if !lr.wall || img.Ref == "" {
		return nil
	}
	return &server.LinkImage{Name: img.Name, Ref: img.Ref, Runtime: img.Runtime, Docker: img.Docker}
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
	out := run.Images{Default: li.Default}
	for _, d := range li.Definitions {
		out.Defined = append(out.Defined, run.Image{Name: d.Name, Ref: d.Ref, Runtime: d.Runtime, Docker: d.Docker})
	}
	return out
}

// appliedOf is what dev.qory.run.policy_applied records of a policy that the gateway
// decides, as today's session writes it: every member but the variables and the
// harness's hosts, which are the session's. It is in JSON's types, as an event's data
// decodes.
func appliedOf(pol *policy.Loaded, held *credential.Held, chosen []tool.Chosen, terminated []string) map[string]any {
	allow, deny := pol.Policy.Egress.Allow, pol.Policy.Egress.Deny
	if allow == nil {
		allow = []string{}
	}
	if deny == nil {
		deny = []string{}
	}
	a := map[string]any{"mode": string(pol.Policy.Egress.Mode), "allow": allow, "deny": deny, "source": pol.Source}
	if pol.Source != "none" {
		a["digest"] = pol.Digest
	}
	if pol.URL != "" {
		a["url"], a["run_configuration"] = pol.URL, pol.RunConfiguration
	}
	if pol.Node != nil {
		np := map[string]any{"digest": pol.Node.Digest}
		if len(pol.Node.Paths) > 0 {
			np["paths"] = pol.Node.Paths
		}
		a["node_policy"] = np
	}
	if len(pol.Policy.Egress.Paths) > 0 {
		a["paths"] = pol.Policy.Egress.Paths
	}
	if held != nil && len(held.Uses) > 0 {
		uses := make([]map[string]any, len(held.Uses))
		for i, u := range held.Uses {
			uses[i] = map[string]any{"name": u.Name, "hosts": u.Hosts, "scheme": u.Scheme}
			if u.Argument != "" {
				uses[i]["argument"] = u.Argument
			}
			if u.Paths != nil {
				uses[i]["paths"] = u.Paths
			}
		}
		a["credentials"] = uses
	}
	if len(chosen) > 0 {
		used := make([]map[string]any, len(chosen))
		for i, c := range chosen {
			used[i] = map[string]any{"name": c.Name, "hosts": c.Serves}
			if c.Argument != "" {
				used[i]["argument"] = c.Argument
			}
		}
		a["tools"] = used
	}
	if pol.Policy.Image != "" {
		a["image"] = pol.Policy.Image
	}
	if len(terminated) > 0 {
		a["terminated"] = terminated
	}
	b, _ := json.Marshal(a)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out
}

// apply puts a policy the reload fetched in force, as today's session does: decided as
// strictly as a start, then set on the run's proxy in one step and committed. The
// session fetches the new policy with its reload and writes its
// dev.qory.run.policy_applied; the tunnels the new policy closed, and every connection
// after the switch, are recorded right after it, today's order, or before the run's
// final event when it never comes. A run with no session has no session to write it:
// the gateway writes it, and what it held follows.
func (lr *linkRun) apply(next *policy.Loaded) error {
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
	refused := lr.px.SetPolicyOpening(in.Mode, in.Allow, in.Deny, d.Guard, in.Paths, d.Uses)
	lr.r.Commit(d)
	lr.posts.SetRunDigest(d.Policy.RunConfiguration)
	lr.mu.Lock()
	defer lr.mu.Unlock()
	lr.refresh()
	// Before the session can see the new digest, so its policy_applied finds the hold
	// waiting for it; the tunnels the policy closed go first.
	data := make([]any, len(refused))
	for i, dec := range refused {
		data[i] = run.Egress(dec)
	}
	if lr.client {
		// No session writes the run's policy_applied: the gateway does, now, and the
		// hold is released right after it, the closed tunnels first.
		lr.st.Await(hold, func(ev *event.Event) bool { return ev.Type == event.PolicyApplied }, event.RunEgress, data...)
		lr.st.Emit(event.PolicyApplied, lr.given[len(lr.given)-1])
		return nil
	}
	lr.st.Await(hold, appliedIs(lr.given[len(lr.given)-1]), event.RunEgress, data...)
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
		if k != "harness_hosts" && k != "variables" {
			own[k] = v
		}
	}
	return own
}
