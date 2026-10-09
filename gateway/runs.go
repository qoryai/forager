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
	"strconv"
	"strings"
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
	// opened says the run answer is made.
	opened bool
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
	// ended says the run ended at the gateway: how is its 410, and the state and the
	// reason of the gateway's dev.qory.run.exited of it, and closed says it was not the
	// session that ended it.
	ended  bool
	how    runEnd
	closed bool
	// exit is the ask of the run's starter at its runtime's exit, made once: nil until the
	// session asks. Once its answer says the run credential is no longer active, the run
	// is ending: it may still end with its own dev.qory.run.exited until window, when
	// windowEnd ends it as the starter said.
	exit      *exitAsk
	window    time.Time
	windowEnd *time.Timer
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
	// active asks the starter of the latest run credential presented, from the answer
	// it keeps or now, nil for an issuer without introspection, and cache is how long
	// its answer holds.
	expires time.Time
	expiry  *time.Timer
	active  func(ctx context.Context, now bool) error
	cache   time.Duration
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
	// quietSeconds is the quiet period of a run with no session that ended quiet.
	quietSeconds int
}

// runEnd is how a run ended at the gateway, as its later requests learn it: the code and
// the from of its 410, and the state and the reason of the gateway's
// dev.qory.run.exited of it, the state empty for an end that writes none, run_closed,
// and the reason for one without a reason; quietSeconds is the quiet period of a run
// with no session that ended quiet.
type runEnd struct {
	code, from, state, reason string
	quietSeconds              int
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

// credentialExpired ends a run on the one address whose run credential's exp passed
// with no fresh one, cancelled; stopped one whose starter no longer holds its run
// credential active, or ended another run of its run key, and gave no outcome,
// cancelled.
var (
	credentialExpired = ending{reason: event.ReasonCredentialExpired, state: stateCancelled, code: event.ReasonCredentialExpired, from: accesskey.FromGateway, closed: true}
	stopped           = ending{reason: event.ReasonStopped, state: stateCancelled, code: event.ReasonStopped, from: accesskey.FromGateway, closed: true}
)

// starterEnding ends a run whose starter no longer holds its run credential active, or
// ended another run of its run key, as the starter said: its outcome and its reason,
// which may be empty; stopped when it gave no outcome. Its 410 is stopped either way.
func starterEnding(outcome, reason string) ending {
	if outcome == "" {
		return stopped
	}
	return ending{reason: reason, state: outcome, code: event.ReasonStopped, from: accesskey.FromGateway, closed: true}
}

// given is the outcome and the reason the starter gave of the starter's end, each empty
// for none; both empty for any other ending.
func (e ending) given() (outcome, reason string) {
	if e.code != event.ReasonStopped || e.reason == event.ReasonStopped {
		return "", ""
	}
	return e.state, e.reason
}

// runEnd is how the ending answers the run's later requests.
func (e ending) runEnd() runEnd {
	return runEnd{code: e.code, from: e.from, state: e.state, reason: e.reason, quietSeconds: e.quietSeconds}
}

// checkUnreachable ends a run on the one address whose run credential could not be
// checked because the introspection endpoint could not be reached after the tries, and
// checkInvalid one whose endpoint gave no valid answer, each failed. Neither holds the
// run key: the next request opens a run as soon as the endpoint answers active.
var (
	checkUnreachable = ending{reason: event.ReasonCredentialCheckUnreachable, state: stateFailed, code: event.ReasonCredentialCheckUnreachable, from: accesskey.FromGateway, closed: true}
	checkInvalid     = ending{reason: event.ReasonCredentialCheckInvalid, state: stateFailed, code: event.ReasonCredentialCheckInvalid, from: accesskey.FromGateway, closed: true}
)

// The states of the dev.qory.run.exited the gateway writes.
const (
	stateFailed    = event.StateFailed
	stateCancelled = event.StateCancelled
)

// reasonWords are the words a person reads of Forager's own reasons of
// dev.qory.run.exited where a line says how a run ended, those Qory Apiary shows; any
// other reason is the run's starter's, read with spaces for its underscores. quiet's
// words go on with its quiet period, [quietWords].
var reasonWords = map[string]string{
	event.ReasonTimeout:                    "time limit reached",
	event.ReasonQuiet:                      "no activity",
	event.ReasonCredentialExpired:          "permission to run expired",
	event.ReasonStopped:                    "no outcome given",
	event.ReasonSessionLost:                "stopped responding",
	event.ReasonGatewayLost:                "end not recorded",
	event.ReasonBatchRefused:               "events refused",
	event.ReasonCredentialCheckUnreachable: "couldn't check whether the run may go on: no answer",
	event.ReasonCredentialCheckInvalid:     "couldn't check whether the run may go on: unreadable answer",
}

// endWords is how a line says a run ended: the state, and the reason's words after a
// comma when it has one; quiet with the quiet period, quietSeconds, "no activity for 30
// minutes" say.
func endWords(end runEnd) string {
	if end.reason == "" {
		return end.state
	}
	words, ok := reasonWords[end.reason]
	if !ok {
		words = strings.ReplaceAll(end.reason, "_", " ")
	}
	if end.reason == event.ReasonQuiet && end.quietSeconds > 0 {
		words += " for " + quietWords(end.quietSeconds)
	}
	return end.state + ", " + words
}

// quietWords is a quiet period as a person reads it: whole hours, else whole minutes,
// else seconds, "30 minutes" say.
func quietWords(seconds int) string {
	n, unit := seconds, "second"
	switch {
	case seconds%3600 == 0:
		n, unit = seconds/3600, "hour"
	case seconds%60 == 0:
		n, unit = seconds/60, "minute"
	}
	if n != 1 {
		unit += "s"
	}
	return strconv.Itoa(n) + " " + unit
}

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
	// deadline is the latest a try of Qory Apiary's ping or run configuration may start
	// again: [openWindow] after the run request came, or the client's login began.
	deadline time.Time
}

// The tries of Qory Apiary's ping and run configuration as a run opens: up to three of
// each, the second openWaits[0] after the first ends and the third openWaits[1] after
// the second, and a try starts again only within openWindow of the run request's
// arrival, or of the client's login's start. A fast answer to the last try therefore
// arrives by about 6.5 seconds, inside the 10 seconds a session and a client wait.
var (
	openWaits  = []time.Duration{time.Second, 2 * time.Second}
	openWindow = 6 * time.Second
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
// signed 410 to the ping whatever its code, and a document Forager refuses are final.
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
		// A signed 410 to the ping: the server would record nothing of the run.
		return false
	}
	return true
}

// tries asks Qory Apiary with ask, again after a failure that may pass, [openWaits]
// apart, until it answers otherwise, the tries run out, the next would start past
// deadline, or ctx ends; the last try's error is the result.
func (g *Gateway) tries(ctx context.Context, deadline time.Time, ask func() error) error {
	waits := openWaits
	if g.cfg.openWaits != nil {
		waits = g.cfg.openWaits
	}
	for n := 0; ; n++ {
		err := ask()
		if err == nil || !passing(err) || n >= len(waits) || ctx.Err() != nil || time.Now().Add(waits[n]).After(deadline) {
			return err
		}
		t := time.NewTimer(waits[n])
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return err
		}
	}
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
		err = codeless(err)
		if ref := (*accesskey.Refusal)(nil); how.client && errors.As(err, &ref) && ref.Code != "" {
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
				// No failure comes without an error now; should one, the session's going
				// is the error, so no caller takes the missing run for one that opened.
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
		// Each try sends the same delivery id and body, which Qory Apiary deduplicates.
		batch := []byte("[" + string(body) + "]")
		if err := g.tries(ask, how.deadline, func() error { return g.client.Ping(ask, g.conf.Events.URL, pingID, batch) }); err != nil {
			return fail(err)
		}
		lr.live = newLive(ctx, g.client, g.conf, g.confDigest, labels, g.report)
		lr.posts = sink.NewServer(g.client, sink.Target{URL: g.conf.Events.URL, Types: g.conf.Events.Types}, st.Dir(), g.report, lr.live.digests)
		lr.live.posts = lr.posts
		if err := st.Deliver(lr.posts, pingID); err != nil {
			lr.posts.Close(g.base)
			return fail(err)
		}
		// The run configuration, when the server names one: its policy, narrowed by
		// the node's, or the node's own when it has none, and its variables.
		if g.conf.Run != nil {
			var rc *server.RunConfiguration
			var digest string
			if err := g.tries(ask, how.deadline, func() (err error) {
				rc, digest, err = g.client.RunConfiguration(ask, g.conf.Run.URL, labels)
				return err
			}); err != nil {
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
	lr.mu.Lock()
	lr.refresh()
	lr.opened = true
	lr.last = time.Now()
	lr.mu.Unlock()
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
	if lr.ending() {
		// The starter's answer at the runtime's exit wins: the run ends as it says, when
		// its window closes, if not before.
		return
	}
	lr.g.report(fmt.Sprintf("run %s: its run credential expired with no fresh one; the run ends: %s", lr.id, credentialExpired.state))
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

// stillActive asks the starter whether the latest run credential presented for the run
// is still active, and returns nil when the run goes on. It ends the run otherwise and
// returns why: credential_check_unreachable for [runcredential.ErrIssuerUnreachable],
// credential_check_invalid for [runcredential.ErrAnswerInvalid], and for the answer
// that it is no longer active, as the starter said: its outcome and its reason, or
// cancelled and stopped. An answer that the run credential is no longer active holds
// the run key whatever else ended the run meanwhile. A request that went, or a run that
// ended, while the starter was asked is the context's error, and the run is left as it
// is. An issuer without introspection is never asked.
func (lr *linkRun) stillActive(ctx context.Context) error {
	lr.mu.Lock()
	active := lr.cred.active
	lr.asked = time.Now()
	lr.mu.Unlock()
	if active == nil {
		return nil
	}
	err := active(ctx, false)
	if err == nil {
		return nil
	}
	var in *inactive
	if errors.As(err, &in) {
		// The starter's end holds the run key even when the run ended otherwise while it
		// was asked, credential_check_unreachable at another request's say, which holds
		// nothing.
		lr.mu.Lock()
		key, expires := lr.cred.key, lr.cred.expires
		lr.mu.Unlock()
		lr.g.endKey(key, lr.g.heldTo(key, expires), in.outcome, in.reason)
	}
	if ctx.Err() != nil || lr.ctx.Err() != nil {
		// The request went, or the run ended, while the issuer was asked: no answer,
		// and this request alone is not served.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return lr.ctx.Err()
	}
	switch {
	case errors.Is(err, runcredential.ErrIssuerUnreachable):
		lr.g.report(fmt.Sprintf("run %s: its run credential could not be checked: the introspection endpoint could not be reached; the run ends: %s", lr.id, checkUnreachable.state))
		lr.end(checkUnreachable)
	case errors.Is(err, runcredential.ErrAnswerInvalid):
		lr.g.report(fmt.Sprintf("run %s: its run credential could not be checked: %v; the run ends: %s", lr.id, err, checkInvalid.state))
		lr.end(checkInvalid)
	default:
		e := stopped
		if in != nil {
			e = starterEnding(in.outcome, in.reason)
		}
		lr.endAsStarterSaid(e)
	}
	return err
}

// endAsStarterSaid ends the run as its starter said, e, and tells the operator.
func (lr *linkRun) endAsStarterSaid(e ending) {
	lr.g.report(fmt.Sprintf("run %s: its run credential is no longer valid; the run ends: %s", lr.id, endWords(e.runEnd())))
	lr.end(e)
}

// exitAsk is the ask of a run's starter at its runtime's exit, which the session makes
// once, before it writes its dev.qory.run.exited: done is closed once it is answered,
// and the rest is set under the run's mu before. inactive says the starter answered that
// the run credential is no longer active, and state and reason are the outcome and the
// reason it gave then, each empty for none: the outcome answer, {} without a state.
type exitAsk struct {
	done          chan struct{}
	inactive      bool
	state, reason string
}

// exitWindow is how long after the starter's answer at its runtime's exit that the run
// credential is no longer active the run that asked may still end with its own
// dev.qory.run.exited.
const exitWindow = 30 * time.Second

// ending is how the run ends when its window closes, or a request of it the window does
// not take comes: as its starter said, cancelled and stopped when it gave no outcome.
func (x *exitAsk) ending() ending { return starterEnding(x.state, x.reason) }

// closing is the run's ask at its exit whose answer said the run credential is no longer
// active, nil for none, and whether its window is still open: the run is then ending,
// and may end with its own dev.qory.run.exited.
func (lr *linkRun) closing() (*exitAsk, bool) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	x := lr.exit
	if x == nil || lr.window.IsZero() {
		return nil, false
	}
	return x, !lr.ended && time.Now().Before(lr.window)
}

// ending reports whether the run is ending after its starter's answer at its exit, its
// window open: no other end but the starter's comes to it meanwhile.
func (lr *linkRun) ending() bool {
	_, open := lr.closing()
	return open
}

// outcomeAnswer is the answer the run's ask at its exit stored, once it is answered:
// the outcome and the reason the starter gave, the state empty for none; ok is false
// before the ask is answered, and when no one asked.
func (lr *linkRun) outcomeAnswer() (state, reason string, ok bool) {
	lr.mu.Lock()
	x := lr.exit
	lr.mu.Unlock()
	if x == nil {
		return "", "", false
	}
	select {
	case <-x.done:
	default:
		return "", "", false
	}
	return x.state, x.reason, true
}

// askAtExit is the session's ask at its runtime's exit of how the run's starter says
// the run ended: the starter is asked once per run, now and not from the answer kept,
// and every ask of the run waits for that one, and gets the answer it stored. Nil when
// ctx ends first.
func (lr *linkRun) askAtExit(ctx context.Context) *exitAsk {
	lr.mu.Lock()
	x := lr.exit
	if x == nil {
		x = &exitAsk{done: make(chan struct{})}
		lr.exit = x
		go lr.answerAtExit(x, lr.cred.active)
	}
	lr.mu.Unlock()
	select {
	case <-x.done:
		return x
	case <-ctx.Done():
		return nil
	}
}

// answerAtExit asks the starter, with active, how the run ended, and stores its answer
// in x. An answer that the run credential is no longer active holds the run key, as on
// any request of the run's, with the outcome and the reason the starter gave, and the
// run that asked is ending: it may end with its own dev.qory.run.exited until its window
// closes, when it ends as the starter said. An answer active, no answer and one that is
// not valid store {}, and change nothing: the runtime's exit decides. An issuer without
// introspection is not asked.
func (lr *linkRun) answerAtExit(x *exitAsk, active func(context.Context, bool) error) {
	defer close(x.done)
	if active == nil {
		return
	}
	var in *inactive
	if err := active(lr.g.base, true); !errors.As(err, &in) {
		return
	}
	window := exitWindow
	if lr.g.cfg.exitWindow != 0 {
		window = lr.g.cfg.exitWindow
	}
	// The run that asked is ending before the run key is held, so the hold ends none of
	// its requests but as its window says.
	lr.mu.Lock()
	x.inactive, x.state, x.reason = true, in.outcome, in.reason
	if !lr.ended {
		lr.window = time.Now().Add(window)
		lr.windowEnd = time.AfterFunc(window, func() { lr.endAsAnswered(x) })
	}
	key, expires := lr.cred.key, lr.cred.expires
	lr.mu.Unlock()
	lr.g.endKey(key, lr.g.heldTo(key, expires), in.outcome, in.reason)
}

// endAsAnswered ends the run as its starter answered at its exit, x: the window closed,
// or a request of the run that the window does not take came.
func (lr *linkRun) endAsAnswered(x *exitAsk) {
	if _, ended := lr.gone(); ended {
		return
	}
	lr.endAsStarterSaid(x.ending())
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

// touch says the session asked something of the run now.
func (lr *linkRun) touch() {
	lr.mu.Lock()
	lr.last = time.Now()
	lr.mu.Unlock()
}

// watch ends the run when its session has asked nothing of it for the quiet time, and
// otherwise looks again when that time would be up. The session's ask at its runtime's
// exit is a request until the starter answers it, however long that takes.
func (lr *linkRun) watch() {
	lr.mu.Lock()
	if lr.ended {
		lr.mu.Unlock()
		return
	}
	if lr.exit != nil {
		select {
		case <-lr.exit.done:
		default:
			lr.timer = time.AfterFunc(lr.g.quiet, lr.watch)
			lr.mu.Unlock()
			return
		}
	}
	if idle := time.Since(lr.last); idle < lr.g.quiet {
		lr.timer = time.AfterFunc(lr.g.quiet-idle, lr.watch)
		lr.mu.Unlock()
		return
	}
	lr.mu.Unlock()
	if lr.ending() {
		// The run ends as its starter said when its window closes, never session_lost.
		return
	}
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
// flushed and closed. It never blocks, but to keep the run key the gateway refuses
// after the starter's end.
func (lr *linkRun) end(e ending) {
	outcome, reason := e.given()
	if e.blocks() {
		// After the starter's end, the gateway refuses the run key until the latest exp
		// of the run credentials of the run key it still holds, and of any presented
		// during the hold, kept in its directory with how the run ended, so a restart
		// refuses it too: kept before the run is seen to end, so no request that sees the
		// end opens a run of it. Outside the run's lock, which is taken under the
		// gateway's.
		lr.mu.Lock()
		live := !lr.ended && lr.opened && lr.cred != nil
		var key runKeyID
		var expires time.Time
		if live {
			key, expires = lr.cred.key, lr.cred.expires
		}
		lr.mu.Unlock()
		if live {
			lr.g.endKey(key, lr.g.heldTo(key, expires), outcome, reason)
		}
	}
	lr.mu.Lock()
	if lr.ended || !lr.opened {
		lr.mu.Unlock()
		return
	}
	lr.ended, lr.how, lr.closed = true, e.runEnd(), e.closed
	for _, t := range []*time.Timer{lr.timer, lr.quiet, lr.windowEnd} {
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
		lr.g.endKey(key, lr.g.heldTo(key, expires), outcome, reason)
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
		if e.state != "" {
			if lr.st.Started() {
				var ran int64
				if !startedAt.IsZero() {
					ran = max(time.Since(startedAt).Milliseconds(), 0)
				}
				data := map[string]any{"state": e.state, "duration_ms": ran}
				if e.reason != "" {
					data["reason"] = e.reason
				}
				if !lr.client {
					// A session's run: the gateway holds no exit status of its runtime.
					data["exit_code"] = -1
				}
				if e.reason == event.ReasonQuiet {
					data["quiet_seconds"] = e.quietSeconds
				}
				lr.st.Emit(event.RunExited, data)
			}
		}
		lr.result, lr.err = lr.st.Close(lr.g.base)
		lr.cancel()
		if lr.cred != nil {
			// Flushed: the gateway lets go of it. After the starter's end, the refused run
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
// run.started: starter, for a run on the one address, which a run credential opened;
// none on the local link.
func (lr *linkRun) credential() string {
	if lr.cred != nil {
		return event.CredentialStarter
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
