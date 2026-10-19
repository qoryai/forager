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

	// batch takes one batch of the session's at a time.
	batch sync.Mutex

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
	// given are the members of dev.qory.run.policy_applied the gateway decides, for each
	// policy it put in force for the run, as the answers carry them.
	given []map[string]any
	// reloadBody is the reload answer as it stands, and reloadDigest its digest, the
	// X-Qory-Run-Configuration of every answer for the run.
	reloadBody   []byte
	reloadDigest string
	// answer is the run answer, given once; it holds the proxy secret, so no print of
	// the run shows it.
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
}

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
}

// The tries of the run's registration with Qory Apiary as a run opens: up to three, each
// with the same bytes, the second openWaits[0] after the first ends and the third
// openWaits[1] after the second, and a try starts again only within openWindow of the
// run request's arrival. A fast answer to the last try therefore arrives by about 6.5
// seconds, inside the 10 seconds a session waits.
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

// open opens a run for a request the link accepted: with a server, the run's
// registration, or on the one address its attach, whose answer is its run
// configuration, the policy in force, the credentials and the tools, the run's proxy,
// under a fresh secret on the local link, and its record. On the one address its proxy
// is guarded whatever its wall, and a record of the run whose open never answered its
// session, of a gateway that stopped as it opened, is removed first, so the run
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
		cancel()
		return nil, true, err
	}
	ask := ctx
	if how.request != nil {
		// Once the session's run request goes, the run's registration is tried no
		// longer, and the run does not open: nothing more is written of
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
				g.report(fmt.Sprintf("run %s: closing its record: %v", req.RunID, accesskey.ShownError(derr)))
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
			regErr = g.tries(ask, how.deadline, func() (err error) {
				rc, digest, err = g.client.Register(ask, conf.Run.URL, body)
				return err
			})
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
	var narrowing *run.Narrowing
	if n := req.Narrowing; n != nil {
		narrowing = &run.Narrowing{Allow: n.Egress.Allow, Deny: n.Egress.Deny}
	}
	var selects []run.Selection
	if remote {
		// The gateway's selection is for a run that attached with a run key alone.
		selects = g.cfg.Selects
	}
	var secrets func(context.Context, string, []string) (sealed.Values, error)
	if g.client != nil {
		secrets = g.secrets(req.RunID)
	}
	r, err := run.Decide(run.Config{
		RunID: req.RunID, Node: g.cfg.Policy, Server: g.client != nil, Fetched: fetched, Labels: decideLabels, Wall: req.Wall,
		Credentials: g.cfg.Credentials, Tools: g.cfg.Tools, Selects: selects, Images: images(req.Images), Passes: run.Passing(req.Passes), Report: g.report,
		Narrowing: narrowing, Secrets: secrets,
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
	if g.cfg.upstreamRoots != nil {
		lr.px.TrustUpstream(g.cfg.upstreamRoots)
	}
	if req.Wall || remote {
		// The proxy serves something that is not on this machine, so this machine's own
		// addresses are not its to reach: an enclosure, or another machine.
		// The names are entries of the node's policy, never of a server's policy or a
		// session's narrowing: neither opens any of this machine's addresses.
		lr.px.Guard(r.GuardNames())
	}
	// The node's path rules, beside a server's, and those put beside the node's policy:
	// fixed for the run, so a reload that brings a server's policy is narrowed by them
	// as the start is.
	if sides := r.NodePaths(); len(sides) > 0 {
		lr.px.NodePaths(sides...)
	}
	var authority []byte
	if r.NeedsCA() {
		ca, err := proxy.NewCA(req.RunID)
		if err != nil {
			return fail(err)
		}
		lr.px.Terminate(ca, r.Uses(), pol.Policy.Egress.Paths, run.ProxyTools(lr.tools))
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
	lr.mu.Lock()
	lr.refresh()
	lr.opened = true
	lr.last = time.Now()
	lr.mu.Unlock()
	if !req.Wall {
		authority = nil
	}
	lr.mu.Lock()
	lr.answer = newSecretValue(string(lr.runAnswer(authority)))
	lr.mu.Unlock()
	return lr, true, nil
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
		lr.timer = time.AfterFunc(lr.g.quiet, lr.watch)
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
	if lr.ended || !lr.opened {
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
	go func() {
		defer close(lr.done)
		lr.release()
		if discarded {
			if err := lr.st.Discard(lr.g.base); err != nil {
				lr.g.report(fmt.Sprintf("run %s: closing its record: %v", lr.id, accesskey.ShownError(err)))
			}
			lr.cancel()
			return
		}
		if e.state != "" && lr.st.Started() {
			var ran int64
			if !startedAt.IsZero() {
				ran = max(time.Since(startedAt).Milliseconds(), 0)
			}
			// A session's run: the gateway holds no exit status of its runtime.
			data := map[string]any{"state": e.state, "duration_ms": ran, "exit_code": -1}
			if e.reason != "" {
				data["reason"] = e.reason
			}
			lr.st.Emit(event.RunExited, data)
		}
		lr.result, lr.err = lr.st.Close(lr.g.base)
		lr.cancel()
		if lr.remote {
			// Flushed: the gateway lets go of it.
			lr.g.retire(lr)
		}
	}()
}

// runAnswerDoc is the run answer as the gateway writes it,
// contracts/forager/v1/link-run-answer.schema.json: on the one address without the
// labels and the proxy secret.
type runAnswerDoc struct {
	Version              int                          `json:"version"`
	RunID                string                       `json:"run_id"`
	Labels               map[string]string            `json:"labels,omitzero"`
	Policy               json.RawMessage              `json:"policy,omitempty"`
	Digest               string                       `json:"digest,omitempty"`
	Variables            map[string]server.Variable   `json:"variables,omitempty"`
	ProxySecret          string                       `json:"proxy_secret,omitempty"`
	CertificateAuthority string                       `json:"certificate_authority,omitempty"`
	Placeholders         []string                     `json:"placeholders,omitempty"`
	Reserved             []string                     `json:"reserved,omitempty"`
	CredentialHosts      []server.LinkCredentialHosts `json:"credential_hosts,omitempty"`
	Image                *server.LinkImage            `json:"image,omitempty"`
	RelayImage           string                       `json:"relay_image,omitempty"`
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

// refresh makes the reload answer of the policy in force, and adds the members of its
// dev.qory.run.policy_applied the gateway decides to those it gave the run. Called with
// lr.mu held.
func (lr *linkRun) refresh() {
	pol := lr.r.Policy()
	applied := appliedOf(pol, lr.r.Beside(), lr.r.Held(), lr.r.Chosen(), lr.px.Terminated())
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
	a := runAnswerDoc{
		Version: 1, RunID: lr.id, Labels: lr.labels, Policy: doc, Digest: digest, Variables: variables(lr.r.Variables()),
		ProxySecret: lr.secret.reveal(), CertificateAuthority: string(authority), Placeholders: lr.r.Placeholders(), Reserved: lr.r.Reserved(),
		CredentialHosts: credentialHosts(lr.r.Held()), Image: lr.image(), Applied: lr.given[len(lr.given)-1],
	}
	if lr.wall {
		a.RelayImage = lr.r.RelayImage()
	}
	if lr.remote {
		a.Labels = nil
	} else if a.Labels == nil {
		a.Labels = map[string]string{}
	}
	b, _ := json.Marshal(a)
	return b
}

// credentialHosts are the run answer's credential_hosts: one entry per credential held,
// from the same uses as appliedOf's credentials; nil when the run holds none.
func credentialHosts(held *credential.Held) []server.LinkCredentialHosts {
	if held == nil {
		return nil
	}
	var out []server.LinkCredentialHosts
	for _, c := range held.Credentials() {
		out = append(out, server.LinkCredentialHosts{Name: c.Name, Hosts: c.Hosts, Placeholders: c.Placeholders})
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
// decides, as today's session writes it: every member but the variables and the
// harness's hosts, which are the session's. beside are the sides of path rules
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
	if pol.Source != "none" {
		a["digest"] = pol.Digest
	}
	if pol.URL != "" {
		// server.Client.Discover refuses a run.url that contains qak_ or qrk_, which no
		// phrase can stand in for: the schema's url is a URI.
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
			// A name or an argument that contains qak_ or qrk_ in any case is sent as
			// accesskey.ShownName's phrase in its place.
			// A host or a path is accesskey.ShownValue's phrase in place of one that
			// contains either.
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
