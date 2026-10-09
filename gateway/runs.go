package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
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
	secret string
	tools  *tool.Set
	posts  *sink.Server
	live   *live
	ctx    context.Context
	cancel context.CancelFunc

	// batch takes one batch of the session's at a time.
	batch sync.Mutex

	mu sync.Mutex
	// opened says the run answer is made; serverClosed that the server closed the run,
	// a signed 410 run_closed.
	opened, serverClosed bool
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
	// answer is the run answer, given once.
	answer []byte
	// last is when the session last asked anything of the run; timer ends the run when
	// it asks nothing for the gateway's quiet time.
	last  time.Time
	timer *time.Timer
	// ended says the run ended at the gateway: endCode and endFrom are its 410, and
	// closed says it was not the session that ended it.
	ended            bool
	endCode, endFrom string
	closed           bool

	// done is closed once the run's gateway side is over and its stream flushed; result
	// and err are then set.
	done   chan struct{}
	result stream.Result
	err    error
}

// ending is how a run ends at the gateway.
type ending struct {
	// reason is the reason of the dev.qory.run.exited the gateway writes, empty for none.
	reason string
	// code and from are the 410 the session's later requests get.
	code, from string
	// closed says the run ended before its session ended it.
	closed bool
}

// sessionLost ends a run whose session the gateway no longer hears or no longer
// accepts.
var sessionLost = ending{reason: event.ReasonSessionLost, code: accesskey.CodeRunClosed, from: accesskey.FromGateway, closed: true}

// serverClosed ends a run the server closed.
var serverClosedRun = ending{reason: event.ReasonRunClosed, code: accesskey.CodeRunClosed, from: accesskey.FromApiary, closed: true}

// open opens a run for a request the link accepted: the ping and the run configuration
// with a server, the policy in force, the credentials and the tools, the run's proxy
// under a fresh secret, and its record. A refusal is an [*accesskey.Refusal]; recorded
// says the run's record was made, so its id is used from now on.
func (g *Gateway) open(req *server.LinkRunRequest) (lr *linkRun, recorded bool, err error) {
	st, err := g.stream.Open(req.RunID)
	if err != nil {
		return nil, false, err
	}
	ctx, cancel := context.WithCancel(g.base)
	labels := maps.Clone(req.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	lr = &linkRun{g: g, id: req.RunID, wall: req.Wall, labels: labels, st: st, ctx: ctx, cancel: cancel, seen: map[string]bool{}, done: make(chan struct{})}
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
		}
		if _, cerr := st.Close(g.base); cerr != nil {
			g.report(fmt.Sprintf("run %s: closing its record: %v", req.RunID, cerr))
		}
		cancel()
		return nil, true, err
	}
	var fetched *run.Fetched
	if g.client != nil {
		ping, err := st.Ping(map[string]any{"forager_version": g.cfg.Version, "events": g.conf.Events.Types, "contract_version": server.Revision, "interval_seconds": g.interval})
		if err != nil {
			return fail(err)
		}
		body, _ := ping.JSON()
		pingID := event.NewID()
		if err := g.client.Ping(ctx, g.conf.Events.URL, pingID, []byte("["+string(body)+"]")); err != nil {
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
			rc, digest, err := g.client.RunConfiguration(ctx, g.conf.Run.URL, labels)
			if err != nil {
				return fail(err)
			}
			fetched = &run.Fetched{URL: g.conf.Run.URL, Digest: digest, Document: rc}
		}
	}
	r, err := run.Decide(run.Config{
		RunID: req.RunID, Node: g.cfg.Policy, Server: g.client != nil, Fetched: fetched, Labels: labels, Wall: req.Wall,
		Credentials: g.cfg.Credentials, Tools: g.cfg.Tools, Images: images(req.Images), Passes: run.Passing(req.Passes), Report: g.report,
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
	if req.Wall {
		// The proxy serves something that is not on this machine, so this machine's own
		// addresses are not its to reach.
		lr.px.Guard(pol.Policy.Egress.Allow)
	}
	// The node's path rules, beside a server's: fixed for the run, so a reload that
	// brings a server's policy is narrowed by them as the start is.
	if paths := r.NodePaths(); paths != nil {
		lr.px.NodePaths(paths)
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
	if lr.secret, err = proxy.NewSecret(); err != nil {
		return fail(err)
	}
	if err := g.proxies.Register(lr.secret, lr.px); err != nil {
		return fail(err)
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
	if !req.Wall {
		authority = nil
	}
	lr.mu.Lock()
	lr.answer = lr.runAnswer(authority)
	lr.mu.Unlock()
	return lr, true, nil
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

// release lets go of what the run holds on the gateway's side: its reload, its secret
// and proxy, its tools and its credentials. Each may be absent.
func (lr *linkRun) release() {
	if lr.live != nil {
		lr.live.stop()
	}
	if lr.secret != "" {
		lr.g.proxies.Unregister(lr.secret)
	}
	if lr.px != nil {
		lr.px.Close()
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
		lr.g.report(fmt.Sprintf("run %s: the server closed the run; it ends", lr.id))
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
// flushed and closed. It never blocks.
func (lr *linkRun) end(e ending) {
	lr.mu.Lock()
	if lr.ended || !lr.opened {
		lr.mu.Unlock()
		return
	}
	lr.ended, lr.endCode, lr.endFrom, lr.closed = true, e.code, e.from, e.closed
	if lr.timer != nil {
		lr.timer.Stop()
	}
	startedAt := lr.startedAt
	lr.mu.Unlock()
	go func() {
		defer close(lr.done)
		lr.release()
		if e.reason != "" {
			switch {
			case lr.st.Started():
				var ran int64
				if !startedAt.IsZero() {
					ran = max(time.Since(startedAt).Milliseconds(), 0)
				}
				lr.st.Emit(event.RunExited, map[string]any{"state": "failed", "exit_code": -1, "reason": e.reason, "duration_ms": ran})
			case e.from == accesskey.FromApiary:
				// Closed before it started: what today's session records then.
				lr.st.Emit(event.RunRefused, map[string]any{"code": accesskey.CodeRunClosed, "status": 410})
			}
		}
		lr.result, lr.err = lr.st.Close(lr.g.base)
		lr.cancel()
	}()
}

// runAnswerDoc is the run answer as the gateway writes it,
// contracts/forager/v1/link-run-answer.schema.json.
type runAnswerDoc struct {
	Version              int                        `json:"version"`
	RunID                string                     `json:"run_id"`
	Labels               map[string]string          `json:"labels"`
	Policy               json.RawMessage            `json:"policy,omitempty"`
	Digest               string                     `json:"digest,omitempty"`
	Variables            map[string]server.Variable `json:"variables,omitempty"`
	ProxySecret          string                     `json:"proxy_secret"`
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
	b, _ := json.Marshal(runAnswerDoc{
		Version: 1, RunID: lr.id, Labels: lr.labels, Policy: doc, Digest: digest, Variables: variables(lr.r.Variables()),
		ProxySecret: lr.secret, CertificateAuthority: string(authority), Placeholders: lr.r.Placeholders(), Reserved: lr.r.Reserved(),
		Image: lr.image(), Applied: lr.given[len(lr.given)-1],
	})
	return b
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
// strictly as a start, then set on the run's proxy in one step and committed; the
// tunnels the new policy closed are recorded after it. The session fetches the new
// policy with its reload and writes its dev.qory.run.policy_applied.
func (lr *linkRun) apply(next *policy.Loaded) error {
	d, err := lr.r.Reload(lr.ctx, next)
	if err != nil {
		return err
	}
	if d.Unchanged {
		return nil
	}
	in := d.Policy.Policy.Egress
	refused := lr.px.SetPolicy(in.Mode, in.Allow, in.Deny, in.Paths, d.Uses)
	lr.r.Commit(d)
	lr.posts.SetRunDigest(d.Policy.RunConfiguration)
	lr.mu.Lock()
	lr.refresh()
	lr.mu.Unlock()
	for _, dec := range refused {
		lr.st.Emit(event.RunEgress, run.Egress(dec))
	}
	return nil
}
