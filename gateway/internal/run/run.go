// Package run holds, for one run, the gateway's side of what a run is given before its
// process starts and while it goes: the policy in force, the credentials the gateway
// holds for it, the tools it starts for it, and what a reload of the server's run
// configuration changes of them.
//
// It decides and holds; it listens on nothing and starts no process but the tools. The
// caller drives it: [Decide] the policy in force, its image and the refusals of a run
// without a wall, [Run.Hold] the credentials and the tools, then the proxy by what the run says
// ([Run.NeedsCA], [Run.Uses], [Run.NodePaths]); on each run configuration the server
// answers, [Run.Read] and [Run.Reload], whose [Decision] the caller puts on the proxy
// and then [Run.Commit]s.
package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/tool"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// Config is what one run is given on the gateway's side.
type Config struct {
	// RunID is the run's id: the tools are started for it.
	RunID string
	// Node is the node's policy; nil means none. Without a server's policy it is the
	// run's, and none is mode observe. Beside a server's policy it narrows that one: the
	// node only takes away.
	Node *Policy
	// Server says the run has a server, whose run configuration a reload may bring
	// later. Fetched implies it.
	Server bool
	// Fetched is the run configuration the server answered for the run's labels; nil
	// when the run has no server, or the server names no run configuration.
	Fetched *Fetched
	// Labels are the run's labels, as the run configuration is asked for by them.
	Labels map[string]string
	// Wall says the run's agent runs behind a wall.
	Wall bool
	// Credentials and Tools are the machine's definitions; the run's policy selects
	// among them by name.
	Credentials []Credential
	Tools       []Tool
	// Images are the images the run's policy selects among, and the one it starts in
	// when the policy selects none; they mean something only behind a wall.
	Images Images
	// Narrowing is the session's narrowing of the policy, behind a separate gateway
	// alone; nil means none. It narrows the start's policy and every policy a reload
	// puts in force.
	Narrowing *Narrowing
	// Passes, when not nil, reports whether the run passes a value of its own for the
	// variable: a placeholder it passes a value for is then placeholder_conflict, at
	// the start and at every reload, as the session refuses it. [Passing] makes one of
	// the names the run passes. Nil passes none, and the placeholders are the caller's
	// to check, with [Run.Conflict].
	Passes func(name string) bool
	// Report receives one line per thing the run reports to its user: a credential's
	// renewal that failed, a tool's standard error, path rules a reload cannot hold.
	// Nil reports nothing.
	Report func(string)
}

// Fetched is one run configuration as the server answered it.
type Fetched struct {
	// URL is where it was fetched from, the configuration document's run section.
	URL string
	// Digest is the server's digest of it, opaque, from the answer's header.
	Digest string
	// Document is the document; nil is one with no member.
	Document *server.RunConfiguration
}

// Run is one run on the gateway's side. Its methods may be called from several
// goroutines.
type Run struct {
	cfg    Config
	labels map[string]string
	defs   []credential.Definition
	tools  []tool.Definition
	// node is the node's policy, nil when the run has none.
	node *policy.Loaded
	// start is the policy pinned at the start: the run's tools are fixed by it, and
	// img is the image it resolved to, fixed too.
	start  *policy.Loaded
	img    Image
	served map[string]string
	server bool
	chosen []tool.Chosen
	// terminates says the proxy holds the run's authority, from the start on.
	terminates bool

	mu sync.Mutex
	// pol is the policy in force, held its credentials, and runDigest the server's
	// digest of the run configuration in force, empty when none was fetched.
	pol *policy.Loaded
	// guard are the names the guard opens under pol ([Run.GuardNames]), and read those
	// of each policy Read made that a reload has not decided yet.
	guard     []string
	read      map[*policy.Loaded][]string
	held      *credential.Held
	runDigest string
}

// Decide is the policy a run starts under, and refuses a run that cannot have it: the
// node's policy, the server's run configuration narrowed by it, or none, mode observe.
// A run without a wall refuses a policy that selects credentials or tools or has path
// rules, the node's beside a server's included, and one that selects an image, a
// [*refusal.NeedsWall]. Behind a
// wall the policy's image is resolved among [Config.Images]: a definition that cannot be
// one, a name defined twice and a name the machine does not define, image_unknown, are
// no run.
func Decide(cfg Config) (*Run, error) {
	if cfg.Report == nil {
		cfg.Report = func(string) {}
	}
	r := &Run{cfg: cfg, labels: maps.Clone(cfg.Labels), server: cfg.Server || cfg.Fetched != nil}
	r.defs = make([]credential.Definition, len(cfg.Credentials))
	for i, c := range cfg.Credentials {
		r.defs[i] = credential.Definition(c)
	}
	r.tools = make([]tool.Definition, len(cfg.Tools))
	for i, t := range cfg.Tools {
		r.tools[i] = tool.Definition(t)
	}
	pol := policy.None()
	if cfg.Node != nil {
		b, _ := json.Marshal(cfg.Node)
		node, err := policy.Read("policy", b)
		if err != nil {
			return nil, err
		}
		r.node, pol = node, node
	}
	if cfg.Fetched == nil {
		r.guard = GuardNames(pol, cfg.Narrowing)
		pol = Narrow(pol, cfg.Narrowing)
	} else {
		fetched, err := r.Read(*cfg.Fetched)
		if err != nil {
			return nil, err
		}
		pol = fetched
		r.guard = r.takeGuard(fetched)
		if cfg.Fetched.Document != nil {
			r.served = cfg.Fetched.Document.Values()
		}
		r.runDigest = pol.RunConfiguration
	}
	if !cfg.Wall {
		if err := needsWall(pol); err != nil {
			return nil, err
		}
	}
	if cfg.Wall {
		img, err := cfg.Images.resolve(pol.Policy.Image)
		if err != nil {
			return nil, err
		}
		r.img = img
	}
	r.start, r.pol = pol, pol
	return r, nil
}

// needsWall refuses what a policy selects that needs a wall, a [*refusal.NeedsWall]
// naming it: credentials, tools and path rules, the node's beside a server's included,
// and an image.
func needsWall(pol *policy.Loaded) error {
	var names []string
	if len(pol.Policy.Credentials) > 0 {
		names = append(names, "credentials")
	}
	if len(pol.Policy.Tools) > 0 {
		names = append(names, "tools")
	}
	if len(pol.Policy.Egress.Paths) > 0 || nodePaths(pol) > 0 {
		names = append(names, "paths")
	}
	if pol.Policy.Image != "" {
		names = append(names, "image="+pol.Policy.Image)
	}
	if names == nil {
		return nil
	}
	return &refusal.NeedsWall{Names: names}
}

// Hold resolves the credentials the policy in force selects and chooses its tools,
// beside them: a credential that does not resolve, a tool that cannot be chosen or
// that cannot be beside the credentials, and a placeholder [Config.Passes] says the run
// passes a value for, are no run. It is called once, after [Decide].
func (r *Run) Hold(ctx context.Context) error {
	held, err := r.hold(ctx, r.start)
	if err != nil {
		return err
	}
	chosen, err := r.choose(held)
	if err != nil {
		held.Close()
		return err
	}
	r.mu.Lock()
	r.held = held
	r.mu.Unlock()
	r.chosen = chosen
	pol := r.start
	r.terminates = len(held.Uses) > 0 || len(chosen) > 0 || len(pol.Policy.Egress.Paths) > 0 || nodePaths(pol) > 0 || (r.cfg.Wall && r.server)
	return nil
}

// Open is [Decide] and then [Run.Hold].
func Open(ctx context.Context, cfg Config) (*Run, error) {
	r, err := Decide(cfg)
	if err != nil {
		return nil, err
	}
	if err := r.Hold(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Close stops the renewals of the credentials the run holds. The tools are the
// caller's to stop, with the set [Run.StartTools] returned.
func (r *Run) Close() {
	r.mu.Lock()
	held := r.held
	r.held = nil
	r.mu.Unlock()
	if held != nil {
		held.Close()
	}
}

// RunID is the run's id.
func (r *Run) RunID() string { return r.cfg.RunID }

// Labels are the run's labels.
func (r *Run) Labels() map[string]string { return maps.Clone(r.labels) }

// Policy is the policy in force: the one the run started under until a reload is
// committed.
func (r *Run) Policy() *policy.Loaded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pol
}

// Digest is the digest of the policy in force, the hex sha256 of its canonical JSON,
// which dev.qory.run.policy_applied reports; empty when no policy is, source none.
func (r *Run) Digest() string {
	pol := r.Policy()
	if pol.Source == "none" {
		return ""
	}
	return pol.Digest
}

// RunConfiguration is the server's digest of the run configuration in force, empty
// when none was fetched.
func (r *Run) RunConfiguration() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runDigest
}

// Variables are the server's variables of the run configuration the run started
// with, nil when it has none. A reload leaves them: they are the run's from its start
// to its end.
func (r *Run) Variables() map[string]string { return maps.Clone(r.served) }

// NodePaths are the node's path rules the proxy holds beside a server's policy, fixed
// for the run so a reload that brings a server's policy is narrowed by them as the
// start is; nil without a server or without a node's policy.
func (r *Run) NodePaths() map[string][]string {
	if r.node == nil || !r.server {
		return nil
	}
	return r.node.Policy.Egress.Paths
}

// Held are the credentials the run holds now.
func (r *Run) Held() *credential.Held {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.held
}

// Uses are the held credentials as the proxy sets them.
func (r *Run) Uses() []proxy.Credential { return ProxyUses(r.Held()) }

// Image is the image the run starts in, resolved among [Config.Images]: zero without a
// wall, and a Ref alone when the default is a reference.
func (r *Run) Image() Image { return r.img }

// Chosen are the run's tools, fixed when it starts.
func (r *Run) Chosen() []tool.Chosen { return r.chosen }

// CredentialPlaceholders are the variables the enclosure gets with a placeholder for
// the credentials the run holds now.
func (r *Run) CredentialPlaceholders() []string {
	held := r.Held()
	if held == nil {
		return nil
	}
	return slices.Clone(held.Placeholders)
}

// ToolPlaceholders are the variables the enclosure gets with a placeholder for the
// run's tools, each once.
func (r *Run) ToolPlaceholders() []string { return tool.Placeholders(r.chosen) }

// Placeholders are the credentials' placeholders and then the tools'.
func (r *Run) Placeholders() []string {
	return slices.Concat(r.CredentialPlaceholders(), r.ToolPlaceholders())
}

// Reserved are the names of the variables the machine's credentials are read from, of
// Forager's own environment: a walled run that passes one into the enclosure is
// variable_reserved, and an unwalled one has its values left out.
func (r *Run) Reserved() []string {
	var out []string
	for _, c := range r.cfg.Credentials {
		if c.Env != "" {
			out = append(out, c.Env)
		}
	}
	return out
}

// Conflict refuses a placeholder the run passes a value for, as passes reports it:
// the credentials' first, then the tools', placeholder_conflict.
func (r *Run) Conflict(passes func(name string) bool) error {
	for _, name := range r.CredentialPlaceholders() {
		if passes(name) {
			return credentialConflict(name)
		}
	}
	for _, name := range r.ToolPlaceholders() {
		if passes(name) {
			return toolConflict(name)
		}
	}
	return nil
}

// NeedsCA says the run has an authority of its own: for the hosts a credential is for,
// the hosts its tools serve and the hosts with path rules, and behind a wall with a
// server always, since a reload may bring a run configuration with path rules or
// credentials, and the enclosure trusts only what it was given at start.
func (r *Run) NeedsCA() bool { return r.terminates }

// ToolEnv is the environment a tool gets: Forager's own, without the variables the
// machine's credentials and the access key are read from, which are Forager's to
// hold and no tool's.
func (r *Run) ToolEnv() []string {
	var out []string
	for _, kv := range accesskey.WithoutVariables(os.Environ()) {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.ContainsFunc(r.cfg.Credentials, func(c Credential) bool { return c.Env == name }) {
			out = append(out, kv)
		}
	}
	return out
}

// StartTools starts the run's tools with [Run.ToolEnv], and waits until each listens.
func (r *Run) StartTools(ctx context.Context) (*tool.Set, error) {
	return tool.Start(ctx, r.chosen, r.cfg.RunID, r.ToolEnv(), r.cfg.Report)
}

// Read reads a run configuration the server answered: the policy it puts in force,
// beside its URL and digest. Without a security_policy it is the node's, or none. With
// one, it is the server's, narrowed by the node's when the run has one. A
// security_policy the schema refuses is run_configuration_invalid.
func (r *Run) Read(f Fetched) (*policy.Loaded, error) {
	var fetched *policy.Loaded
	if f.Document != nil && f.Document.SecurityPolicy != nil {
		var err error
		if fetched, err = policy.Read("run-configuration", f.Document.SecurityPolicy); err != nil {
			return nil, refusal.New(refusal.RunConfigurationInvalid, nil, "run configuration %s: %v", f.URL, err)
		}
		fetched.Source = "fetched"
	}
	pol, err := inForce(fetched, r.node, f.URL, f.Digest)
	if err != nil {
		return nil, fmt.Errorf("run configuration %s: %w", f.URL, err)
	}
	out := Narrow(pol, r.cfg.Narrowing)
	r.mu.Lock()
	if r.read == nil {
		r.read = map[*policy.Loaded][]string{}
	}
	r.read[out] = GuardNames(pol, r.cfg.Narrowing)
	r.mu.Unlock()
	return out, nil
}

// takeGuard is the guard's names of a policy [Run.Read] made, forgotten once taken; the
// policy's own allow list for one it did not make.
func (r *Run) takeGuard(p *policy.Loaded) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names, ok := r.read[p]
	if !ok {
		return p.Policy.Egress.Allow
	}
	delete(r.read, p)
	return names
}

// GuardNames are the names a guarded proxy opens, this machine's own addresses
// reached for them, under pol narrowed by n: the entries of pol's own allow list, as
// its owner wrote them, never a narrowing's. A session's narrowing only narrows, so it
// opens nothing pol does not: under a pol that enforces, pol's names, which the
// narrowed allow list must allow as well; under one that observes, or none, no name
// at all, since every name its allow list holds is the narrowing's to choose. A nil n
// is pol's allow list, as without a narrowing.
func GuardNames(pol *policy.Loaded, n *Narrowing) []string {
	if n == nil {
		return pol.Policy.Egress.Allow
	}
	if pol.Policy.Egress.Mode != policy.Enforce {
		return nil
	}
	return slices.Clone(pol.Policy.Egress.Allow)
}

// GuardNames are the names a guarded proxy opens under the policy in force:
// [GuardNames] of the policy before the session's narrowing.
func (r *Run) GuardNames() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.guard
}

// Narrowing is a session's narrowing of the policy the gateway holds for its run,
// behind a separate gateway alone: the narrowing of link-run-request.schema.json.
type Narrowing struct {
	// Allow, when not nil, puts the narrowing's side under enforce: a host it does not
	// cover is removed. Nil leaves its side under observe.
	Allow []string
	// Deny adds to the hosts denied.
	Deny []string
}

// Narrow is the policy pol narrowed by n, which only narrows: it combines with pol as
// a node's policy narrows a server's ([policy.Narrowed]), n's side under enforce when
// it lists allow and under observe otherwise, its deny added to pol's. The path rules,
// the credentials, the tools, the image, the source's URL and digest of the run
// configuration, and the node's side are pol's. The digest is the narrowed policy's
// own, the hex SHA-256 of its canonical JSON; a policy of source none that a
// narrowing narrows is of source config, the narrowing being the document the session
// passes. A nil n is pol.
func Narrow(pol *policy.Loaded, n *Narrowing) *policy.Loaded {
	if n == nil {
		return pol
	}
	mode := policy.Observe
	if n.Allow != nil {
		mode = policy.Enforce
	}
	side := &policy.Loaded{Policy: policy.Policy{Version: 1, Egress: policy.Egress{Mode: mode, Allow: slices.Clone(n.Allow), Deny: slices.Clone(n.Deny)}}}
	out, err := policy.Narrowed(pol, side)
	if err != nil {
		// The narrowing selects no tool, credential or image, which alone refuse.
		return pol
	}
	out.Node = pol.Node
	if out.Source == "none" {
		out.Source = "config"
	}
	b, _ := json.Marshal(out.Policy)
	sum := sha256.Sum256(b)
	out.Digest = hex.EncodeToString(sum[:])
	return out
}

// Settled reports whether a failed fetch of the run configuration is one the server
// answered and Forager refused, which is not asked for again until the answered digest
// changes: a document the client could not read, a policy the schema refuses, or a
// refusal Forager decides. Any other is asked for again on the next answer.
func Settled(err error) bool {
	var document *server.DocumentError
	var refused *policy.Error
	var code *accesskey.Refusal
	return errors.As(err, &document) || errors.As(err, &refused) || (errors.As(err, &code) && refusal.Decides(code.Code))
}

// Decision is what a reload puts in force, for the caller to set on the run's proxy
// in one step and then [Run.Commit], or to [Decision.Discard].
type Decision struct {
	// Unchanged says the run configuration is the one in force: nothing is set.
	Unchanged bool
	// Policy is the policy put in force, as dev.qory.run.policy_applied records it:
	// without the path rules, and without their hosts in its allow list, when the
	// proxy cannot hold them.
	Policy *policy.Loaded
	// Uses are its credentials as the proxy sets them.
	Uses []proxy.Credential
	// Guard are the names a guarded proxy opens under it ([GuardNames]): those of the
	// policy before the session's narrowing.
	Guard []string
	// Image is the image the policy resolves to, the one the run started in: a reload
	// that resolves to another is refused. Zero without a wall.
	Image Image
	// CredentialsChanged says the policy selects other credentials than the one in
	// force.
	CredentialsChanged bool
	held               *credential.Held
}

// Discard stops the renewals of the decision's credentials, for a decision the
// caller does not put in force.
func (d *Decision) Discard() {
	if d.held != nil {
		d.held.Close()
	}
}

// Reload decides what a run configuration read with [Run.Read] puts in force. One
// that is the one in force is [Decision.Unchanged]. A reload is as strict as a start:
// what a start refuses, a policy that selects credentials without the run's authority,
// an image without a wall, a credential that does not resolve, fails the reload, and
// the policy in force stays; and the run's tools and image are fixed when it starts.
// The image compared is the one the selection resolves to, so naming the machine's
// default, or no longer naming it, is no change. Path rules
// the proxy cannot hold, for want of the run's authority, take their hosts out of the
// allow list instead, so they are not reached on every path, and the caller's user is
// told.
func (r *Run) Reload(ctx context.Context, next *policy.Loaded) (*Decision, error) {
	guard := r.takeGuard(next)
	if next.RunConfiguration == r.RunConfiguration() {
		return &Decision{Unchanged: true, Policy: next}, nil
	}
	d, err := r.decide(ctx, next)
	if d != nil {
		d.Guard = guard
	}
	if err != nil {
		return nil, fmt.Errorf("run configuration %s: %w; the policy in force stays", next.URL, err)
	}
	return d, nil
}

// decide is the reload's check of one policy.
func (r *Run) decide(ctx context.Context, next *policy.Loaded) (*Decision, error) {
	in := *next
	if !sameSelection(in.Policy.Tools, r.start.Policy.Tools) {
		return nil, errors.New("the run configuration selects other tools than the run started with; a run's tools are fixed when it starts")
	}
	if !r.cfg.Wall {
		if in.Policy.Image != "" {
			return nil, fmt.Errorf("the run configuration selects the image %q, which needs a wall", in.Policy.Image)
		}
	} else if next, err := r.cfg.Images.resolve(in.Policy.Image); err != nil {
		return nil, err
	} else if next != r.img {
		return nil, errors.New("the run configuration selects another image than the run started in; a run's image is fixed when it starts")
	}
	if !r.terminates {
		if len(in.Policy.Credentials) > 0 {
			return nil, errors.New("the run configuration selects credentials, which need a wall")
		}
		if len(in.Policy.Egress.Paths) > 0 {
			in.Policy.Egress.Allow = withoutHeld(in.Policy.Egress.Allow, in.Policy.Egress.Paths)
			in.Policy.Egress.Paths = nil
			r.cfg.Report("the run configuration has path rules, which need a wall; the hosts they hold are taken out of the allow list")
		}
	}
	fresh, err := r.hold(ctx, &in)
	if err != nil {
		return nil, err
	}
	if err := tool.Check(r.chosen, in.Policy.Egress.Mode, in.Policy.Egress.Allow, claimedBy(fresh)); err != nil {
		fresh.Close()
		return nil, err
	}
	return &Decision{
		Policy: &in, Uses: ProxyUses(fresh), held: fresh,
		Image:              r.img,
		CredentialsChanged: !sameSelection(in.Policy.Credentials, r.Policy().Policy.Credentials),
	}, nil
}

// Commit puts a decision the caller set on the proxy in force: its policy and its
// credentials are the run's from now on, and the credentials it replaces are closed.
// An unchanged decision changes nothing.
func (r *Run) Commit(d *Decision) {
	if d.Unchanged {
		return
	}
	r.mu.Lock()
	old := r.held
	r.pol, r.held, r.runDigest, r.guard = d.Policy, d.held, d.Policy.RunConfiguration, d.Guard
	r.mu.Unlock()
	if old != nil {
		old.Close()
	}
}

// hold resolves the credentials a policy selects, as the machine defines them, and
// refuses a placeholder the run passes a value for: at the start and at every reload
// alike.
func (r *Run) hold(ctx context.Context, pol *policy.Loaded) (*credential.Held, error) {
	held, err := credential.Resolve(ctx, r.defs, pol.Policy.Credentials, pol.Policy.Egress.Mode, pol.Policy.Egress.Allow, r.cfg.Report)
	if err != nil {
		return nil, err
	}
	if r.cfg.Passes != nil {
		for _, name := range held.Placeholders {
			if r.cfg.Passes(name) {
				held.Close()
				return nil, credentialConflict(name)
			}
		}
	}
	return held, nil
}

// choose resolves the tools the start's policy selects, as the machine defines them,
// beside the credentials the run holds, and refuses a placeholder the run passes a
// value for.
func (r *Run) choose(held *credential.Held) ([]tool.Chosen, error) {
	pol := r.start
	chosen, err := tool.Choose(r.tools, pol.Policy.Tools)
	if err != nil {
		return nil, err
	}
	if err := tool.Check(chosen, pol.Policy.Egress.Mode, pol.Policy.Egress.Allow, claimedBy(held)); err != nil {
		return nil, err
	}
	if r.cfg.Passes != nil {
		for _, name := range tool.Placeholders(chosen) {
			if r.cfg.Passes(name) {
				return nil, toolConflict(name)
			}
		}
	}
	return chosen, nil
}

func credentialConflict(name string) error {
	return refusal.New(refusal.PlaceholderConflict, []string{name}, "%s is a placeholder of a credential the gateway holds outside the enclosure, and the run passes a value for it inside", name)
}

func toolConflict(name string) error {
	return refusal.New(refusal.PlaceholderConflict, []string{name}, "%s is a placeholder of a tool the gateway starts outside the enclosure, and the run passes a value for it inside", name)
}

// inForce is the policy a run configuration puts in force. Without a security_policy it
// is the node's, or none, beside the run configuration's URL and digest. With one, it
// is the server's, narrowed by the node's when the run has one.
func inForce(fetched, node *policy.Loaded, url, digest string) (*policy.Loaded, error) {
	var out policy.Loaded
	switch {
	case fetched == nil && node == nil:
		out = *policy.None()
	case fetched == nil:
		out = *node
	case node == nil:
		out = *fetched
	default:
		narrowed, err := policy.Narrowed(fetched, node)
		if err != nil {
			return nil, err
		}
		out = *narrowed
	}
	out.URL, out.RunConfiguration = url, digest
	return &out, nil
}

// nodePaths is how many hosts the node's path rules list beside a server's policy.
func nodePaths(pol *policy.Loaded) int {
	if pol.Node == nil {
		return 0
	}
	return len(pol.Node.Paths)
}

// claimedBy names the held credential that is for a host, or above or below it; empty
// when none is.
func claimedBy(held *credential.Held) func(string) string {
	return func(host string) string {
		for _, u := range held.Uses {
			for _, h := range u.Hosts {
				if policy.Covers(h, host) || policy.Covers(host, h) {
					return u.Name
				}
			}
		}
		return ""
	}
}

// sameSelection reports whether two selections, of tools or of credentials, are the
// same, in any order.
func sameSelection(a, b []policy.Selected) bool {
	order := func(s []policy.Selected) []policy.Selected {
		s = slices.Clone(s)
		slices.SortFunc(s, func(x, y policy.Selected) int {
			return strings.Compare(x.Name+"\x00"+x.Argument, y.Name+"\x00"+y.Argument)
		})
		return s
	}
	return slices.Equal(order(a), order(b))
}

// withoutHeld is an allow list without the hosts path rules hold, for a proxy that
// cannot hold them: an entry goes when it is a held host, stands under one or stands
// above one, since what stays would be reached on every path. Under enforce the hosts
// are then denied and recorded like any other.
func withoutHeld(allow []string, paths map[string][]string) []string {
	out := []string{}
	for _, entry := range allow {
		keep := true
		for host := range paths {
			if policy.Covers(host, entry) || policy.Covers(entry, host) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, entry)
		}
	}
	return out
}

// ProxyUses are held credentials as the proxy sets them.
func ProxyUses(held *credential.Held) []proxy.Credential {
	if held == nil {
		return nil
	}
	uses := make([]proxy.Credential, len(held.Uses))
	for i, u := range held.Uses {
		uses[i] = proxy.Credential{Name: u.Name, Hosts: u.Hosts, Scheme: u.Scheme, Username: u.Username, Header: u.Header, Paths: u.Paths, Token: u.Token, Rejected: u.Rejected}
	}
	return uses
}

// ProxyTools are running tools as the proxy reaches them.
func ProxyTools(set *tool.Set) []proxy.Tool {
	out := make([]proxy.Tool, len(set.Tools))
	for i, t := range set.Tools {
		out[i] = proxy.Tool{Name: t.Name, Hosts: t.Serves, Socket: t.Socket}
	}
	return out
}

// Egress is the data of the dev.qory.run.egress event of one decision.
func Egress(d proxy.Decision) map[string]any {
	decision := "denied"
	if d.Allowed {
		decision = "allowed"
	}
	data := map[string]any{"host": d.Host, "port": d.Port, "method": d.Method, "decision": decision, "mode": string(d.Mode), "rule": d.Rule, "outcome": d.Outcome}
	if d.Path != "" {
		data["request_method"], data["path"], data["path_rule"] = d.RequestMethod, d.Path, d.PathRule
	}
	if d.Credential != "" {
		data["credential"] = d.Credential
	}
	if d.Tool != "" {
		data["tool"] = d.Tool
	}
	if d.RequestID != "" {
		data["request_id"] = d.RequestID
	}
	if d.Status != 0 {
		data["status"] = d.Status
	}
	return data
}
