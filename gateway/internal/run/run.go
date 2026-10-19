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
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/tool"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/sealed"
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
	// Labels are the run's labels: on the local link, those the run configuration is
	// asked for by; behind a separate gateway, those the attach's answer gives back of
	// the starter's registration, which the gateway's selection of credentials reads.
	Labels map[string]string
	// Wall says the run's agent runs behind a wall.
	Wall bool
	// Credentials and Tools are the machine's definitions; the run's policy selects
	// among them by name.
	Credentials []Credential
	Tools       []Tool
	// Selects are the gateway's selection among Credentials, for a run that attached
	// with a run key behind a separate gateway; nil on the local link. The run gets it,
	// by its labels, with or without a wall, when the run configuration's policy selects
	// no credential, at the start and at every reload.
	Selects []Selection
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
	// renewal that failed, a tool's standard error, and an entry of the gateway's
	// selection whose credential the run does not get.
	// Nil reports nothing.
	Report func(string)
	// Secrets fetches the values of the credentials of the run configuration the run
	// starts with, by their names in the document's order, under digest, the digest
	// Forager computed of the document's bytes, and opens them: the secrets request,
	// once per run. Nil when the server's discovery lists no secrets endpoint; a run
	// configuration with credentials is then refused.
	Secrets func(ctx context.Context, digest string, credentials []string) (sealed.Values, error)
}

// Fetched is one run configuration as the server answered it.
type Fetched struct {
	// URL is where it was fetched from, the configuration document's run section.
	URL string
	// Digest is the server's digest of it, from the answer's header.
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
	// node is the node's policy, nil when the run has none, and beside the sides of
	// path rules [Policy.Under] put beside it, which no document holds: the run's copy
	// of them, taken when it starts and checked as taken, so the proxy and the record
	// hold them fixed for the run whatever the caller's [Policy] holds afterwards.
	node   *policy.Loaded
	beside []map[string][]string
	// start is the policy pinned at the start: the run's tools are fixed by it, and
	// img is the image it resolved to, fixed too, and named the image its run
	// configuration named, empty when it named none.
	start *policy.Loaded
	img   Image
	named string
	// relay is the reference of the machine's default image, which the wall starts the
	// run's relay from whatever image the run gets.
	relay  string
	served map[string]string
	server bool
	// patterns are the compiled patterns of [Config.Selects], by index, nil for an entry
	// whose credential takes no argument.
	patterns []*regexp.Regexp
	chosen   []tool.Chosen
	// terminates says the proxy holds the run's authority, from the start on.
	terminates bool

	mu sync.Mutex
	// pol is the policy in force, held its credentials, and runDigest the server's
	// digest of the run configuration in force, empty when none was fetched.
	pol *policy.Loaded
	// guard are the names the guard opens under pol ([Run.GuardNames]), and read those
	// of each policy Read made that a reload has not decided yet, and images the image
	// its run configuration named, when it named one.
	guard     []string
	read      map[*policy.Loaded][]string
	images    map[*policy.Loaded]string
	held      *credential.Held
	runDigest string
	// creds are the credentials and the model_credential of each run configuration Read
	// read that a reload has not decided yet.
	creds map[*policy.Loaded]storedSet

	// stored are the credentials of the run configuration the run started with, and
	// values their values as they opened, fixed for the run and cleared by Close.
	// storedModel is its model_credential, empty when it names none.
	stored      []server.RunCredential
	storedModel string
	values      sealed.Values
}

// storedSet is what a run configuration says of the run's credentials: its credentials
// and its model_credential.
type storedSet struct {
	creds []server.RunCredential
	model string
}

// Decide is the policy a run starts under, and refuses a run that cannot have it: the
// node's policy, the server's run configuration narrowed by it, or none, mode observe.
// A run without a wall refuses a policy that selects tools or has path rules, the
// node's beside a server's and a ceiling's the node's policy was put under included,
// and one that selects an image, a [*refusal.NeedsWall]: its credentials are the
// gateway's to set with or without a wall. Behind a wall the
// policy's image, or the one the run configuration names, is resolved among
// [Config.Images]: a definition that cannot be
// one, a name defined twice, an allow list that cannot be one, a name the machine does
// not define, image_unknown, a reference not pinned by digest, run_configuration_invalid,
// and one under none of the allowed prefixes, image_not_allowed, are no run.
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
	r.patterns = make([]*regexp.Regexp, len(cfg.Selects))
	for i, s := range cfg.Selects {
		if s.Label == "" {
			continue
		}
		re, err := WholeMatch(s.Pattern)
		if err != nil {
			return nil, accesskey.ShownError(err)
		}
		r.patterns[i] = re
	}
	pol := policy.None()
	if cfg.Node != nil {
		b, _ := json.Marshal(cfg.Node)
		node, err := policy.Read("policy", b)
		if err != nil {
			return nil, err
		}
		r.beside = copySides(cfg.Node.Egress.beside)
		if err := checkSides(r.beside); err != nil {
			return nil, err
		}
		r.node, pol = node, node
	}
	if cfg.Fetched == nil {
		r.guard = GuardNames(r.node, pol, cfg.Narrowing)
		pol = Narrow(pol, cfg.Narrowing)
	} else {
		fetched, err := r.Read(*cfg.Fetched)
		if err != nil {
			return nil, err
		}
		pol = fetched
		set := r.takeCreds(fetched)
		r.guard, r.named, r.stored, r.storedModel = r.takeGuard(fetched), r.takeNamed(fetched), set.creds, set.model
		if cfg.Fetched.Document != nil {
			r.served = cfg.Fetched.Document.Values()
		}
		r.runDigest = pol.RunConfiguration
	}
	if !cfg.Wall {
		if err := needsWall(pol, len(r.beside) > 0); err != nil {
			return nil, err
		}
	}
	if len(r.stored) > 0 && cfg.Secrets == nil {
		return nil, refusal.New(refusal.RunConfigurationInvalid, nil,
			"run configuration %s: enrol an access key allowed stored secrets: the document has credentials, and Qory Apiary's configuration document lists no secrets endpoint for this access key", accesskey.ShownValue(cfg.Fetched.URL, false))
	}
	if cfg.Wall {
		img, err := cfg.Images.resolve(pol.Policy.Image)
		if err != nil {
			return nil, err
		}
		r.img, r.relay = img, cfg.Images.defaultImage().Ref
	}
	r.start, r.pol = pol, pol
	return r, nil
}

// needsWall refuses what a policy selects that needs a wall, a [*refusal.NeedsWall]
// naming it: tools and path rules, the node's beside a server's and the sides beside
// the node's policy, beside, included, and an image. Credentials need none: a program
// that ignores the proxy sends only their placeholders.
func needsWall(pol *policy.Loaded, beside bool) error {
	var names []string
	if len(pol.Policy.Tools) > 0 {
		names = append(names, "tools")
	}
	if len(pol.Policy.Egress.Paths) > 0 || nodePaths(pol) > 0 || beside {
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
// passes a value for, are no run. When the run configuration the run starts with has
// credentials, it first fetches and opens their values with [Config.Secrets], and
// refuses a value that a header cannot hold. It is called once, after [Decide].
func (r *Run) Hold(ctx context.Context) error {
	if len(r.stored) > 0 {
		if err := r.open(ctx); err != nil {
			return err
		}
	}
	held, err := r.hold(ctx, r.start)
	if err != nil {
		r.clearValues()
		return err
	}
	chosen, err := r.choose(held)
	if err != nil {
		held.Close()
		r.clearValues()
		return err
	}
	r.mu.Lock()
	r.held = held
	r.mu.Unlock()
	r.chosen = chosen
	pol := r.start
	r.terminates = len(held.Uses) > 0 || len(chosen) > 0 || len(pol.Policy.Egress.Paths) > 0 || nodePaths(pol) > 0 || len(r.beside) > 0 || r.server
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

// Close stops the renewals of the credentials the run holds, and overwrites the values
// of the run configuration's credentials. The tools are the caller's to stop, with the
// set [Run.StartTools] returned.
func (r *Run) Close() {
	r.mu.Lock()
	held := r.held
	r.held = nil
	r.mu.Unlock()
	if held != nil {
		held.Close()
	}
	r.clearValues()
}

// open fetches and opens the values of the start's run configuration's credentials,
// under the digest Forager computed of the document's bytes, and refuses a value a
// header cannot hold and a model key's value that starts with none of its
// key_prefixes.
func (r *Run) open(ctx context.Context) error {
	names := make([]string, len(r.stored))
	for i, c := range r.stored {
		names[i] = c.Name
	}
	digest := ""
	if d := r.cfg.Fetched.Document; d != nil {
		digest = d.Computed
	}
	values, err := r.cfg.Secrets(ctx, digest, names)
	if err != nil {
		return err
	}
	for i, name := range names {
		v, _ := values.Value(name)
		if !HeaderValue(v) {
			values.Clear()
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(name),
				"run configuration %s: store another value of the credential %s in Qory Apiary: its value has a control character, or a space or tab at its start or end, which a header value cannot have", accesskey.ShownValue(r.cfg.Fetched.URL, false), accesskey.ShownName(name, true))
		}
		if prefixes := r.stored[i].KeyPrefixes; !credential.KeyMatches(prefixes, v) {
			values.Clear()
			return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(name),
				"run configuration %s: store a value of the credential %s that starts with %s in Qory Apiary: the stored value starts with none of its key_prefixes", accesskey.ShownValue(r.cfg.Fetched.URL, false), accesskey.ShownName(name, true), strings.Join(prefixes, " or "))
		}
	}
	r.mu.Lock()
	r.values = values
	r.mu.Unlock()
	return nil
}

// clearValues overwrites the opened values of the run configuration's credentials,
// under r.mu, so it never overlaps the copy a request takes ([Run.storedUses]).
func (r *Run) clearValues() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values.Clear()
	r.values = sealed.Values{}
}

// HeaderValue reports whether v, UTF-8, holds the contract's rule for a value set in a
// header: no control character but tab, of C0, DEL and C1, and no space or tab at its
// start or end. Every value from the server is held to it, whatever its scheme.
func HeaderValue(v []byte) bool {
	if len(v) == 0 || v[0] == ' ' || v[0] == '\t' || v[len(v)-1] == ' ' || v[len(v)-1] == '\t' {
		return false
	}
	for i := 0; i < len(v); {
		c, size := utf8.DecodeRune(v[i:])
		if c == utf8.RuneError && size <= 1 {
			return false
		}
		if c != '\t' && (c < 0x20 || (c >= 0x7f && c <= 0x9f)) {
			return false
		}
		i += size
	}
	return true
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

// NodePaths are the sides of path rules the proxy holds beside the policy's, fixed for
// the run so a reload that brings a server's policy is narrowed by them as the start
// is: the node's policy's beside a server's, then the sides [Policy.Under] put beside
// the node's policy, with a server or without. Nil when there are none.
func (r *Run) NodePaths() []map[string][]string {
	var out []map[string][]string
	if r.node != nil && r.server && len(r.node.Policy.Egress.Paths) > 0 {
		out = append(out, r.node.Policy.Egress.Paths)
	}
	return append(out, r.beside...)
}

// Beside are the sides of path rules [Policy.Under] put beside the node's policy, one
// per ceiling that has any, in order, fixed for the run: dev.qory.run.policy_applied
// lists them as ceiling_paths. Nil when there are none.
func (r *Run) Beside() []map[string][]string { return slices.Clone(r.beside) }

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

// RelayImage is the reference of the machine's default image, which the wall starts
// the run's relay from: empty without a wall, or when the machine has no default.
func (r *Run) RelayImage() string { return r.relay }

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
// the hosts its tools serve and the hosts with path rules, and with a server always,
// with or without a wall, since a reload may bring a run configuration with
// credentials or path rules, and the agent's tools trust only what they were given at
// the start.
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
// one, it is the server's, narrowed by the node's when the run has one. An image the
// run configuration names is the policy's image selection, which the server's policy
// and the node's must name as well when they name one, else image_unknown. When the
// server's side selects no credential, the run's credentials are the gateway's
// selection, [Config.Selects], capped by the node's credentials member.
// A security_policy the schema refuses, and an image that is not a reference pinned by
// digest, are run_configuration_invalid.
func (r *Run) Read(f Fetched) (*policy.Loaded, error) {
	var fetched *policy.Loaded
	if f.Document != nil && f.Document.SecurityPolicy != nil {
		var err error
		if fetched, err = policy.Read("run-configuration", f.Document.SecurityPolicy); err != nil {
			return nil, refusal.New(refusal.RunConfigurationInvalid, nil, "run configuration %s: %s", accesskey.ShownValue(f.URL, false), accesskey.ShownValue(err.Error(), false))
		}
		fetched.Source = "fetched"
	}
	if f.Document != nil {
		if err := server.CheckCredentials(f.Document.Credentials, f.Document.ModelCredential); err != nil {
			return nil, fmt.Errorf("run configuration %s: %w", accesskey.ShownValue(f.URL, false), err)
		}
	}
	pol, err := inForce(fetched, r.node, f.URL, f.Digest)
	named := ""
	if err == nil && f.Document != nil && f.Document.Image != "" {
		named = f.Document.Image
		err = nameImage(pol, fetched, r.node, named)
	}
	if err == nil && len(r.cfg.Selects) > 0 && (fetched == nil || len(fetched.Policy.Credentials) == 0) {
		err = r.selects(pol)
	}
	if err != nil {
		return nil, fmt.Errorf("run configuration %s: %w", accesskey.ShownValue(f.URL, false), err)
	}
	out := Narrow(pol, r.cfg.Narrowing)
	r.mu.Lock()
	if r.read == nil {
		r.read = map[*policy.Loaded][]string{}
	}
	r.read[out] = GuardNames(r.node, pol, r.cfg.Narrowing)
	if f.Document != nil && (len(f.Document.Credentials) > 0 || f.Document.ModelCredential != "") {
		if r.creds == nil {
			r.creds = map[*policy.Loaded]storedSet{}
		}
		r.creds[out] = storedSet{f.Document.Credentials, f.Document.ModelCredential}
	}
	if named != "" {
		if r.images == nil {
			r.images = map[*policy.Loaded]string{}
		}
		r.images[out] = named
	}
	r.mu.Unlock()
	return out, nil
}

// nameImage puts the image a run configuration names in pol, the policy it puts in
// force, as the policy's image selection. It refuses an image that is not a reference
// pinned by digest, run_configuration_invalid, and one that the server's policy,
// fetched, or the node's selects another image than, image_unknown: a name and a
// reference of one image are two.
func nameImage(pol, fetched, node *policy.Loaded, image string) error {
	if err := server.CheckConfigurationImage(image); err != nil {
		return err
	}
	for _, side := range []struct {
		what string
		pol  *policy.Loaded
	}{{"server's", fetched}, {"node's", node}} {
		if side.pol != nil && side.pol.Policy.Image != "" && side.pol.Policy.Image != image {
			return refusal.New(refusal.ImageUnknown, []string{accesskey.ShownName(image, false)}, "the run configuration names the image %s, and the %s policy the image %s", accesskey.ShownName(image, false), side.what, accesskey.ShownName(side.pol.Policy.Image, false))
		}
	}
	pol.Policy.Image = image
	return nil
}

// selects puts the gateway's selection, [Config.Selects], in the credentials of pol, a
// policy [Run.Read] made whose server's side selects none, narrowed by the node's
// credentials member whenever the node's policy has one, beside a server's policy or
// alone in force, as the server's selection is: a selected credential the member does
// not list is no run. An entry for a credential that takes an argument gives none when
// the run's labels do not satisfy it, and the run's user is told why: a label it takes
// that the run does not have, the forge label among them, a forge label of another
// value, or a value outside its pattern or that is a name's phrase
// ([accesskey.IsNamePhrase]). Nothing is resolved here: the policy's
// credentials are resolved as any are, the argument checked against the definition's
// pattern before its adapter runs.
func (r *Run) selects(pol *policy.Loaded) error {
	id := r.cfg.RunID
	var selected []policy.Selected
	for i, s := range r.cfg.Selects {
		if s.Label == "" {
			selected = append(selected, policy.Selected{Name: s.Name})
			continue
		}
		name := accesskey.ShownName(s.Name, false)
		forge, ok := r.labels["forge"]
		if !ok {
			r.cfg.Report(fmt.Sprintf("run %s: the gateway selects %s by the run's label %s, which the run does not have: it gets no %s", id, name, "forge", name))
			continue
		}
		if forge != s.Forge {
			r.cfg.Report(fmt.Sprintf("run %s: the gateway selects %s for the forge %s, and the run's forge is %s: it gets no %s", id, name, Spaced(accesskey.ShownName(s.Forge, false)), Spaced(accesskey.ShownName(forge, false)), name))
			continue
		}
		value, ok := r.labels[s.Label]
		if !ok {
			r.cfg.Report(fmt.Sprintf("run %s: the gateway selects %s by the run's label %s, which the run does not have: it gets no %s", id, name, Spaced(accesskey.ShownName(s.Label, false)), name))
			continue
		}
		// A value that is a name's phrase, as a separate gateway reads the labels from
		// the attach answer, is no argument, whatever the pattern admits.
		if accesskey.IsNamePhrase(value) || !r.patterns[i].MatchString(value) {
			r.cfg.Report(fmt.Sprintf("run %s: the run's label %s=%s is no argument %s takes: it gets no %s", id, Spaced(accesskey.ShownName(s.Label, false)), Spaced(accesskey.ShownName(value, false)), name, name))
			continue
		}
		selected = append(selected, policy.Selected{Name: s.Name, Argument: value})
	}
	if r.node != nil && r.node.Policy.Credentials != nil {
		var out []string
		for _, sel := range selected {
			if !slices.ContainsFunc(r.node.Policy.Credentials, func(b policy.Selected) bool {
				return b.Name == sel.Name && (b.Argument == "" || b.Argument == sel.Argument)
			}) {
				out = append(out, accesskey.ShownName(sel.Name, false))
			}
		}
		if len(out) > 0 {
			return fmt.Errorf("the gateway selects the credentials %s, which the node's policy does not list", strings.Join(out, ", "))
		}
	}
	if len(selected) > 0 || len(pol.Policy.Credentials) > 0 {
		// The selection is the run's credentials. With the node's policy alone in force,
		// its credentials member is the selection's cap, as beside a server's policy, and
		// not the run's; a member that lists none is kept as written when nothing is
		// selected.
		pol.Policy.Credentials = selected
	}
	return nil
}

// takeGuard is the guard's names of a policy [Run.Read] made, forgotten once taken;
// [GuardNames] of the node's policy and p for one it did not make.
func (r *Run) takeGuard(p *policy.Loaded) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names, ok := r.read[p]
	if !ok {
		return GuardNames(r.node, p, r.cfg.Narrowing)
	}
	delete(r.read, p)
	return names
}

// takeCreds is the credentials and the model_credential of the run configuration of a
// policy [Run.Read] made, empty when it has neither, and forgets them.
func (r *Run) takeCreds(p *policy.Loaded) storedSet {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.creds[p]
	delete(r.creds, p)
	return c
}

// takeNamed is the image the run configuration of a policy [Run.Read] made named,
// empty when it named none, and forgets it.
func (r *Run) takeNamed(p *policy.Loaded) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	named := r.images[p]
	delete(r.images, p)
	return named
}

// GuardNames are the names a guarded proxy opens, this machine's own addresses
// reached for them, under pol, the policy in force before n narrows it: the entries of
// the node's policy's allow list that name a host itself, not a "*." pattern, and that
// pol's allow list matches by [policy.Match]. A server's policy, which pol may be or
// contain, opens nothing: with no node's policy, nil, there is no name. A session's
// narrowing only narrows, so it opens nothing either: under a pol that observes, no
// name at all, since every name its allow list holds is the narrowing's to choose. A
// nil n is no narrowing.
func GuardNames(node, pol *policy.Loaded, n *Narrowing) []string {
	if node == nil || (n != nil && pol.Policy.Egress.Mode != policy.Enforce) {
		return nil
	}
	var out []string
	for _, entry := range node.Policy.Egress.Allow {
		if strings.HasPrefix(entry, "*.") {
			continue
		}
		if _, ok := policy.Match(pol.Policy.Egress.Allow, entry); ok {
			out = append(out, entry)
		}
	}
	return out
}

// GuardNames are the names a guarded proxy opens under the policy in force:
// [GuardNames] of the node's policy and the policy before the session's narrowing.
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
	// Policy is the policy put in force, as dev.qory.run.policy_applied records it.
	Policy *policy.Loaded
	// Uses are its credentials as the proxy sets them.
	Uses []proxy.Credential
	// Guard are the names a guarded proxy opens under it ([GuardNames]): entries of the
	// node's policy that the policy before the session's narrowing allows.
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
// what a start refuses, path rules or an image without a wall, a credential that does
// not resolve, fails the reload, and the policy in force stays; and the run's tools
// and image are fixed when it starts. Whether a name needs a wall is decided by the
// run's wall, as [Decide] decides it, never by the run's authority, which every run
// with a server has. The image compared is the one the selection resolves to, so
// naming the machine's default, or no longer naming it, is no change; an image the run
// configuration names is fixed by the string, so one that differs from the start's,
// appears or disappears is refused.
func (r *Run) Reload(ctx context.Context, next *policy.Loaded) (*Decision, error) {
	guard, named, creds := r.takeGuard(next), r.takeNamed(next), r.takeCreds(next)
	if next.RunConfiguration == r.RunConfiguration() {
		return &Decision{Unchanged: true, Policy: next}, nil
	}
	if !sameCredentials(creds.creds, r.stored) {
		return nil, fmt.Errorf("run configuration %s: start a new run to use other credentials; a run's credentials from Qory Apiary are fixed when it starts, and this run configuration has other credentials than the run started with; the policy in force stays", accesskey.ShownValue(next.URL, false))
	}
	if creds.model != r.storedModel {
		return nil, fmt.Errorf("run configuration %s: start a new run to start with another model key; a run's model_credential is fixed when it starts, and this run configuration names another; the policy in force stays", accesskey.ShownValue(next.URL, false))
	}
	d, err := r.decide(ctx, next, named)
	if d != nil {
		d.Guard = guard
	}
	if err != nil {
		return nil, fmt.Errorf("run configuration %s: %w; the policy in force stays", accesskey.ShownValue(next.URL, false), err)
	}
	return d, nil
}

// decide is the reload's check of one policy, whose run configuration named the image
// named, empty when it named none.
func (r *Run) decide(ctx context.Context, next *policy.Loaded, named string) (*Decision, error) {
	in := *next
	if !sameSelection(in.Policy.Tools, r.start.Policy.Tools) {
		return nil, errors.New("the run configuration selects other tools than the run started with; a run's tools are fixed when it starts")
	}
	if !r.cfg.Wall {
		if in.Policy.Image != "" {
			return nil, fmt.Errorf("the run configuration selects the image %s, which needs a wall", accesskey.ShownName(in.Policy.Image, true))
		}
		// What a start without a wall refuses, a reload refuses too: the run's authority
		// does not decide it, since every run with a server has one.
		if err := needsWall(&in, len(r.beside) > 0); err != nil {
			return nil, err
		}
	} else if named != r.named {
		return nil, r.imageMoved(named)
	} else if next, err := r.cfg.Images.resolve(in.Policy.Image); err != nil {
		return nil, err
	} else if next != r.img {
		return nil, errors.New("the run configuration selects another image than the run started in; a run's image is fixed when it starts")
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

// imageMoved refuses a reload whose run configuration names the image named, or none,
// when the start's named another, or none: the image a run starts in is fixed.
func (r *Run) imageMoved(named string) error {
	started := r.img.Ref
	if r.img.Name != "" {
		started = r.img.Name
	}
	started = accesskey.ShownName(started, false)
	if named == "" {
		return fmt.Errorf("the run configuration names no image, and the run started in %s, which its run configuration named", started)
	}
	return fmt.Errorf("the run configuration names the image %s, and the run started in %s", accesskey.ShownName(named, false), started)
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

// hold resolves the credentials a policy selects, as the machine defines them, beside
// the run configuration's credentials the run started with, which replace a machine's
// credential that claims one of their hosts, and refuses a placeholder the run passes
// a value for: at the start and at every reload alike.
func (r *Run) hold(ctx context.Context, pol *policy.Loaded) (*credential.Held, error) {
	held, err := credential.ResolveWith(ctx, r.defs, pol.Policy.Credentials, r.storedUses(), r.storedModel, pol.Policy.Egress.Mode, pol.Policy.Egress.Allow, r.cfg.Report)
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
	shown := accesskey.ShownName(name, false)
	return refusal.New(refusal.PlaceholderConflict, []string{shown}, "%s is a placeholder of a credential the gateway holds outside the enclosure, and the run passes a value for it inside", shown)
}

func toolConflict(name string) error {
	shown := accesskey.ShownName(name, false)
	return refusal.New(refusal.PlaceholderConflict, []string{shown}, "%s is a placeholder of a tool the gateway starts outside the enclosure, and the run passes a value for it inside", shown)
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

// copySides is a copy of sides of path rules that shares nothing with them: the list,
// each side and each host's paths are new, so a change to the sides the copy was taken
// from leaves the copy as it was. Nil when sides is.
func copySides(sides []map[string][]string) []map[string][]string {
	if sides == nil {
		return nil
	}
	out := make([]map[string][]string, len(sides))
	for i, side := range sides {
		out[i] = make(map[string][]string, len(side))
		for host, paths := range side {
			out[i][host] = slices.Clone(paths)
		}
	}
	return out
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

// storedUses are the run configuration's credentials the run started with, as the
// credential package holds them. Each one's Value copies the opened value under r.mu,
// as [Run.clearValues] clears it, so a request that is still being served when the run
// ends copies the value whole or gets none, and never reads bytes while they are
// overwritten.
func (r *Run) storedUses() []credential.Stored {
	out := make([]credential.Stored, len(r.stored))
	for i, c := range r.stored {
		name := c.Name
		hosts, paths := c.Applies()
		out[i] = credential.Stored{Name: name, Hosts: hosts, Scheme: c.Auth.Scheme, Username: c.Auth.Username, Header: c.Auth.Header,
			Paths: paths, Placeholders: c.Placeholders, Format: c.Format, Endpoint: c.Endpoint, OAuth: c.Auth.OAuth, Value: func() []byte {
				r.mu.Lock()
				defer r.mu.Unlock()
				b, _ := r.values.Value(name)
				return slices.Clone(b)
			}}
	}
	return out
}

// sameCredentials reports whether two run configurations' credentials are the same
// entries, in any order.
func sameCredentials(a, b []server.RunCredential) bool {
	order := func(s []server.RunCredential) []server.RunCredential {
		s = slices.Clone(s)
		slices.SortFunc(s, func(x, y server.RunCredential) int { return strings.Compare(x.Name, y.Name) })
		return s
	}
	return reflect.DeepEqual(order(a), order(b))
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

// ProxyUses are held credentials as the proxy sets them. Of the model keys, the start
// key alone, [credential.Held.Start], is among them, with its placeholder's value: the
// gateway holds the others and sets none of them.
func ProxyUses(held *credential.Held) []proxy.Credential {
	if held == nil {
		return nil
	}
	uses := make([]proxy.Credential, 0, len(held.Uses))
	for _, u := range held.Uses {
		if u.Format != "" && u.Name != held.Start {
			continue
		}
		c := proxy.Credential{Name: u.Name, Hosts: u.Hosts, Scheme: u.Scheme, Username: u.Username, Header: u.Header, Paths: u.Paths}
		if u.Format != "" {
			c.Placeholder = link.KeyPlaceholder(u.Name)
		}
		if u.Stored {
			// The server's value: no renewal, and no Token, so it stays bytes.
			c.Value, c.Stored = u.Value, true
		} else {
			c.Token, c.Rejected = u.Token, u.Rejected
		}
		uses = append(uses, c)
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
	// The host, the path, its rule and the request's method are as the run sent them or
	// the policy gives them: a value that contains qak_ or qrk_ in any case is
	// accesskey.ShownValue's phrase in its place.
	data := map[string]any{"host": accesskey.ShownValue(d.Host, false), "port": d.Port, "method": d.Method, "decision": decision, "mode": string(d.Mode), "rule": d.Rule, "outcome": d.Outcome}
	if d.Path != "" {
		data["request_method"], data["path"], data["path_rule"] = accesskey.ShownValue(d.RequestMethod, false), accesskey.ShownValue(d.Path, false), accesskey.ShownValue(d.PathRule, false)
	}
	// A credential's or a tool's name that contains qak_ or qrk_ in any case is sent as
	// accesskey.ShownName's phrase in its place.
	if d.Credential != "" {
		data["credential"] = accesskey.ShownName(d.Credential, false)
	}
	if d.Tool != "" {
		data["tool"] = accesskey.ShownName(d.Tool, false)
	}
	if d.RequestID != "" {
		data["request_id"] = d.RequestID
	}
	if d.Status != 0 {
		data["status"] = d.Status
	}
	return data
}
