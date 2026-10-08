package session

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/gateway"
	"github.com/qoryai/runner/policy"
	"github.com/qoryai/runner/refusal"
	"github.com/qoryai/runner/session/internal/variables"
)

// Policy is the run's policy document, contracts/runner/v1/policy.schema.json, as the
// caller hands it to the runner. The runner validates it against the schema before
// anything starts and pins it for the run with the digest of its canonical JSON.
type Policy struct {
	// Version is the document version, 1.
	Version int `json:"version"`
	// Egress is the egress mode, the allow list and the deny list.
	Egress PolicyEgress `json:"egress"`
	// Credentials are the credentials of [Spec.Credentials] the run may use, by name.
	// Nil is no member; an empty list is a member that lists none, which as the node's
	// policy beside a server's allows none of the server's.
	Credentials []PolicyCredential `json:"credentials,omitzero"`
	// Tools are the tools of [Spec.Tools] the run may reach, by name, nil and empty as
	// for Credentials.
	Tools []PolicyTool `json:"tools,omitzero"`
	// Image is the name of the image of [Spec.Images] the run starts in; empty is the
	// machine's default, [Spec.Image].
	Image string `json:"image,omitempty"`
}

// PolicyTool selects one tool the machine defines.
type PolicyTool struct {
	Name string `json:"name"`
	// Argument is what the run asks the tool for, a repository or a prefix say.
	Argument string `json:"argument,omitempty"`
}

// PolicyCredential selects one credential the machine defines.
type PolicyCredential struct {
	Name string `json:"name"`
	// Argument is what the run asks the credential for, a repository say.
	Argument string `json:"argument,omitempty"`
}

// PolicyEgress is the egress section of a [Policy].
type PolicyEgress struct {
	// Mode is observe or enforce.
	Mode string `json:"mode"`
	// Allow are lower-case host names, or *. suffixes, in the contract's grammar. Nil
	// and empty are the same: nothing, which under enforce reaches nothing.
	Allow []string `json:"allow,omitempty"`
	// Deny are hosts the session may not reach, in the same grammar, in either mode: a
	// host an entry covers is denied before Allow and before Mode are consulted, with
	// the entry as its rule.
	Deny []string `json:"deny,omitempty"`
	// Paths are the paths the session may ask of a host, by host. A host listed is one
	// the proxy terminates TLS for.
	Paths map[string][]string `json:"paths,omitempty"`
}

// ReadPolicy reads a policy document from bytes, YAML or JSON by name's extension,
// JSON when it has none, and validates it against the schema: a run's own policy file,
// read by the command that starts the run.
func ReadPolicy(name string, b []byte) (*Policy, error) {
	p, err := policy.Parse(name, b)
	if err != nil {
		return nil, &policy.Error{Name: name, Err: err}
	}
	out := &Policy{Version: p.Version, Egress: PolicyEgress{Mode: string(p.Egress.Mode), Allow: p.Egress.Allow, Deny: p.Egress.Deny, Paths: p.Egress.Paths}, Image: p.Image}
	if p.Credentials != nil {
		out.Credentials = []PolicyCredential{}
	}
	for _, c := range p.Credentials {
		out.Credentials = append(out.Credentials, PolicyCredential{Name: c.Name, Argument: c.Argument})
	}
	if p.Tools != nil {
		out.Tools = []PolicyTool{}
	}
	for _, t := range p.Tools {
		out.Tools = append(out.Tools, PolicyTool{Name: t.Name, Argument: t.Argument})
	}
	return out, nil
}

// Under returns the policy as it stands under a ceiling, the machine's own: a policy
// narrows only. The deny lists of both hold whatever the modes, the ceiling's entries
// first: a deny narrows, so neither side's is dropped. With that, a nil ceiling, or
// one in mode observe, forbids nothing more and the policy stands as it is. Under a
// ceiling in mode enforce the mode is enforce: a policy in mode observe asks for no
// limit of its own and gets the ceiling, and one in mode enforce gets its entries the
// ceiling covers; an entry it does not cover is dropped, as a harness declaration's
// is. Path rules narrow the same way: a host both name keeps the policy's paths the
// ceiling's cover, and a host one of them names keeps its rules. The credentials, the
// tools and the image are the policy's own: a ceiling defines them and selects none.
func (p *Policy) Under(ceiling *Policy) *Policy {
	if ceiling == nil {
		return p
	}
	deny := bothDeny(ceiling.Egress.Deny, p.Egress.Deny)
	if ceiling.Egress.Mode != string(policy.Enforce) {
		if len(ceiling.Egress.Deny) == 0 {
			return p
		}
		c := *p
		c.Egress.Deny = deny
		return &c
	}
	if p.Egress.Mode != string(policy.Enforce) {
		c := *ceiling
		c.Egress.Deny = deny
		c.Credentials, c.Tools, c.Image = p.Credentials, p.Tools, p.Image
		return &c
	}
	allow := []string{}
	for _, entry := range p.Egress.Allow {
		for _, above := range ceiling.Egress.Allow {
			if policy.Covers(above, entry) {
				allow = append(allow, entry)
				break
			}
		}
	}
	paths := map[string][]string{}
	for host, rules := range ceiling.Egress.Paths {
		paths[host] = rules
	}
	for host, rules := range p.Egress.Paths {
		above, both := ceiling.Egress.Paths[host]
		if !both {
			paths[host] = rules
			continue
		}
		kept := []string{}
		for _, r := range rules {
			for _, a := range above {
				if policy.CoversPath(a, r) {
					kept = append(kept, r)
					break
				}
			}
		}
		paths[host] = kept
	}
	if len(paths) == 0 {
		paths = nil
	}
	return &Policy{Version: p.Version, Egress: PolicyEgress{Mode: string(policy.Enforce), Allow: allow, Deny: deny, Paths: paths}, Credentials: p.Credentials, Tools: p.Tools, Image: p.Image}
}

// bothDeny is the deny list of a policy under a ceiling: the ceiling's entries, then
// the policy's that are not already there, and nil when both are empty.
func bothDeny(ceiling, own []string) []string {
	if len(ceiling) == 0 && len(own) == 0 {
		return nil
	}
	out := append([]string{}, ceiling...)
	for _, entry := range own {
		if !slices.Contains(out, entry) {
			out = append(out, entry)
		}
	}
	return out
}

// Variables are the run's and the machine's variables and how a run takes the
// server's: for qory, --env, wall.env and the runner file's variables section.
//
// For each name the highest source that sets it wins: the run's fixed names, those
// the runner, the wall, the runtime's preparation and the placeholders set and
// [Spec.LaunchFixed]; the server's variables, which it resolved among its own levels;
// Run; Machine; [Spec.LaunchDefaults]; [Spec.Env]. A walled run refuses first what
// must stay outside the enclosure: a QORY_ name other than QORY_RUN_ID and
// QORY_RUN_SOCKET, or a variable a machine value is read from, from any of them,
// variable_reserved; any run refuses a value for a placeholder, placeholder_conflict.
// The deny list, the contract's denied-variables.json, the runtime's denies and Deny,
// then leaves out a value of the server, Run, Machine or LaunchDefaults; the built-in
// list alone leaves out one of LaunchFixed. The server's are left out of a run without
// a wall unless Unwalled is [UnwalledAccept]. A value that loses is left out and the
// run starts; dev.qory.run.policy_applied records each name, its source and what lost,
// never a value, and [Spec.OnVariables] receives the same.
type Variables struct {
	// Run are the run's own variables, NAME=value: for qory, --env. They apply with or
	// without a wall.
	Run []string
	// Machine are the machine's variables, NAME=value: for qory, wall.env.
	Machine []string
	// Deny are names and patterns, in which * matches any run of characters, of
	// variables the run leaves out of the server's, Run, Machine and
	// [Spec.LaunchDefaults], matched regardless of case: the runner file's
	// variables.deny.
	Deny []string
	// Unwalled is how a run without a Wall takes the server's variables:
	// [UnwalledAccept] applies them as a walled run does, after the deny list;
	// [UnwalledIgnore], which empty means, leaves them all out. The deny list keeps the
	// wall and the runner whole, not the developer's shell, which accept opens to the
	// server.
	Unwalled string
}

// Applied is the run's variables as resolved: one entry per name, sorted by name, as
// dev.qory.run.policy_applied records them. A name is in it when the server, the run,
// the machine or the harness's defaults set it; a fixed name, and a name of the
// environment the run inherits, only beside one of those.
type Applied []AppliedVariable

// AppliedVariable is one name: the source whose value the run applies, empty when none
// does, and the values that lost, the highest source first.
type AppliedVariable struct {
	Name, From string
	Lost       []Loss
}

// Loss is one source's value that lost, and why.
type Loss struct {
	From, Why string
}

// The sources of a variable, the highest first, and why a value lost, as
// [AppliedVariable] and [Loss] contain them.
const (
	FromFixed   = variables.FromFixed
	FromApiary  = variables.FromApiary
	FromRun     = variables.FromRun
	FromMachine = variables.FromMachine
	FromHarness = variables.FromHarness
	FromShell   = variables.FromShell

	WhyOverridden = variables.WhyOverridden
	WhyDenied     = variables.WhyDenied
	WhyFixed      = variables.WhyFixed
	WhyUnwalled   = variables.WhyUnwalled
)

// applied is the record of a resolution as [Spec.OnVariables] receives it.
func applied(entries []variables.Entry) Applied {
	out := make(Applied, len(entries))
	for i, e := range entries {
		lost := make([]Loss, len(e.Lost))
		for j, l := range e.Lost {
			lost[j] = Loss{From: l.From, Why: l.Why}
		}
		out[i] = AppliedVariable{Name: e.Name, From: e.From, Lost: lost}
	}
	return out
}

// The two values of [Variables.Unwalled].
const (
	UnwalledAccept = variables.Accept
	UnwalledIgnore = variables.Ignore
)

// Server is the server document, contracts/runner/v1/server.schema.json, as the
// caller hands it to the runner: the server whose configuration document says where
// events go and where the run configuration is, the access key the runner signs every
// request as, and the pin, the server's keys every answer is verified under. The
// access key's secret is outside the document: [Spec.AccessKey]. The runner validates
// the document, fetches the configuration document, and posts a ping the server must
// accept, before anything starts.
type Server struct {
	// Version is the document version, 1.
	Version int `json:"version"`
	// URL is the server's origin: https, or http to a loopback address; no path.
	URL string `json:"url"`
	// AccessKeyID is the access key's id, "ak_" and 16 lower-case Crockford base32
	// characters, which the server assigned when the key enrolled.
	AccessKeyID string `json:"access_key_id"`
	// ApiaryPublicKey is the pin: the server's Ed25519 public keys, one or more. A
	// server without a pin is no run, apiary_public_key_missing, before any request.
	ApiaryPublicKey accesskey.Pin `json:"apiary_public_key"`
}

// Credential is one credential as the machine defines it, [Spec.Credentials]: a token
// the runner holds outside the enclosure and the proxy sets on the requests to the
// hosts it is for. A run's policy selects credentials by name and defines none. Exactly
// one of Env, File and Adapter says where the token comes from.
//
// An adapter is a program of the machine's that knows one kind of host, a source code
// host say. The runner starts it outside the enclosure and reads one JSON document
// from its standard output, contracts/runner/v1/credential.schema.json: the token, when
// it expires, and how it is used, the hosts, the scheme and the paths, because hosts
// differ in those and the runner knows none of them.
type Credential struct {
	// Name is what a policy selects it by.
	Name string
	// Env names a variable of the runner's own environment that holds the token.
	Env string
	// File is a path that holds the token, read again whenever it is used.
	File string
	// Adapter is the program and its arguments; ${argument} in an argument is replaced
	// by the argument the run's policy gives.
	Adapter []string
	// Argument is a regular expression the policy's argument must match whole; empty
	// means a policy passes none. Only an adapter takes one.
	Argument string
	// Hosts, Scheme, Username, Header and Paths say how a token from Env or File is
	// used: the scheme is bearer, basic with Username, or header with Header, and nil
	// Paths are every path. For an Adapter, which says all that itself, Hosts and Paths
	// are the most it may claim, when they are set.
	Hosts                    []string
	Scheme, Username, Header string
	Paths                    []string
	// Placeholders are variables the enclosure gets with a value that is no credential,
	// for a program that does not start without one set.
	Placeholders []string
}

// Check refuses a definition that cannot be one, so a command reading the machine's
// configuration says so before any run selects it.
func (c Credential) Check() error { return gateway.CredentialDefinition(c).Check() }

// Tool is one tool as the machine defines it, [Spec.Tools]: a program the runner starts
// for the run, outside the enclosure, that serves hosts. The proxy ends the session's
// TLS for those hosts, decides the host and the path by the policy as for any host, and
// hands every request it lets through to the tool, over a Unix socket the tool listens
// on, as plain HTTP/1.1 with the headers Qory-Request-Id and Qory-Path-Rule. A run's
// policy selects tools by name and defines none.
//
// What the tool does with a request is its own: the protocol, its secrets, whom it
// calls. A path rule reads the path and nothing else, so what a request names beyond
// its path, in its query, its headers or its body, is the tool's to check.
type Tool struct {
	// Name is what a policy selects it by.
	Name string
	// Command is the program and its arguments; ${argument} in an argument is replaced
	// by the argument the run's policy gives. The program gets the runner's own
	// environment, without the variables [Credential.Env] names, with QORY_TOOL_LISTEN,
	// the path of the Unix socket it listens on, and QORY_RUN_ID.
	Command []string
	// Argument is a regular expression the policy's argument must match whole; empty
	// means a policy passes none.
	Argument string
	// Serves are the hosts whose requests go to the tool, in the grammar of the
	// policy's allow list. A host need not exist: a tool with no host of its own serves
	// a name the machine's owner chose, under .internal say, and the proxy never dials
	// it.
	Serves []string
	// Placeholders are variables the enclosure gets with a value that is no credential,
	// for a program that does not start without one set.
	Placeholders []string
}

// Check refuses a definition that cannot be one, so a command reading the machine's
// configuration says so before any run selects it.
func (t Tool) Check() error { return gateway.ToolDefinition(t).Check() }

// Image is one image as the machine defines it, [Spec.Images]: what an agent's
// enclosure is started from, and how. A run's policy selects images by name and names
// no reference, so a repository never chooses what it runs under.
type Image struct {
	// Name is what a policy, or [Spec.Image], selects it by.
	Name string
	// Ref is the image's reference, pinned by digest where the machine wants the same
	// image every time.
	Ref string
	// Runtime is the container runtime the wall starts the image under, one the
	// machine's engine has: sysbox-runc. Empty is the engine's default.
	Runtime string
	// Docker gives the agent a Docker daemon of its own, inside the enclosure: the
	// image holds dockerd, and the wall starts it before the agent. It needs a Runtime
	// that runs a daemon in a container without privileges. Experimental: see contracts/runner/v1/README.md §The wall.
	Docker bool
}

// Check refuses a definition that cannot be one, so a command reading the machine's
// configuration says so before any run selects it.
func (i Image) Check() error {
	if !imageNameShape.MatchString(i.Name) {
		return fmt.Errorf("the image name %q is not 1 to 64 of a-z, 0-9, underscore, dot and dash", i.Name)
	}
	if i.Ref == "" {
		return fmt.Errorf("image %s: the reference is empty", i.Name)
	}
	if i.Docker && i.Runtime == "" {
		return fmt.Errorf("image %s: a Docker of the agent's own needs a runtime that runs one without privileges, such as sysbox-runc", i.Name)
	}
	return nil
}

var imageNameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// image is the image a run starts in: the one its policy selects, or the machine's
// default, [Spec.Image], which is the name of one of [Spec.Images] or a reference.
func image(spec Spec, selected string) (Image, error) {
	for _, d := range spec.Images {
		if err := d.Check(); err != nil {
			return Image{}, err
		}
	}
	if len(spec.Images) > 0 {
		seen := map[string]bool{}
		for _, d := range spec.Images {
			if seen[d.Name] {
				return Image{}, fmt.Errorf("the image %s is defined twice", d.Name)
			}
			seen[d.Name] = true
		}
	}
	name := selected
	if name == "" {
		name = spec.Image
	}
	if i := slices.IndexFunc(spec.Images, func(d Image) bool { return d.Name == name }); i >= 0 {
		return spec.Images[i], nil
	}
	if selected != "" {
		return Image{}, refusal.New(refusal.ImageUnknown, []string{selected}, "the policy selects the image %q, which this machine does not define", selected)
	}
	return Image{Ref: spec.Image}, nil
}
