package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/tool"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
)

// Policy is the run's policy document, contracts/forager/v1/policy.schema.json, as the
// caller passes it to Forager. Forager validates it against the schema before
// anything starts, the path rules [Policy.Under] puts beside it included
// ([CheckBeside]), and pins it for the run with the digest of its canonical JSON.
type Policy struct {
	// Version is the document version, 1.
	Version int `json:"version"`
	// Egress is the egress mode, the allow list and the deny list.
	Egress PolicyEgress `json:"egress"`
	// Credentials are the credentials of [Config.Credentials] the run may use, by name.
	// Nil is no member; an empty list is a member that lists none, which as the node's
	// policy beside a server's allows none of the server's.
	Credentials []PolicyCredential `json:"credentials,omitzero"`
	// Tools are the tools of [Config.Tools] the run may reach, by name, nil and empty as
	// for Credentials.
	Tools []PolicyTool `json:"tools,omitzero"`
	// Image is the image the run starts in: the machine's name for one of its images,
	// or a reference pinned by digest under one of the machine's allowed prefixes;
	// empty is the machine's default.
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
	// AllowFirst are hosts the session may reach in either mode, each a lower-case host
	// name or an IPv4 address, never a *. suffix: a host an entry matches exactly is
	// allowed before Deny and Allow are consulted, with the entry as its rule.
	AllowFirst []string `json:"allow_first,omitempty"`
	// Deny are hosts the session may not reach, in the same grammar, in either mode: a
	// host an entry covers is denied before Allow and before Mode are consulted, unless
	// AllowFirst lists the host, with the entry as its rule.
	Deny []string `json:"deny,omitempty"`
	// Paths are the paths the session may ask of a host, by host. A host listed is one
	// the proxy terminates TLS for.
	Paths map[string][]string `json:"paths,omitempty"`
	// beside are further sides of path rules, by host as Paths, each held apart from
	// Paths and from one another: a request to a host a side lists must match an entry
	// of that side as well as of every other side that lists the host. [Policy.Under]
	// puts the ceiling's paths here. No document holds them: the schema has no such
	// member, and JSON leaves them out.
	beside []map[string][]string
}

// ReadPolicy reads a policy document from bytes, YAML or JSON by name's extension,
// JSON when it has none, and validates it against the schema: a run's own policy file,
// read by the command that starts the run.
func ReadPolicy(name string, b []byte) (*Policy, error) {
	p, err := policy.Parse(name, b)
	if err != nil {
		return nil, &policy.Error{Name: name, Err: err}
	}
	out := &Policy{Version: p.Version, Egress: PolicyEgress{Mode: string(p.Egress.Mode), Allow: p.Egress.Allow, AllowFirst: p.Egress.AllowFirst, Deny: p.Egress.Deny, Paths: p.Egress.Paths}, Image: p.Image}
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

// Under returns the policy as it stands under a ceiling, the machine's: a policy
// narrows only. The deny lists of both hold whatever the modes, the ceiling's entries
// first: a deny narrows, so neither side's is dropped. The path rules of each side
// hold whatever the modes, kept apart as a node's paths are beside a server's policy:
// the result's Paths are the policy's, and the ceiling's go beside them, so a request
// to a host either side lists must match an entry of each side that lists it, and the
// mode decides what a miss does. With that, a nil ceiling, or one in mode observe,
// forbids nothing more and the policy's mode and allow list stand. Under a ceiling in
// mode enforce the mode is enforce: a policy in mode observe limits no host and gets
// the ceiling's allow list, and one in mode enforce gets its entries the
// ceiling covers; an entry it does not cover is dropped, as a harness declaration's
// is. The allow_first list is each side's entries that the other side allows, the
// ceiling's first, as [policy.Narrowed] combines it: an entry lifts the deny and allow
// of the side that lists it alone. The credentials, the tools and the image are the
// policy's: a ceiling defines them and selects none. The run's record lists the
// ceiling's path rules in dev.qory.run.policy_applied's ceiling_paths.
func (p *Policy) Under(ceiling *Policy) *Policy {
	if ceiling == nil {
		return p
	}
	deny := bothDeny(ceiling.Egress.Deny, p.Egress.Deny)
	first := policy.First(ceiling.Egress.side(), p.Egress.side())
	beside := sides(p.Egress.beside, []map[string][]string{ceiling.Egress.Paths}, ceiling.Egress.beside)
	var out Policy
	switch {
	case ceiling.Egress.Mode != string(policy.Enforce):
		if len(ceiling.Egress.Deny) == 0 && len(ceiling.Egress.AllowFirst) == 0 && len(beside) == len(p.Egress.beside) {
			return p
		}
		out = *p
	case p.Egress.Mode != string(policy.Enforce):
		out = *ceiling
		out.Credentials, out.Tools, out.Image = p.Credentials, p.Tools, p.Image
	default:
		allow := []string{}
		for _, entry := range p.Egress.Allow {
			for _, above := range ceiling.Egress.Allow {
				if policy.Covers(above, entry) {
					allow = append(allow, entry)
					break
				}
			}
		}
		out = Policy{Version: p.Version, Egress: PolicyEgress{Mode: string(policy.Enforce), Allow: allow}, Credentials: p.Credentials, Tools: p.Tools, Image: p.Image}
	}
	out.Egress.AllowFirst, out.Egress.Deny, out.Egress.Paths, out.Egress.beside = first, deny, p.Egress.Paths, beside
	return &out
}

// side is the egress section as one side of a policy decides a host by.
func (e PolicyEgress) side() policy.Egress {
	return policy.Egress{Mode: policy.Mode(e.Mode), Allow: e.Allow, AllowFirst: e.AllowFirst, Deny: e.Deny}
}

// sides are the sides of path rules of each list, in order, but those that list no
// host, which hold nothing.
func sides(lists ...[]map[string][]string) []map[string][]string {
	var out []map[string][]string
	for _, list := range lists {
		for _, side := range list {
			if len(side) > 0 {
				out = append(out, side)
			}
		}
	}
	return out
}

// CheckBeside validates each side of path rules beside the policy, [Policy.Under]'s,
// against the schema as the paths of a policy document, as the policy is validated: a
// side the schema refuses is a [*policy.Error] naming "policy", and no run.
func CheckBeside(p *Policy) error {
	if p == nil {
		return nil
	}
	return checkSides(p.Egress.beside)
}

// checkSides validates each of sides as [CheckBeside] does. [Decide] gives it the run's
// copy of the sides, the one the proxy and the record hold. Tests replace it.
var checkSides = func(sides []map[string][]string) error {
	for _, side := range sides {
		b, err := json.Marshal(Policy{Version: 1, Egress: PolicyEgress{Mode: string(policy.Observe), Paths: side}})
		if err != nil {
			return &policy.Error{Name: "policy", Err: err}
		}
		if _, err := policy.Read("policy", b); err != nil {
			return err
		}
	}
	return nil
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

// Credential is one credential as the machine defines it, [Config.Credentials]: a
// secret the gateway holds outside the enclosure and the proxy sets on the requests to
// the hosts it is for. A run's policy selects credentials by name and defines none.
// Exactly one of Env, File and Adapter says where the secret comes from.
//
// An adapter is a program of the machine's that knows one kind of host, a source code
// host say. The gateway starts it outside the enclosure and reads one JSON document
// from its standard output, contracts/forager/v1/credential.schema.json: the secret, when
// it expires, and how it is used, the hosts, the scheme and the paths, because hosts
// differ in those and the gateway knows none of them.
type Credential struct {
	// Name is what a policy selects it by.
	Name string
	// Env is a variable of Forager's own environment that holds the secret.
	Env string
	// File is a path that holds the secret, read again whenever it is used.
	File string
	// Adapter is the program and its arguments; ${argument} in an argument is replaced
	// by the argument the run's policy gives.
	Adapter []string
	// Argument is a regular expression the policy's argument must match whole; empty
	// means a policy passes none. Only an adapter takes one.
	Argument string
	// Hosts, Scheme, Username, Header and Paths say how a secret from Env or File is
	// used: the scheme is bearer, basic with Username, or header with Header, and nil
	// Paths are every path. For an Adapter, which says all that itself, Hosts and Paths
	// are the most it may claim, when they are set.
	Hosts                    []string
	Scheme, Username, Header string
	Paths                    []string
	// Placeholders are variables the enclosure gets with a value that is no credential,
	// for a program that does not start without one set.
	Placeholders []string
	// Format, Endpoint, OAuth and KeyPrefixes make the credential a model key, in place
	// of Hosts and Placeholders: Format is its API format, one of
	// api-format.schema.json; Endpoint the base URL of its API, whose host alone gets
	// the key, on every path; OAuth marks a bearer as an OAuth token; and KeyPrefixes
	// the prefixes its secret must start with, nil for any. The session gives the key
	// to the runtime's variable for Format and the scheme, and sets the runtime's
	// endpoint variable to Endpoint.
	Format, Endpoint string
	OAuth            bool
	KeyPrefixes      []string
}

// Check refuses a definition that cannot be one, so a command reading the machine's
// configuration says so before any run selects it.
func (c Credential) Check() error { return credential.Definition(c).Check() }

// Selection is one credential the gateway selects, [Config.Selects]: behind a separate
// gateway, a run gets it, with or without a wall, when the server's policy selects no
// credential. An
// entry for a credential that takes no argument names the credential alone; one for a
// credential that takes an argument names Label, Forge and Pattern as well.
type Selection struct {
	// Name is the credential's, one of [Config.Credentials].
	Name string
	// Label is the run's label whose value is the credential's argument; empty for a
	// credential that takes none.
	Label string
	// Forge is the value the run's forge label must be: a run with another, or none,
	// gets no credential of the entry.
	Forge string
	// Pattern is a regular expression the label's value must match whole: a run whose
	// value it does not match gets no credential of the entry.
	Pattern string
}

// WholeMatch compiles pattern as a [Selection]'s is matched: anchored, so a value
// matches only when the pattern matches all of it. The error of a pattern that does not
// compile alone is that one's; one that compiles alone and not anchored, such as a\Q,
// whose quote takes the anchor's closing in, has the anchored form's.
func WholeMatch(pattern string) (*regexp.Regexp, error) {
	if _, err := regexp.Compile(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile(`^(?:` + pattern + `)$`)
}

// Spaced is text with every control character, C0, DEL and C1, and every format
// character, Cf, the bidirectional overrides among them, a space, but those of keep:
// what a line the gateway prints or answers holds of a value it did not choose, so the
// value can neither break the line, send its reader's terminal an escape, nor show the
// line in another order than it is written.
func Spaced(text string, keep ...rune) string {
	return strings.Map(func(r rune) rune {
		if (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) && !slices.Contains(keep, r) {
			return ' '
		}
		return r
	}, text)
}

// Tool is one tool as the machine defines it, [Config.Tools]: a program the gateway
// starts for the run, outside the enclosure, that serves hosts. The proxy ends the
// session's TLS for those hosts, decides the host and the path by the policy as for any
// host, and hands every request it lets through to the tool, over a Unix socket the
// tool listens on, as plain HTTP/1.1 with the headers Qory-Request-Id and
// Qory-Path-Rule. A run's policy selects tools by name and defines none.
//
// What the tool does with a request is its own: the protocol, its secrets, whom it
// calls. A path rule reads the path and nothing else, so what a request names beyond
// its path, in its query, its headers or its body, is the tool's to check.
type Tool struct {
	// Name is what a policy selects it by.
	Name string
	// Command is the program and its arguments; ${argument} in an argument is replaced
	// by the argument the run's policy gives. The program gets Forager's own
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
func (t Tool) Check() error { return tool.Definition(t).Check() }

// Discovery is what the server's configuration document lists of the run's access key.
type Discovery struct {
	// NodeID is the id of the access key's node, nd_, node pool, np_, or gateway, ng_.
	NodeID string
	// Secrets is true when the document lists a secrets section.
	Secrets bool
}

// Image is one image as the machine defines it: what an agent's enclosure is started
// from, and how. A run's policy selects one by name, or names one by its reference
// pinned by digest under one of the machine's allowed prefixes, [Images.Allow], so a
// repository chooses what it runs under only among what the machine allows.
type Image struct {
	// Name is what a policy, or [Images.Default], selects it by.
	Name string
	// Ref is the image's reference, pinned by digest where the machine wants the same
	// image every time.
	Ref string
	// Runtime is the container runtime the wall starts the image under, one the
	// machine's engine has: sysbox-runc. Empty is the engine's default.
	Runtime string
	// Docker gives the agent a Docker daemon of its own, inside the enclosure: the
	// image holds dockerd, and the wall starts it before the agent. It needs a Runtime
	// that runs a daemon in a container without privileges. Experimental: see
	// contracts/forager/v1/README.md §The wall.
	Docker bool
	// Reference says the run's policy named the image by its reference, Ref, rather
	// than by a name of the machine's: the run starts under the default's Runtime, with
	// no Docker, and the wall fetches the image, unless the engine holds it by that
	// digest, and refuses one whose user is root. It
	// is the gateway's answer alone; no definition sets it.
	Reference bool
}

// Check refuses a definition that cannot be one, so a command reading the machine's
// configuration says so before any run selects it.
func (i Image) Check() error {
	if !imageNameShape.MatchString(i.Name) {
		return fmt.Errorf("the image name %s is not 1 to 64 of a-z, 0-9, underscore, dot and dash", accesskey.ShownName(i.Name, true))
	}
	if i.Ref == "" {
		return fmt.Errorf("image %s: the reference is empty", accesskey.ShownName(i.Name, false))
	}
	if i.Docker && i.Runtime == "" {
		return fmt.Errorf("image %s: nested Docker needs a runtime that runs it without privileges, such as sysbox-runc", accesskey.ShownName(i.Name, false))
	}
	return nil
}

var imageNameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// Images are the session's image table: the images the machine defines, which a run's
// policy selects among by name, the one a run starts in when its policy selects none,
// and the prefixes of the references a policy may name.
type Images struct {
	// Default is the image when the policy selects none: the name of one of Defined, or
	// a reference.
	Default string
	// Defined are the images the machine defines.
	Defined []Image
	// Allow are the prefixes of the references pinned by digest a run's policy may name
	// its image by ([policy.ImageAllowed]): none, nil, allows no reference. A list
	// needs a Default, whose runtime such an image starts under.
	Allow []string
}

// check refuses an image table that cannot be one: a definition that cannot be one, a
// name defined twice, an allow entry that cannot be one ([policy.CheckImagePrefix]),
// and an allow list without a default.
func (im Images) check() error {
	for _, d := range im.Defined {
		if err := d.Check(); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, d := range im.Defined {
		if seen[d.Name] {
			return fmt.Errorf("the image %s is defined twice", accesskey.ShownName(d.Name, false))
		}
		seen[d.Name] = true
	}
	for _, entry := range im.Allow {
		if err := policy.CheckImagePrefix(entry); err != nil {
			return err
		}
	}
	if len(im.Allow) > 0 && im.Default == "" {
		return errors.New("images.allow needs a default image, whose runtime an image by reference starts under")
	}
	return nil
}

// resolve is the image a run starts in: the one its policy selects, or the default,
// which is the name of one of the definitions or a reference. A selection written as a
// reference must be pinned by digest, run_configuration_invalid, and under one of
// Allow, image_not_allowed; it starts under the default's runtime with no Docker.
func (im Images) resolve(selected string) (Image, error) {
	if err := im.check(); err != nil {
		return Image{}, err
	}
	if err := policy.CheckImage(selected); err != nil {
		return Image{}, err
	}
	if policy.ImageReference(selected) {
		if _, ok := policy.ImageAllowed(im.Allow, selected); !ok {
			return Image{}, refusal.New(refusal.ImageNotAllowed, []string{accesskey.ShownName(selected, false)},
				"the image %s is under none of the machine's allowed prefixes (images.allow)", accesskey.ShownName(selected, false))
		}
		def := im.defaultImage()
		return Image{Ref: selected, Runtime: def.Runtime, Reference: true}, nil
	}
	if selected == "" {
		return im.defaultImage(), nil
	}
	if i := slices.IndexFunc(im.Defined, func(d Image) bool { return d.Name == selected }); i >= 0 {
		return im.Defined[i], nil
	}
	return Image{}, refusal.New(refusal.ImageUnknown, []string{accesskey.ShownName(selected, false)}, "the policy selects the image %s, which this machine does not define", accesskey.ShownName(selected, true))
}

// defaultImage is the image a run starts in when its policy selects none: the
// definition Default names, or Default as a reference.
func (im Images) defaultImage() Image {
	if i := slices.IndexFunc(im.Defined, func(d Image) bool { return d.Name == im.Default }); i >= 0 {
		return im.Defined[i]
	}
	return Image{Ref: im.Default}
}

// Passing is a [Config.Passes] of the names of the variables the run passes a value
// for: in what it inherits, what the harness sets, or the run's or the machine's
// variables.
func Passing(names []string) func(name string) bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return func(name string) bool { return set[name] }
}
