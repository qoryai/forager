package run

import (
	"slices"

	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/tool"
	"github.com/qoryai/forager/policy"
)

// Policy is the run's policy document, contracts/forager/v1/policy.schema.json, as the
// caller passes it to Forager. Forager validates it against the schema before
// anything starts and pins it for the run with the digest of its canonical JSON.
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
	// Image is the name of the image of the machine's the run starts in; empty is the
	// machine's default.
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
}

// Check refuses a definition that cannot be one, so a command reading the machine's
// configuration says so before any run selects it.
func (c Credential) Check() error { return credential.Definition(c).Check() }

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
	// NodeID is the id of the access key's node, nd_, or node pool, np_.
	NodeID string
	// Secrets is true when the document lists a secrets section.
	Secrets bool
}
