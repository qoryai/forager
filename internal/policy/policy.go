// Package policy reads the run policy and answers what it allows.
//
// The policy is the document of contracts/runner/v1/policy.schema.json, given to the
// runner once by its caller and pinned for the run. [Read] reads it from bytes: a
// document the schema refuses is a [*Error] and no run; [None] is the absent policy,
// mode observe with no list to deny by. The schema is the reader: a refused document
// carries the schema's message.
//
// A policy narrows only. [Match] says which entry of a list, the allow list's or the
// deny list's, covers a host, and [Covers] whether one entry stands above another,
// which is how a policy is put under a ceiling. [Narrowed] is a server's policy with
// the node's applied to it, which only takes away. Nothing here grants: the widest a
// policy can be is the absent one.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/internal/jcs"
	"github.com/qoryai/runner/internal/refusal"
)

// Mode is the egress mode of a policy.
type Mode string

// The two modes. Observe records every connection and denies only what the deny list
// names; Enforce denies a connection to a host outside the allow list as well, and
// records the denial. The deny list is decided first in either mode.
const (
	Observe Mode = "observe"
	Enforce Mode = "enforce"
)

// Policy is the policy document.
type Policy struct {
	Version int    `json:"version"`
	Egress  Egress `json:"egress"`
	// Credentials and Tools are nil when the document has no such member, and empty
	// when it has an empty list: a node's empty list allows none of a server's.
	Credentials []Selected `json:"credentials,omitzero"`
	Tools       []Selected `json:"tools,omitzero"`
	// Image is the name of the machine's image the run starts in; empty is the
	// machine's default.
	Image string `json:"image,omitempty"`
}

// Egress is the policy's egress section.
type Egress struct {
	Mode  Mode     `json:"mode"`
	Allow []string `json:"allow"`
	// Deny are the hosts the session may not reach, in Allow's grammar, in either
	// mode: a host an entry covers is denied before Allow and before Mode are
	// consulted, with the entry as its rule.
	Deny  []string            `json:"deny,omitempty"`
	Paths map[string][]string `json:"paths,omitempty"`
}

// Selected is one credential or tool of the machine's the policy lets the run use.
type Selected struct {
	Name     string `json:"name"`
	Argument string `json:"argument,omitempty"`
}

// Loaded is a policy as read for a run: the document, where it came from and its
// digest, which is the version stamp of the run's policy.
type Loaded struct {
	Policy Policy
	// Source is "config" when a document was given, "fetched" when the server's run
	// configuration holds it, "none" when there was none.
	Source string
	// Digest is the hex sha256 of the document as canonical JSON, the runner's own
	// serialization of it, when Source is "config" or "fetched": the version stamp of
	// the run's policy, the same for the same policy however it was written.
	Digest string
	// URL is where the run configuration was fetched from, and RunConfiguration the
	// server's digest of it, opaque, when Source is "fetched".
	URL              string
	RunConfiguration string
	// Canonical is "sha256=" and the hex sha256 of the document's RFC 8785
	// serialisation, when Source is "config": what dev.qory.run.policy_applied reports
	// of a node's policy that narrows a server's.
	Canonical string
	// Node is the node's policy when it narrows a server's; nil otherwise.
	Node *Node
}

// Node is the node's side of a policy that narrows a server's: what the record shows
// of it, and its path rules, which every request to a host they list must match as
// well as the server's.
type Node struct {
	// Digest is the node's policy's [Loaded.Canonical].
	Digest string
	// Paths are the node's path rules, nil when it has none.
	Paths map[string][]string
}

// Error is a document that is not a policy. A run does not start on it.
type Error struct {
	// Name is what the caller called the document: a file name, or "policy".
	Name string
	Err  error
}

func (e *Error) Error() string { return "policy " + e.Name + ": " + e.Err.Error() }

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// None is the absent policy: observe everything with no list to deny by, source none.
func None() *Loaded {
	return &Loaded{Policy: Policy{Version: 1, Egress: Egress{Mode: Observe}}, Source: "none"}
}

// Read reads a policy document from bytes, YAML or JSON by name's extension, JSON
// when it has none, validates it and pins it with its digest. A refused document is a
// [*Error] naming name.
func Read(name string, b []byte) (*Loaded, error) {
	p, j, err := parse(name, b)
	if err != nil {
		return nil, &Error{Name: name, Err: err}
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return nil, &Error{Name: name, Err: err}
	}
	sum := sha256.Sum256(canonical)
	c, err := jcs.Canonical(j)
	if err != nil {
		return nil, &Error{Name: name, Err: err}
	}
	jsum := sha256.Sum256(c)
	return &Loaded{Policy: *p, Source: "config", Digest: hex.EncodeToString(sum[:]), Canonical: "sha256=" + hex.EncodeToString(jsum[:])}, nil
}

// Parse validates the bytes of a policy document against the schema and decodes it.
// name chooses YAML or JSON by its extension, JSON when it has none.
func Parse(name string, b []byte) (*Policy, error) {
	p, _, err := parse(name, b)
	return p, err
}

// parse is [Parse], returning the document as JSON as well.
func parse(name string, b []byte) (*Policy, []byte, error) {
	if !strings.Contains(name, ".") {
		name += ".json"
	}
	doc, err := contracts.Decode(name, b)
	if err != nil {
		return nil, nil, err
	}
	schema, err := contracts.Compile("policy.schema.json")
	if err != nil {
		return nil, nil, err
	}
	if err := schema.Validate(doc); err != nil {
		return nil, nil, err
	}
	j, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}
	var p Policy
	if err := json.Unmarshal(j, &p); err != nil {
		return nil, nil, err
	}
	return &p, j, nil
}

// Narrowed is a server's policy, fetched, with the node's policy applied to it: the
// node only narrows. Each field is computed as follows.
//
//   - The mode is enforce when either side's is.
//   - The allow list is the hosts both sides allow, where a side in mode observe allows
//     every host: under enforce on both sides, each side's entries that an entry of
//     the other covers, the server's first, each once; under enforce on one side, that
//     side's entries; under observe on both, the server's.
//   - The deny list is both sides' entries, the server's first, each once.
//   - The path rules are the server's, and the node's go to the proxy beside them as
//     [Node.Paths]: a request to a host either side lists must match an entry of each
//     side that lists it.
//   - The tools are the server's selection, which the node's tools member bounds when
//     the node's document has one: each selected tool must be listed in it by name, and
//     by argument when the node's entry has one, so an empty list allows none. A tool
//     outside it is refused with [refusal.ToolUnknown]. The credentials are bounded the
//     same way.
//   - The image is the one both select, or the one a side selects; two different ones
//     are refused with [refusal.ImageUnknown]. Neither leaves the machine's default.
//
// The result keeps the fetched policy's source, digest and URL, with the node's side in
// [Loaded.Node].
func Narrowed(fetched, node *Loaded) (*Loaded, error) {
	s, n := fetched.Policy, node.Policy
	run := Policy{Version: s.Version, Egress: Egress{Mode: Observe, Paths: s.Egress.Paths}, Credentials: s.Credentials, Tools: s.Tools, Image: s.Image}
	serverEnforces, nodeEnforces := s.Egress.Mode == Enforce, n.Egress.Mode == Enforce
	if serverEnforces || nodeEnforces {
		run.Egress.Mode = Enforce
	}
	switch {
	case serverEnforces && nodeEnforces:
		run.Egress.Allow = union(coveredBy(s.Egress.Allow, n.Egress.Allow), coveredBy(n.Egress.Allow, s.Egress.Allow))
	case nodeEnforces:
		run.Egress.Allow = slices.Clone(n.Egress.Allow)
	default:
		run.Egress.Allow = slices.Clone(s.Egress.Allow)
	}
	if run.Egress.Allow == nil {
		run.Egress.Allow = []string{}
	}
	if len(s.Egress.Deny) > 0 || len(n.Egress.Deny) > 0 {
		run.Egress.Deny = union(s.Egress.Deny, n.Egress.Deny)
	}
	if n.Tools != nil {
		if out := outside(s.Tools, n.Tools); len(out) > 0 {
			return nil, refusal.New(refusal.ToolUnknown, out, "the server's policy selects the tools %s, which the node's policy does not list", strings.Join(out, ", "))
		}
	}
	if n.Credentials != nil {
		if out := outside(s.Credentials, n.Credentials); len(out) > 0 {
			return nil, fmt.Errorf("the server's policy selects the credentials %s, which the node's policy does not list", strings.Join(out, ", "))
		}
	}
	switch {
	case s.Image != "" && n.Image != "" && s.Image != n.Image:
		return nil, refusal.New(refusal.ImageUnknown, []string{s.Image}, "the server's policy selects the image %s and the node's policy the image %s", s.Image, n.Image)
	case s.Image == "":
		run.Image = n.Image
	}
	out := *fetched
	out.Policy = run
	out.Node = &Node{Digest: node.Canonical, Paths: n.Egress.Paths}
	return &out, nil
}

// coveredBy are the entries of list an entry of other covers, in list's order.
func coveredBy(list, other []string) []string {
	var out []string
	for _, entry := range list {
		if slices.ContainsFunc(other, func(above string) bool { return Covers(above, entry) }) {
			out = append(out, entry)
		}
	}
	return out
}

// union is a's entries, then b's that a does not hold, each once.
func union(a, b []string) []string {
	out := []string{}
	for _, entry := range slices.Concat(a, b) {
		if !slices.Contains(out, entry) {
			out = append(out, entry)
		}
	}
	return out
}

// outside names the selections that no entry of bound lists: by name, and by argument
// when the entry has one.
func outside(selected, bound []Selected) []string {
	var out []string
	for _, sel := range selected {
		if !slices.ContainsFunc(bound, func(b Selected) bool {
			return b.Name == sel.Name && (b.Argument == "" || b.Argument == sel.Argument)
		}) {
			out = append(out, sel.Name)
		}
	}
	return out
}

// Covers reports whether an allow entry covers another: a name is covered by the same
// name or by a suffix pattern above it; a pattern is covered by the same pattern or by
// a suffix pattern above it. "*.github.com" covers "api.github.com" and
// "*.api.github.com", not "github.com". An IP literal is covered by an identical entry
// alone, as [Match] matches it: "*.0.0.1" does not cover "10.0.0.1".
func Covers(entry, other string) bool {
	entry, other = strings.ToLower(entry), strings.ToLower(other)
	if entry == other {
		return true
	}
	if net.ParseIP(other) != nil {
		return false
	}
	suffix, isPattern := strings.CutPrefix(entry, "*.")
	if !isPattern {
		return false
	}
	name := strings.TrimPrefix(other, "*.")
	return strings.HasSuffix(name, "."+suffix)
}

// Match returns the first entry of a list, the allow list or the deny list, that
// matches host, and whether one did. A host is compared lower-case and without a
// trailing dot; an IP literal matches only an identical entry; a pattern "*.x"
// matches any host with at least one label before ".x" and never "x" itself.
func Match(entries []string, host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip := net.ParseIP(host) != nil
	for _, entry := range entries {
		e := strings.ToLower(entry)
		if e == host {
			return entry, true
		}
		if ip {
			continue
		}
		if suffix, ok := strings.CutPrefix(e, "*."); ok && strings.HasSuffix(host, "."+suffix) {
			return entry, true
		}
	}
	return "", false
}

// String names the mode for messages.
func (m Mode) String() string { return string(m) }

// Validate reports whether the mode is one of the two.
func (m Mode) Validate() error {
	switch m {
	case Observe, Enforce:
		return nil
	}
	return fmt.Errorf("egress mode %q is neither observe nor enforce", string(m))
}

// MatchPath returns the first of patterns that matches path, and whether one did. A
// pattern is a path matched whole, or up to a final * matched as a prefix. The
// comparison is exact, case included: on a host that ignores case this denies a
// spelling the host would have taken, never the reverse.
func MatchPath(patterns []string, path string) (string, bool) {
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(path, prefix) {
				return p, true
			}
		} else if p == path {
			return p, true
		}
	}
	return "", false
}

// CoversPath reports whether a path pattern covers another: the same pattern, or a
// prefix pattern whose prefix the other starts with.
func CoversPath(entry, other string) bool {
	if entry == other {
		return true
	}
	prefix, ok := strings.CutSuffix(entry, "*")
	return ok && strings.HasPrefix(strings.TrimSuffix(other, "*"), prefix)
}

// CleanPath is the path of a request as a path rule reads it, and whether it can be
// read one way only. escaped is the path as sent. It is refused when it holds an
// encoded slash, backslash, dot or percent sign, a backslash, an empty segment, or a
// dot segment: a proxy and a server that disagree on any of those disagree on which
// rule applies.
func CleanPath(escaped string) (string, bool) {
	if escaped == "" {
		return "/", true
	}
	lower := strings.ToLower(escaped)
	for _, bad := range []string{"%2f", "%5c", "%2e", "%25", "\\", "//", "/./", "/../"} {
		if strings.Contains(lower, bad) {
			return "", false
		}
	}
	if !strings.HasPrefix(escaped, "/") || strings.HasSuffix(escaped, "/.") || strings.HasSuffix(escaped, "/..") {
		return "", false
	}
	for i := 0; i < len(escaped); i++ {
		if c := escaped[i]; c < 0x21 || c == 0x7f {
			return "", false
		}
	}
	return escaped, true
}
