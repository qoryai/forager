// Package policy reads the run policy and answers what it allows.
//
// The policy is the document of contracts/forager/v1/policy.schema.json, given to
// Forager once by its caller and pinned for the run. [Read] reads it from bytes: a
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
	"maps"
	"math"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/internal/jcs"
	"github.com/qoryai/forager/refusal"
)

// Mode is the egress mode of a policy.
type Mode string

// The two modes. Observe records every connection and denies only what the deny list
// names; Enforce denies a connection to a host outside the allow list and the
// allow_first list as well, and records the denial. In either mode the allow_first list
// is decided first, then the deny list.
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
	// Image is the image the run starts in: the machine's name for one of its images,
	// or a reference pinned by digest under one of the machine's allowed prefixes;
	// empty is the machine's default.
	Image string `json:"image,omitempty"`
}

// Egress is the policy's egress section.
type Egress struct {
	Mode  Mode     `json:"mode"`
	Allow []string `json:"allow"`
	// AllowFirst are hosts the session may reach in either mode, each a host name or
	// an IPv4 address, never a *. pattern: a host an entry matches exactly ([Exact]) is
	// allowed before Deny and Allow are consulted, with the entry as its rule.
	AllowFirst []string `json:"allow_first,omitempty"`
	// Deny are the hosts the session may not reach, in Allow's grammar, in either
	// mode: a host an entry covers is denied before Allow and before Mode are
	// consulted, unless AllowFirst lists the host, with the entry as its rule.
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
	// Digest is the hex sha256 of the document as canonical JSON, Forager's own
	// serialization of it, when Source is "config" or "fetched": the version stamp of
	// the run's policy, the same for the same policy however it was written.
	Digest string
	// URL is where the run configuration was fetched from, and RunConfiguration the
	// server's digest of it, as the answer's header contained it, when Source is
	// "fetched".
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

// Error prints the name and the error's text as accesskey.ShownValue and
// accesskey.ShownError print them.
func (e *Error) Error() string {
	return "policy " + accesskey.ShownValue(e.Name, false) + ": " + accesskey.ShownError(e.Err).Error()
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// None is the absent policy: observe everything with no list to deny by, source none.
func None() *Loaded {
	return &Loaded{Policy: Policy{Version: 1, Egress: Egress{Mode: Observe}}, Source: "none"}
}

// Read reads a policy document from bytes, YAML or JSON by name's extension, JSON
// when it has none, validates it and pins it with its digest. A refused document is a
// [*Error] naming name; one whose image is a reference not pinned by digest wraps a
// refusal with run_configuration_invalid ([CheckImage]).
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
// name chooses YAML or JSON by its extension, JSON when it has none. An image written
// as a reference that is not pinned by digest is refused before the schema reads it,
// with run_configuration_invalid ([CheckImage]).
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
	if err := checkImage(doc); err != nil {
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
	if err := formed(p.Egress); err != nil {
		return nil, nil, err
	}
	return &p, j, nil
}

// formed refuses an egress entry naming a host, of allow, allow_first, deny or paths,
// that is not in the form [Host] gives it: a name, or an IPv4 address of four decimal
// parts with no leading zero. A *. suffix is held by the schema alone.
func formed(e Egress) error {
	for _, list := range []struct {
		name    string
		entries []string
	}{{"allow", e.Allow}, {"allow_first", e.AllowFirst}, {"deny", e.Deny}, {"paths", slices.Sorted(maps.Keys(e.Paths))}} {
		for _, entry := range list.entries {
			if strings.HasPrefix(entry, "*.") {
				continue
			}
			if form, ok := Host(entry); !ok || form != entry {
				return fmt.Errorf("egress.%s holds %s, which is neither a host name nor an IPv4 address in canonical form", list.name, entry)
			}
		}
	}
	return nil
}

// Narrowed is a server's policy, fetched, with the node's policy applied to it: the
// node only narrows. Each field is computed as follows.
//
//   - The mode is enforce when either side's is.
//   - The allow list is the hosts both sides allow, where a side in mode observe allows
//     every host: under enforce on both sides, each side's entries that an entry of
//     the other covers, the server's first, each once; under enforce on one side, that
//     side's entries; under observe on both, the server's.
//   - The allow_first list is each side's entries that the other side allows
//     ([Egress.Allows]), the server's first, each once: the hosts both sides allow and
//     one of them lists there. An entry lifts the deny and allow of the side that lists
//     it alone, so a host the other side's deny covers, or that the other side's allow
//     does not cover under enforce, stays out.
//   - The deny list is both sides' entries, the server's first, each once.
//   - The path rules are the server's, and the node's go to the proxy beside them as
//     [Node.Paths]: a request to a host either side lists must match an entry of each
//     side that lists it.
//   - The tools are the server's selection, which the node's tools member bounds when
//     the node's document has one: each selected tool must be listed in it by name, and
//     by argument when the node's entry has one, so an empty list allows none. A tool
//     outside it is refused with [refusal.ToolUnknown]. The credentials are bounded the
//     same way.
//   - The image is the one both select, or the one a side selects; two different ones,
//     two strings that are not the same, a name and a reference among them, are
//     refused with [refusal.ImageUnknown]. Neither leaves the machine's default.
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
	run.Egress.AllowFirst = First(s.Egress, n.Egress)
	if len(s.Egress.Deny) > 0 || len(n.Egress.Deny) > 0 {
		run.Egress.Deny = union(s.Egress.Deny, n.Egress.Deny)
	}
	if n.Tools != nil {
		if out := accesskey.ShownNames(outside(s.Tools, n.Tools)); len(out) > 0 {
			return nil, refusal.New(refusal.ToolUnknown, out, "the server's policy selects the tools %s, which the node's policy does not list", strings.Join(out, ", "))
		}
	}
	if n.Credentials != nil {
		if out := accesskey.ShownNames(outside(s.Credentials, n.Credentials)); len(out) > 0 {
			return nil, fmt.Errorf("the server's policy selects the credentials %s, which the node's policy does not list", strings.Join(out, ", "))
		}
	}
	switch {
	case s.Image != "" && n.Image != "" && s.Image != n.Image:
		return nil, refusal.New(refusal.ImageUnknown, []string{accesskey.ShownName(s.Image, false)}, "the server's policy selects the image %s and the node's policy the image %s", accesskey.ShownName(s.Image, false), accesskey.ShownName(n.Image, false))
	case s.Image == "":
		run.Image = n.Image
	}
	out := *fetched
	out.Policy = run
	out.Node = &Node{Digest: node.Canonical, Paths: n.Egress.Paths}
	return &out, nil
}

// Allows reports whether e, one side of a policy, allows host by itself: a host its
// allow_first matches exactly, else one its deny does not cover and, under enforce,
// its allow covers.
func (e Egress) Allows(host string) bool {
	if _, ok := Exact(e.AllowFirst, host); ok {
		return true
	}
	if _, ok := Match(e.Deny, host); ok {
		return false
	}
	if e.Mode != Enforce {
		return true
	}
	_, ok := Match(e.Allow, host)
	return ok
}

// Listed is the allow_first entries, then the allow entries: what a check of a host
// under enforce counts as covering it by [Covers], an allow_first entry covering the
// host it is alone.
func (e Egress) Listed() []string { return slices.Concat(e.AllowFirst, e.Allow) }

// First is the allow_first list of two sides of a policy combined: a's entries that
// b allows ([Egress.Allows]), then b's that a allows, each once, nil when there are
// none. Each entry is a host both sides allow, which the combined policy allows before
// its deny and allow: an entry of one side lifts that side's deny and allow alone.
func First(a, b Egress) []string {
	var out []string
	for _, side := range []struct {
		entries []string
		other   Egress
	}{{a.AllowFirst, b}, {b.AllowFirst, a}} {
		for _, entry := range side.entries {
			if side.other.Allows(entry) && !slices.Contains(out, entry) {
				out = append(out, entry)
			}
		}
	}
	return out
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

// Exact returns the entry of an allow_first list that matches host exactly, and
// whether one did: host compared lower-case and without a trailing dot, so a host
// below an entry is not matched.
func Exact(entries []string, host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, entry := range entries {
		if strings.ToLower(entry) == host {
			return entry, true
		}
	}
	return "", false
}

// Host is the form of a host a request names that a decision is made on and a
// connection dialled to, and whether the host has one. A name is ASCII letters, digits,
// hyphens and dots, lower-cased and without one trailing dot, with no empty label. A
// host is read as an IPv4 address when it ends in a number as the WHATWG URL Standard
// tests it: its last label is all digits, or 0x followed by hex digits or none. It is
// one only as four decimal parts with no leading zero, as [netip.ParseAddr] reads them,
// so 0x7f.example is a name and 127.1 and example.0x1f have no form. A host with a
// colon is an IPv6 address, the inside of a bracketed literal: it is one in RFC 5952's
// form, hex digits in either case, with no zone, and not in ::/96 (except ::1),
// ::ffff:0:0/96, ::ffff:0:0:0/96 or 64:ff9b::/96. Anything else has no form.
func Host(host string) (string, bool) {
	if strings.Contains(host, ":") {
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() || a.Zone() != "" || a.String() != strings.ToLower(host) || embedsIPv4(a) {
			return "", false
		}
		return a.String(), true
	}
	for i := 0; i < len(host); i++ {
		if c := host[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return "", false
		}
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" {
		return "", false
	}
	labels := strings.Split(h, ".")
	if slices.Contains(labels, "") {
		return "", false
	}
	if endsInNumber(labels[len(labels)-1]) {
		if a, err := netip.ParseAddr(h); err != nil || !a.Is4() {
			return "", false
		}
	}
	return h, true
}

// EndpointHost returns the host of a base URL, such as ANTHROPIC_BASE_URL's value, in
// the form [Host] gives, and whether the URL has one. A URL has none when [url.Parse]
// refuses it, when it is opaque or relative, when its scheme is not https (compared
// without regard to case), when it has user information ("https://a@b/"), when its
// host is empty, when [Host] refuses its host, or when its port is not a decimal number
// from 1 to 65535. The host is read as url.Parse decodes it, without the brackets of an
// IPv6 literal. A URL with no port, or with nothing after the port's colon, has a host
// if the rest allows it. The host does not depend on the path, query or fragment, but
// url.Parse refuses a bad percent escape in the path or fragment, and such a URL has no
// host.
func EndpointHost(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || !u.IsAbs() || u.Scheme != "https" || u.User != nil || u.Hostname() == "" {
		return "", false
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", false
		}
	}
	return Host(u.Hostname())
}

// CredentialFor reports whether a credential with hosts, entries in the allow list's
// grammar, is for host: host's form under [Host], matched against hosts by [Match]. A
// host with no form is in no credential's hosts. A private host is in a credential's
// hosts only through an entry equal to it, compared lower-case, and never through a
// "*." pattern. A private host is an IP literal in 10.0.0.0/8, 172.16.0.0/12,
// 192.168.0.0/16 or fc00::/7, the ranges [netip.Addr.IsPrivate] reports; a name of one
// label, such as litellm; or a name that ends in ".local", ".internal" or ".home.arpa".
// Only a name with one of these endings can get a result other than [Match]'s: Match
// compares an IP literal only to an identical entry, and a "*." pattern matches no name
// of one label. The gateway's proxy picks a request's credential by this rule.
func CredentialFor(hosts []string, host string) bool {
	h, ok := Host(host)
	if !ok {
		return false
	}
	if private(h) {
		for _, entry := range hosts {
			if strings.ToLower(entry) == h {
				return true
			}
		}
		return false
	}
	_, ok = Match(hosts, h)
	return ok
}

// private reports whether h, a host in [Host]'s form, is a private host as
// [CredentialFor] reads one.
func private(h string) bool {
	if a, err := netip.ParseAddr(h); err == nil {
		return a.IsPrivate()
	}
	return !strings.Contains(h, ".") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".home.arpa")
}

// embedded are the IPv6 ranges a host has no form in, each holding an IPv4 address in
// its last 32 bits: ::/96, the IPv4-compatible addresses, other than ::1, which is in
// it but has a form; ::ffff:0:0/96, the IPv4-mapped ones; ::ffff:0:0:0/96, the
// IPv4-translated ones; and 64:ff9b::/96, the well-known NAT64 prefix. Other ranges
// that hold one, such as 2002::/16, are not among them.
var embedded = []netip.Prefix{
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
}

// embedsIPv4 reports whether a is in one of the embedded ranges, ::1 apart: the
// loopback address carries no IPv4 address.
func embedsIPv4(a netip.Addr) bool {
	if a == netip.IPv6Loopback() {
		return false
	}
	for _, p := range embedded {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// numeric reports whether s is all decimal digits.
func numeric(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// endsInNumber reports whether a host's last label, lower-cased, makes it end in a
// number as the WHATWG URL Standard tests it: all decimal digits, or 0x followed by hex
// digits or none.
func endsInNumber(last string) bool {
	if digits, ok := strings.CutPrefix(last, "0x"); ok {
		return strings.Trim(digits, "0123456789abcdef") == ""
	}
	return numeric(last)
}

// HostPaths returns the entry of a policy's path rules, by host in the allow list's
// grammar, that holds host, its paths, and whether one does. An entry matches as
// [Match] matches it, and of several that match the most specific holds the host: its
// name itself, else the "*." entry with the longest suffix. The entry decides the
// host's paths whole; entries are never merged. Keys are unique and, as the schema has
// them, lower-case, so no two match equally. Every lookup of a host's path rules goes
// through here.
func HostPaths(paths map[string][]string, host string) (entry string, rules []string, ok bool) {
	best := -1
	for key, r := range paths {
		if _, match := Match([]string{key}, host); !match {
			continue
		}
		// A "*." entry matches by its suffix, so its length ranks it; the host's name
		// itself ranks above every one of them.
		rank := len(key)
		if !strings.HasPrefix(key, "*.") {
			rank = math.MaxInt
		}
		if rank > best {
			best, entry, rules, ok = rank, key, r, true
		}
	}
	return entry, rules, ok
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
