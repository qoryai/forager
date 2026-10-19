// Package credential holds the credentials a run uses without its session ever
// holding them, and gets them from where the machine says: a variable of Forager's
// environment, a file, or an adapter.
//
// An adapter is a program of the machine's that knows one kind of host, a source code
// host say. The gateway starts it outside the enclosure, with one argument the run's
// policy chose, and reads one JSON document from its standard output,
// contracts/forager/v1/credential.schema.json: the credential, when it expires, and how
// it is used, the hosts, the scheme and the paths, because hosts differ in all three and
// the gateway knows none of them. The gateway runs the adapter again before the
// credential expires and when a host refuses it; the answer then changes the credential
// and nothing else.
//
// A [Definition] is the machine's. A run's policy selects definitions by name and
// defines none, so whoever writes a policy chooses among the programs the machine's
// owner installed and never names one.
package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
)

// Definition is one credential as the machine defines it. Exactly one of Env, File and
// Adapter says where the token comes from. A model key has Format, Endpoint and the
// scheme in place of Hosts and Placeholders.
type Definition struct {
	Name string
	// Env is the name of a variable of Forager's own environment that holds the
	// credential.
	Env string
	// File is a path that holds the token, read again when it changes.
	File string
	// Adapter is the program and its arguments; ${argument} in an argument is replaced
	// by the run's argument.
	Adapter []string
	// Argument is a regular expression the run's argument must match whole. Empty
	// means the run passes none.
	Argument string
	// Hosts, Scheme, Username, Header and Paths say how a token from Env or File is
	// used. For an Adapter, which says that itself, Hosts and Paths are the most it may
	// claim, when they are set.
	Hosts                    []string
	Scheme, Username, Header string
	Paths                    []string
	// Placeholders are variables the enclosure gets with a value that is no credential.
	Placeholders []string
	// Format is a model key's API format, one of api-format.schema.json; empty for any
	// other credential.
	Format string
	// Endpoint is the base URL of a model key's API: the key is set on every path of its
	// host alone.
	Endpoint string
	// OAuth marks a model key set as a bearer as an OAuth token.
	OAuth bool
	// KeyPrefixes are the prefixes a model key's token must start with; nil for any
	// token.
	KeyPrefixes []string
}

// Use is one way a held token is used: what the proxy needs to know, and what the
// record lists of it.
type Use struct {
	Name string
	// Argument is the argument the run's policy passed to the credential, the same for
	// every use of one credential; empty when it passed none.
	Argument                 string
	Hosts                    []string
	Scheme, Username, Header string
	Paths                    []string
	// Stored says the credential is the server's, a run configuration's credentials
	// entry, whose value Qory Apiary sealed to the access key.
	Stored bool
	// Format, Endpoint and OAuth are a model key's, from the server or the machine;
	// empty for every other credential.
	Format, Endpoint string
	OAuth            bool
	held             *held
	index            int
}

// Stored is a credential whose value Qory Apiary stores for the run: an entry of the
// run configuration's credentials, how its value is set, and the value as it opened.
type Stored struct {
	Name                     string
	Hosts                    []string
	Scheme, Username, Header string
	// Paths are nil for every path.
	Paths        []string
	Placeholders []string
	// Format, Endpoint and OAuth are an API credential's; empty for a host credential.
	Format, Endpoint string
	OAuth            bool
	// Value returns a copy of the opened value's bytes, which the caller clears once it
	// has set them; empty once the run has ended.
	Value func() []byte
}

// Token is the token as it is now, of a credential of the machine's; empty for a
// credential from the server, whose value [Use.Value] returns.
func (u *Use) Token() string {
	if u.Stored {
		return ""
	}
	return u.held.token(u.index)
}

// Value is a copy of the opened value of a credential from the server, which the
// caller clears once it has set it; empty once the run has ended. Nil for a credential
// of the machine's.
func (u *Use) Value() []byte {
	if !u.Stored || u.held.value == nil {
		return nil
	}
	return u.held.value()
}

// Rejected tells the holder a host refused the token, which is a reason to ask the
// adapter again, not more often than every [retryWait].
func (u *Use) Rejected() { u.held.rejected() }

// Timing of an adapter.
const (
	// adapterWait is how long an adapter has to answer.
	adapterWait = time.Minute
	// renewBefore is how long before a credential expires the gateway runs the adapter
	// again.
	renewBefore = 5 * time.Minute
	// retryWait is the least time between two askings.
	retryWait = 30 * time.Second
)

// Held are a run's credentials, resolved. Start is the name of the model key the
// runtime starts with, the one model key the proxy sets; empty when the run has none.
type Held struct {
	Uses         []*Use
	Placeholders []string
	Start        string
	all          []*held
}

// Credential is one credential a run holds: its name, the hosts of its uses in their
// order, as the proxy matches them, and the variables the enclosure gets a placeholder in
// for it, each once. Of a credential from the server, Stored is true. Of a model key,
// from the server or the machine, Format, Endpoint and OAuth are set. Of both, Scheme,
// Username and Header are how its value is set.
type Credential struct {
	Name                     string
	Hosts                    []string
	Placeholders             []string
	Stored                   bool
	Scheme, Username, Header string
	Format, Endpoint         string
	OAuth                    bool
}

// Credentials are the run's credentials, one each, in the order the policy selects
// them. Hosts are taken from [Held.Uses], so they are the hosts the record's
// applied.credentials lists for the credential. Placeholders is empty, never nil, for a
// credential that sets none.
func (h *Held) Credentials() []Credential {
	out := make([]Credential, 0, len(h.all))
	for _, c := range h.all {
		cred := Credential{Name: c.def.Name, Placeholders: append([]string{}, c.placeholders...)}
		for _, u := range h.Uses {
			if u.held == c {
				cred.Hosts = append(cred.Hosts, u.Hosts...)
				if u.Stored {
					cred.Stored = true
				}
				if u.Stored || u.Format != "" {
					cred.Scheme, cred.Username, cred.Header = u.Scheme, u.Username, u.Header
					cred.Format, cred.Endpoint, cred.OAuth = u.Format, u.Endpoint, u.OAuth
				}
			}
		}
		out = append(out, cred)
	}
	return out
}

// Close stops the renewals.
func (h *Held) Close() {
	for _, c := range h.all {
		c.stop()
	}
}

// Resolve reads the credentials a policy selects, asking every adapter once, and
// refuses what cannot hold: a name the machine does not define, an argument it does not
// provide for, a host two credentials claim or the run's allow list does not cover
// under enforce, a claim above the definition's own. report hears of a renewal that
// failed.
func Resolve(ctx context.Context, defs []Definition, selected []policy.Selected, mode policy.Mode, allow []string, report func(string)) (*Held, error) {
	return ResolveWith(ctx, defs, selected, nil, "", mode, allow, report)
}

// ResolveWith is [Resolve] beside the credentials from the server, stored, which come
// after the machine's. A credential from the server replaces each credential of the
// machine's that claims a host it claims, or a host above or below one: a definition
// whose env or file use claims one is not read, and an adapter's answer that claims one
// is dropped, with no renewal; the adapter has run all the same. A credential of the
// machine's that it replaces may have its name. A credential from the server with the
// name of a credential of the machine's that stays is refused, so the record lists
// each once. The checks of Resolve then cover all of them. start is the run
// configuration's model_credential, the name of the model key the runtime starts with,
// empty when it names none ([Held.startKey]).
func ResolveWith(ctx context.Context, defs []Definition, selected []policy.Selected, stored []Stored, start string, mode policy.Mode, allow []string, report func(string)) (*Held, error) {
	out := &Held{}
	replaced := func(hosts []string) bool {
		for _, s := range stored {
			for _, theirs := range s.Hosts {
				for _, host := range hosts {
					if policy.Covers(theirs, host) || policy.Covers(host, theirs) {
						return true
					}
				}
			}
		}
		return false
	}
	for _, sel := range selected {
		i := slices.IndexFunc(defs, func(d Definition) bool { return d.Name == sel.Name })
		if i < 0 {
			return nil, fmt.Errorf("the policy selects the credential %s, which this machine does not define", accesskey.ShownName(sel.Name, true))
		}
		def := defs[i]
		if slices.ContainsFunc(out.all, func(h *held) bool { return h.def.Name == def.Name }) {
			return nil, fmt.Errorf("the policy selects the credential %s twice", accesskey.ShownName(def.Name, true))
		}
		if err := def.check(sel.Argument); err != nil {
			out.Close()
			return nil, err
		}
		if len(def.Adapter) == 0 && replaced(def.hosts()) {
			continue
		}
		h := &held{def: def, argument: sel.Argument, report: report, done: make(chan struct{})}
		answer, err := h.ask(ctx)
		if err != nil {
			out.Close()
			return nil, fmt.Errorf("credential %s: %w", accesskey.ShownName(def.Name, false), err)
		}
		var claimed []string
		for _, a := range answer.Apply {
			claimed = append(claimed, a.Hosts...)
		}
		if replaced(claimed) {
			continue
		}
		h.set(answer)
		h.shape = answer.shape()
		for i, a := range answer.Apply {
			out.Uses = append(out.Uses, &Use{Name: def.Name, Argument: sel.Argument, Hosts: a.Hosts, Scheme: a.Scheme, Username: a.Username, Header: a.Header, Paths: a.Paths,
				Format: def.Format, Endpoint: def.Endpoint, OAuth: def.OAuth, held: h, index: i})
		}
		for _, p := range slices.Concat(def.Placeholders, answer.Placeholders) {
			if !slices.Contains(h.placeholders, p) {
				h.placeholders = append(h.placeholders, p)
			}
			if !slices.Contains(out.Placeholders, p) {
				out.Placeholders = append(out.Placeholders, p)
			}
		}
		out.all = append(out.all, h)
	}
	// The name check runs against the machine's credentials that stay, so one the
	// server's replaces may have its name, such as model in both.
	for _, s := range stored {
		if slices.ContainsFunc(out.all, func(h *held) bool { return h.def.Name == s.Name }) {
			out.Close()
			return nil, fmt.Errorf("rename the run configuration's credential %s or this machine's credential of that name; the machine's is for other hosts, so it stays, and the record lists each credential once", accesskey.ShownName(s.Name, true))
		}
	}
	for _, s := range stored {
		h := &held{def: Definition{Name: s.Name}, value: s.Value, done: make(chan struct{})}
		out.Uses = append(out.Uses, &Use{Name: s.Name, Hosts: s.Hosts, Scheme: s.Scheme, Username: s.Username, Header: s.Header, Paths: s.Paths, Stored: true,
			Format: s.Format, Endpoint: s.Endpoint, OAuth: s.OAuth, held: h})
		for _, p := range s.Placeholders {
			if !slices.Contains(h.placeholders, p) {
				h.placeholders = append(h.placeholders, p)
			}
			if !slices.Contains(out.Placeholders, p) {
				out.Placeholders = append(out.Placeholders, p)
			}
		}
		out.all = append(out.all, h)
	}
	if err := out.check(mode, allow); err != nil {
		out.Close()
		return nil, err
	}
	if err := out.startKey(start); err != nil {
		out.Close()
		return nil, err
	}
	for _, h := range out.all {
		go h.renew()
	}
	return out, nil
}

// startKey sets Start: start when it names a model key of the run, or the run's one
// model key when start is empty. It refuses a start that names no model key of the
// run, and an empty one beside two or more model keys, each run_configuration_invalid.
func (h *Held) startKey(start string) error {
	var keys []string
	for _, c := range h.Credentials() {
		if c.Format != "" {
			keys = append(keys, c.Name)
		}
	}
	shown := make([]string, len(keys))
	for i, k := range keys {
		shown[i] = accesskey.ShownName(k, false)
	}
	switch {
	case start == "" && len(keys) == 0:
	case start == "" && len(keys) == 1:
		h.Start = keys[0]
	case start == "" && len(keys) > 1:
		return refusal.New(refusal.RunConfigurationInvalid, nil,
			"set model_credential to the model key the runtime starts with, or keep one model key in forager.yaml: the run has the model keys %s", strings.Join(shown, ", "))
	case slices.Contains(keys, start):
		h.Start = start
	case len(keys) == 0:
		return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(start),
			"remove model_credential from Qory Apiary's run configuration, or give the run a model key %s: the run has no model key", accesskey.ShownName(start, true))
	default:
		return refusal.New(refusal.RunConfigurationInvalid, refusal.Shown(start),
			"set model_credential in Qory Apiary's run configuration to one of the run's model keys, %s: the run has no model key %s", strings.Join(shown, ", "), accesskey.ShownName(start, true))
	}
	return nil
}

// check refuses two uses that claim a host together, unless both are model keys, which
// the proxy tells apart by their placeholders, and, under enforce, a host the run's
// allow list does not cover, a model key's host being its endpoint's: a credential for a host the run never reaches is a
// mistake to hear of before the run, not during it.
func (h *Held) check(mode policy.Mode, allow []string) error {
	for i, u := range h.Uses {
		for _, host := range u.Hosts {
			for _, other := range h.Uses[:i] {
				if u.Format != "" && other.Format != "" {
					continue
				}
				for _, theirs := range other.Hosts {
					if policy.Covers(theirs, host) || policy.Covers(host, theirs) {
						return fmt.Errorf("claim %s in only one of the credentials %s and %s; both claim it, and a host has one", accesskey.ShownValue(host, false), accesskey.ShownName(other.Name, false), accesskey.ShownName(u.Name, false))
					}
				}
			}
			if mode != policy.Enforce {
				continue
			}
			if !slices.ContainsFunc(allow, func(entry string) bool { return policy.Covers(entry, host) }) {
				name, shown := accesskey.ShownName(u.Name, false), accesskey.ShownValue(host, false)
				return fmt.Errorf("add %s to the run's egress allow list, or remove the credential %s: the credential %s is for %s, which no allow entry covers", shown, name, name, shown)
			}
		}
	}
	return nil
}

var (
	nameShape   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	headerShape = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	envShape    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// prefixShape is a key prefix's form: 1 to 32 characters of printable ASCII
	// without a space.
	prefixShape = regexp.MustCompile(`^[!-~]{1,32}$`)
)

// hosts are the hosts a token from Env or File is set on, and the most an adapter may
// claim: a model key's endpoint host, or the definition's Hosts.
func (d Definition) hosts() []string {
	if d.Format == "" {
		return d.Hosts
	}
	if host, ok := policy.EndpointHost(d.Endpoint); ok {
		return []string{host}
	}
	return nil
}

// KeyMatches reports whether a model key's value starts with one of prefixes, or
// prefixes is empty.
func KeyMatches(prefixes []string, value []byte) bool {
	return len(prefixes) == 0 || slices.ContainsFunc(prefixes, func(p string) bool { return bytes.HasPrefix(value, []byte(p)) })
}

// checkModelKey refuses a model key's definition that cannot be one: a format outside
// api-format.schema.json, an endpoint from which [policy.EndpointHost] reads no host,
// hosts, paths or placeholders beside the endpoint, a scheme the proxy does not
// implement, oauth beside another scheme than bearer, and key prefixes other than 1 to
// 4 of 1 to 32 characters of printable ASCII without a space, each once.
func (d Definition) checkModelKey() error {
	name := accesskey.ShownName(d.Name, false)
	schema, err := contracts.Compile("api-format.schema.json")
	if err != nil {
		return err
	}
	if err := schema.Validate(d.Format); err != nil {
		return fmt.Errorf("credential %s: set format to anthropic-messages, openai-responses, openai-chat or gemini: %s is no API format Forager knows", name, accesskey.ShownValue(d.Format, true))
	}
	if _, ok := policy.EndpointHost(d.Endpoint); !ok || strings.ContainsAny(d.Endpoint, "?#") {
		return fmt.Errorf("credential %s: set endpoint to an https URL with a host and no user, query or fragment: Forager reads no host from it", name)
	}
	if len(d.Hosts) > 0 || len(d.Paths) > 0 || len(d.Placeholders) > 0 {
		return fmt.Errorf("credential %s: remove hosts, paths and placeholders from the model key: its endpoint gives its host, and the session gives the runtime the key's variable", name)
	}
	if err := (apply{Scheme: d.Scheme, Username: d.Username, Header: d.Header}).check(); err != nil {
		return fmt.Errorf("credential %s: %w", name, err)
	}
	if d.OAuth && d.Scheme != "bearer" {
		return fmt.Errorf("credential %s: remove oauth, or set the scheme to bearer: oauth marks a bearer alone", name)
	}
	if d.KeyPrefixes != nil && (len(d.KeyPrefixes) < 1 || len(d.KeyPrefixes) > 4) {
		return fmt.Errorf("credential %s: list 1 to 4 key prefixes, or none: the model key lists %d", name, len(d.KeyPrefixes))
	}
	for i, p := range d.KeyPrefixes {
		switch {
		case !prefixShape.MatchString(p):
			return fmt.Errorf("credential %s: write each key prefix as 1 to 32 characters of printable ASCII without a space: %s is not", name, accesskey.ShownValue(p, true))
		case slices.Contains(d.KeyPrefixes[:i], p):
			return fmt.Errorf("credential %s: list the key prefix %s once: the model key lists it twice", name, accesskey.ShownValue(p, true))
		}
	}
	return nil
}

// Check refuses a definition that cannot be one, before any run selects it.
func (d Definition) Check() error {
	if !nameShape.MatchString(d.Name) {
		return fmt.Errorf("the credential name %s is not 1 to 64 of a-z, 0-9, underscore, dot and dash", accesskey.ShownName(d.Name, true))
	}
	sources := 0
	for _, set := range []bool{d.Env != "", d.File != "", len(d.Adapter) > 0} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		return fmt.Errorf("credential %s: exactly one of env, file and adapter says where the token comes from", accesskey.ShownName(d.Name, false))
	}
	if d.Format != "" {
		if d.Argument != "" && len(d.Adapter) == 0 {
			return fmt.Errorf("credential %s: an argument is an adapter's; env and file take none", accesskey.ShownName(d.Name, false))
		}
		if d.Argument != "" {
			if _, err := wholeMatch(d.Argument); err != nil {
				return fmt.Errorf("credential %s: argument: %w", accesskey.ShownName(d.Name, false), accesskey.ShownError(err))
			}
		}
		return d.checkModelKey()
	}
	if d.Endpoint != "" || d.OAuth || d.KeyPrefixes != nil {
		return fmt.Errorf("credential %s: add format to the credential, or remove endpoint, oauth and key_prefixes: only a model key has them", accesskey.ShownName(d.Name, false))
	}
	if d.Argument != "" {
		if _, err := wholeMatch(d.Argument); err != nil {
			return fmt.Errorf("credential %s: argument: %w", accesskey.ShownName(d.Name, false), accesskey.ShownError(err))
		}
	}
	for _, p := range d.Placeholders {
		if !envShape.MatchString(p) {
			return fmt.Errorf("credential %s: the placeholder %s is not a variable's name", accesskey.ShownName(d.Name, false), accesskey.ShownName(p, true))
		}
	}
	if len(d.Adapter) > 0 {
		if d.Scheme != "" || d.Username != "" || d.Header != "" {
			return fmt.Errorf("credential %s: an adapter says how its token is used; the scheme is not the definition's to give", accesskey.ShownName(d.Name, false))
		}
		return nil
	}
	if d.Argument != "" {
		return fmt.Errorf("credential %s: an argument is an adapter's; env and file take none", accesskey.ShownName(d.Name, false))
	}
	if len(d.Hosts) == 0 {
		return fmt.Errorf("credential %s: a token from env or file needs the hosts it is for", accesskey.ShownName(d.Name, false))
	}
	return apply{Hosts: d.Hosts, Scheme: d.Scheme, Username: d.Username, Header: d.Header}.check()
}

// check refuses a run's argument the definition does not provide for.
func (d Definition) check(argument string) error {
	if err := d.Check(); err != nil {
		return err
	}
	switch {
	case d.Argument == "" && argument != "":
		return fmt.Errorf("credential %s takes no argument and the policy gives %s", accesskey.ShownName(d.Name, false), accesskey.ShownName(argument, true))
	case d.Argument != "":
		re, err := wholeMatch(d.Argument)
		if err != nil {
			return fmt.Errorf("credential %s: argument: %w", accesskey.ShownName(d.Name, false), accesskey.ShownError(err))
		}
		if !re.MatchString(argument) {
			return fmt.Errorf("credential %s: the argument %s is not one the machine provides for", accesskey.ShownName(d.Name, false), accesskey.ShownName(argument, true))
		}
	}
	return nil
}

// wholeMatch compiles pattern as a run's argument is matched: anchored, so an argument
// matches only when the pattern matches all of it. The error of a pattern that does not
// compile alone is that one's; one that compiles alone and not anchored, such as a\Q,
// whose quote takes the anchor's closing in, has the anchored form's.
func wholeMatch(pattern string) (*regexp.Regexp, error) {
	if _, err := regexp.Compile(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile(`^(?:` + pattern + `)$`)
}

// answer is an adapter's answer, or what Env and File amount to.
type answer struct {
	Version      int       `json:"version"`
	Token        string    `json:"token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Apply        []apply   `json:"apply"`
	Placeholders []string  `json:"placeholders"`
}

type apply struct {
	Hosts    []string `json:"hosts"`
	Scheme   string   `json:"scheme"`
	Username string   `json:"username"`
	Header   string   `json:"header"`
	Token    string   `json:"token"`
	Paths    []string `json:"paths"`
}

func (a apply) check() error {
	switch a.Scheme {
	case "bearer":
	case "basic":
		if a.Username == "" || strings.ContainsAny(a.Username, ": \t\r\n") {
			return errors.New("the scheme basic needs a username without a colon or a space")
		}
	case "header":
		if !headerShape.MatchString(a.Header) {
			return errors.New("the scheme header needs a header's name")
		}
	default:
		return fmt.Errorf("the scheme %s is not bearer, basic or header", accesskey.ShownValue(a.Scheme, true))
	}
	return nil
}

// shape is everything of an answer but its tokens, which is what a renewal must leave
// as it was.
func (a *answer) shape() string {
	var b strings.Builder
	for _, u := range a.Apply {
		fmt.Fprintf(&b, "%q %s %s %s %q\n", u.Hosts, u.Scheme, u.Username, u.Header, u.Paths)
	}
	return b.String()
}

// held is one credential, held for a run.
type held struct {
	def      Definition
	argument string
	report   func(string)
	shape    string
	// placeholders are the definition's placeholders and then the adapter's, each once.
	placeholders []string
	// value, for a credential from the server, returns its opened value; nil for the
	// machine's.
	value func() []byte

	mu      sync.Mutex
	tokens  []string
	expires time.Time
	asked   time.Time
	stale   bool
	wake    chan struct{}
	done    chan struct{}
	once    sync.Once
}

func (h *held) token(i int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.def.File != "" {
		// A file is read when it is used: whatever rotates it needs to tell no one.
		// A model key's token that starts with none of its prefixes is not taken: the
		// token read before stays.
		if b, err := os.ReadFile(h.def.File); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" && KeyMatches(h.def.KeyPrefixes, []byte(t)) {
				return t
			}
		}
	}
	return h.tokens[i]
}

func (h *held) set(a *answer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokens = h.tokens[:0]
	for _, u := range a.Apply {
		t := u.Token
		if t == "" {
			t = a.Token
		}
		h.tokens = append(h.tokens, t)
	}
	h.expires, h.asked, h.stale = a.ExpiresAt, time.Now(), false
}

func (h *held) rejected() {
	h.mu.Lock()
	h.stale = true
	wake := h.wake
	h.mu.Unlock()
	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (h *held) stop() { h.once.Do(func() { close(h.done) }) }

// renew asks an adapter again before its token expires and after a host refused it. A
// renewal that fails, or that answers with other hosts, schemes or paths, leaves the
// token as it was and is reported: what a run reaches is fixed when it starts.
func (h *held) renew() {
	if len(h.def.Adapter) == 0 {
		return
	}
	h.mu.Lock()
	h.wake = make(chan struct{}, 1)
	h.mu.Unlock()
	for {
		h.mu.Lock()
		wait := time.Until(h.expires.Add(-renewBefore))
		if h.expires.IsZero() {
			wait = 24 * time.Hour
		}
		if least := time.Until(h.asked.Add(retryWait)); h.stale || wait < least {
			wait = max(least, 0)
		}
		h.mu.Unlock()
		select {
		case <-h.done:
			return
		case <-h.wake:
			continue
		case <-time.After(wait):
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-h.done:
				cancel()
			case <-ctx.Done():
			}
		}()
		a, err := h.ask(ctx)
		cancel()
		switch {
		case err != nil:
			h.report(fmt.Sprintf("credential %s was not renewed: %v", accesskey.ShownName(h.def.Name, false), err))
		case a.shape() != h.shape:
			h.report(fmt.Sprintf("credential %s was not renewed: the adapter answered with other hosts, schemes or paths than when the run started", accesskey.ShownName(h.def.Name, false)))
		default:
			h.set(a)
			continue
		}
		h.mu.Lock()
		h.asked, h.stale = time.Now(), false
		h.mu.Unlock()
	}
}

// prefixError is the error of a model key's token that starts with none of its
// prefixes. It never contains the token.
func (d Definition) prefixError() error {
	shown := make([]string, len(d.KeyPrefixes))
	for i, p := range d.KeyPrefixes {
		shown[i] = accesskey.ShownValue(p, true)
	}
	return fmt.Errorf("give the model key %s a token that starts with %s, its key_prefixes: the token starts with none of them", accesskey.ShownName(d.Name, false), strings.Join(shown, " or "))
}

// ask gets the token from where the definition says.
func (h *held) ask(ctx context.Context) (*answer, error) {
	d := h.def
	static := func(token string) (*answer, error) {
		if token == "" {
			return nil, errors.New("the token is empty")
		}
		if !KeyMatches(d.KeyPrefixes, []byte(token)) {
			return nil, d.prefixError()
		}
		return &answer{Version: 1, Token: token, Apply: []apply{{Hosts: d.hosts(), Scheme: d.Scheme, Username: d.Username, Header: d.Header, Paths: d.Paths}}}, nil
	}
	switch {
	case d.Env != "":
		return static(os.Getenv(d.Env))
	case d.File != "":
		b, err := os.ReadFile(d.File)
		if err != nil {
			return nil, accesskey.ShownError(err)
		}
		return static(strings.TrimSpace(string(b)))
	}
	ctx, cancel := context.WithTimeout(ctx, adapterWait)
	defer cancel()
	args := make([]string, len(d.Adapter)-1)
	for i, a := range d.Adapter[1:] {
		args[i] = strings.ReplaceAll(a, "${argument}", h.argument)
	}
	// The adapter's path as a message prints it.
	path := accesskey.ShownValue(d.Adapter[0], false)
	cmd := exec.CommandContext(ctx, d.Adapter[0], args...)
	// The access key's variables are Forager's, and no credential program's.
	cmd.Env = accesskey.WithoutVariables(os.Environ())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		// What an adapter prints is its own to word, and a line of it is worth the
		// reader's time; its output is never the token, which goes to stdout.
		line, _, _ := strings.Cut(strings.TrimSpace(stderr.String()), "\n")
		return nil, fmt.Errorf("the adapter %s: %w: %s", path, accesskey.ShownError(err), accesskey.ShownValue(line, false))
	}
	doc, err := contracts.Decode("answer.json", stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("the adapter %s did not print a JSON document: %w", path, accesskey.ShownError(err))
	}
	schema, err := contracts.Compile("credential.schema.json")
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(doc); err != nil {
		return nil, fmt.Errorf("the adapter %s: %w", path, accesskey.ShownError(err))
	}
	var a answer
	if err := json.Unmarshal(stdout.Bytes(), &a); err != nil {
		return nil, accesskey.ShownError(err)
	}
	if d.Format != "" && len(a.Placeholders) > 0 {
		return nil, fmt.Errorf("the adapter %s gives the model key %s placeholders: the session gives the runtime the key's variable", path, accesskey.ShownName(d.Name, false))
	}
	for _, u := range a.Apply {
		if err := u.check(); err != nil {
			return nil, fmt.Errorf("the adapter %s: %w", path, err)
		}
		if u.Token == "" && a.Token == "" {
			return nil, fmt.Errorf("the adapter %s gave no token for %v", path, u.Hosts)
		}
		if d.Format != "" {
			// A model key is set as its definition says, which the session chooses the
			// runtime's variable by.
			if u.Scheme != d.Scheme || u.Username != d.Username || !strings.EqualFold(u.Header, d.Header) {
				return nil, fmt.Errorf("the adapter %s sets the model key %s with another scheme than the definition's", path, accesskey.ShownName(d.Name, false))
			}
			token := u.Token
			if token == "" {
				token = a.Token
			}
			if !KeyMatches(d.KeyPrefixes, []byte(token)) {
				return nil, d.prefixError()
			}
		}
		// What the machine's definition says is the most an adapter may claim.
		for _, host := range u.Hosts {
			if hosts := d.hosts(); len(hosts) > 0 && !slices.ContainsFunc(hosts, func(entry string) bool { return policy.Covers(entry, host) }) {
				return nil, fmt.Errorf("the adapter %s claims %s, above the hosts the machine gives it", path, host)
			}
		}
		if len(d.Paths) > 0 {
			if u.Paths == nil {
				return nil, fmt.Errorf("the adapter %s claims every path of %v, above the paths the machine gives it", path, u.Hosts)
			}
			for _, p := range u.Paths {
				if !slices.ContainsFunc(d.Paths, func(entry string) bool { return policy.CoversPath(entry, p) }) {
					return nil, fmt.Errorf("the adapter %s claims the path %s, above the paths the machine gives it", path, accesskey.ShownValue(p, false))
				}
			}
		}
	}
	return &a, nil
}
