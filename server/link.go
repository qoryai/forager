package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
)

// LocalOrigin is the origin of every URL of the local link: the session sends every
// request over the link's socket, and the host names nothing else.
const LocalOrigin = "http://localhost"

// LinkContentType is the content type of a run request on the link.
const LinkContentType = "application/json"

// EndCodes are the codes of a 410 on the link, the end of a run at the gateway, which
// the session records as the reason of its dev.qory.run.exited: the gateway closed
// the run, the run credential expired with no fresh one, its issuer
// reports it no longer active or ended another run of its run key, the gateway heard
// nothing from the session for too long, or it refused a batch of the session's. A 410
// with another code, or none, is run_closed.
var EndCodes = []string{event.ReasonRunClosed, event.ReasonCredentialExpired, event.ReasonRunEndedAtIssuer, event.ReasonSessionLost, event.ReasonBatchRefused}

// CodeInvalidRequest is the gateway's 400 to a request of the link its rules refuse; to
// a batch it ends the run.
const CodeInvalidRequest = "invalid_request"

// ErrLinkPeer is the error of a local link whose socket's peer is another user than
// this process's: the link secret is not written.
var ErrLinkPeer = errors.New("the socket's peer is another user; the link secret is not sent")

// LinkDiscovery is what the gateway answers discovery with on its link,
// contracts/forager/v1/link-discovery.schema.json: where the session posts its events,
// which, and every how many seconds it sends a heartbeat; where it opens a run; and
// the gateway's proxy address. A member Forager does not know is ignored.
type LinkDiscovery struct {
	Version int        `json:"version"`
	Events  LinkEvents `json:"events"`
	Run     Endpoint   `json:"run"`
	// Proxy is the gateway's proxy address, which the schema requires: a discovery
	// without it is refused.
	Proxy *LinkProxy `json:"proxy,omitempty"`
}

// LinkEvents is the events section of the link's discovery.
type LinkEvents struct {
	URL string `json:"url"`
	// Types are full type names, or "*" for every type.
	Types []string `json:"types"`
	// IntervalSeconds is the gateway's heartbeat interval: the session sends its
	// heartbeats this often, and the gateway ends a run whose session sends nothing for
	// three intervals.
	IntervalSeconds int `json:"interval_seconds"`
}

// LinkProxy is the gateway's proxy: its one address, host:port, which every
// connection opens with the relay's preamble and the run's proxy secret.
type LinkProxy struct {
	Address string `json:"address"`
}

// LinkRunRequest is the body of the session's POST to the run URL of the link,
// contracts/forager/v1/link-run-request.schema.json, which opens a run.
type LinkRunRequest struct {
	Version int `json:"version"`
	// RunID is the run's id, which the session chooses: a UUID in the canonical
	// lower-case form.
	RunID string `json:"run_id"`
	// Wall says whether the session runs the agent behind a wall.
	Wall bool `json:"wall"`
	// Labels are the run's labels, as run.started reports them.
	Labels map[string]string `json:"labels,omitempty"`
	// About is what the run is about, as run.started reports it, [ReportedAbout].
	About *About `json:"about,omitempty"`
	// Narrowing is the session's narrowing of the policy, behind a separate gateway
	// alone: the local link refuses one, and [Link.OpenRun] sends none on it.
	Narrowing *LinkNarrowing `json:"narrowing,omitempty"`
	// Passes are the names of the variables the run passes a value for, in what it
	// inherits, what the harness sets and its variables: names alone, never a value.
	// The gateway refuses a credential's or a tool's placeholder the run passes, as the
	// session does.
	Passes []string `json:"passes,omitempty"`
	// Images are the images the session resolves a policy's selection against, so the
	// gateway decides the run's image as the session does.
	Images *LinkImages `json:"images,omitempty"`
}

// LinkNarrowing is a session's narrowing of the policy the gateway holds for its run.
type LinkNarrowing struct {
	Egress LinkNarrowingEgress `json:"egress"`
}

// LinkNarrowingEgress is a narrowing's egress: hosts it allows, and hosts it denies,
// each in the grammar of the policy's egress.allow.
type LinkNarrowingEgress struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// LinkImages are the session's images: its default, the name of one of Definitions or
// a reference, and the images the machine defines, which a policy selects by name.
// A reference may carry a registry's credentials in its user information: neither the
// session's client nor the gateway logs or reports one.
type LinkImages struct {
	Default     string      `json:"default,omitempty"`
	Definitions []LinkImage `json:"definitions,omitempty"`
}

// LinkImage is one image: its name, empty for the default given as a reference, its
// reference, the container runtime the wall starts it under, empty for the engine's
// default, and whether it gives the agent a Docker daemon of its own.
type LinkImage struct {
	Name    string `json:"name,omitempty"`
	Ref     string `json:"ref"`
	Runtime string `json:"runtime,omitempty"`
	Docker  bool   `json:"docker,omitempty"`
}

// LinkRunAnswer is what the gateway answers a run request it accepts,
// contracts/forager/v1/link-run-answer.schema.json. A member Forager does not know is
// ignored. Its ProxySecret is never printed: fmt and log/slog show it as [redacted].
type LinkRunAnswer struct {
	Version int    `json:"version"`
	RunID   string `json:"run_id"`
	// Credential is where the run's credential came from, which run.started reports:
	// issuer, an issuer gave the run its run credential; none, on the local link.
	Credential string `json:"credential"`
	// Policy is the policy in force for the run, as policy.schema.json defines it, and
	// Digest the hex SHA-256 of its canonical JSON; each is present with the other, and
	// with neither the gateway observes everything.
	Policy json.RawMessage `json:"policy,omitzero"`
	Digest string          `json:"digest,omitempty"`
	// Variables are the run's variables by name; nil when the answer has none.
	Variables map[string]Variable `json:"variables,omitzero"`
	// ProxySecret is the run's proxy secret, which opens every connection to the
	// gateway's proxy after the relay's preamble.
	ProxySecret string `json:"proxy_secret"`
	// CertificateAuthority is the run's certificate authority, PEM, when the run has a
	// wall and the gateway reads inside HTTPS for it.
	CertificateAuthority string `json:"certificate_authority,omitempty"`
	// Placeholders are the variables the agent sees in place of a credential or a
	// tool's secret.
	Placeholders []string `json:"placeholders,omitempty"`
	// Reserved are the names of the variables the machine's credentials are read from:
	// a walled run that passes one is refused with variable_reserved, and an unwalled
	// run has its value left out.
	Reserved []string `json:"reserved,omitempty"`
	// Image is the image the run gets, when it has a wall.
	Image *LinkImage `json:"image,omitempty"`
	// Labels are the run's labels as the gateway holds them, which run.started reports.
	Labels map[string]string `json:"labels,omitempty"`
	// Details are the keys of about.details the run credential decides, a JSON object,
	// which run.started reports; nil when the answer has none.
	Details json.RawMessage `json:"details,omitzero"`
	// Applied are the members of dev.qory.run.policy_applied the gateway decides for
	// the policy in force, a JSON object: every member but harness_hosts and variables,
	// which the session adds. The gateway refuses a policy_applied whose other members
	// are not these. Nil when the answer has none.
	Applied json.RawMessage `json:"applied,omitzero"`
}

// Values are the answer's variables as values by name; nil when it has none.
func (a *LinkRunAnswer) Values() map[string]string { return values(a.Variables) }

// redactedSecret is what a secret is printed as.
const redactedSecret = "[redacted]"

// shownRunAnswer is a LinkRunAnswer without its methods, which fmt prints the way it
// prints any struct.
type shownRunAnswer LinkRunAnswer

func (a LinkRunAnswer) shown() shownRunAnswer {
	s := shownRunAnswer(a)
	if s.ProxySecret != "" {
		s.ProxySecret = redactedSecret
	}
	return s
}

// Format prints a as fmt prints a struct, under every verb and flag, with its
// ProxySecret redacted.
func (a LinkRunAnswer) Format(f fmt.State, verb rune) {
	out := fmt.Sprintf(fmt.FormatString(f, verb), a.shown())
	if verb == 'v' && f.Flag('#') {
		out = strings.Replace(out, "server.shownRunAnswer", "server.LinkRunAnswer", 1)
	}
	io.WriteString(f, out)
}

// String is a as %v prints it, its ProxySecret redacted.
func (a LinkRunAnswer) String() string { return fmt.Sprintf("%v", a) }

// GoString is a as %#v prints it, its ProxySecret redacted.
func (a LinkRunAnswer) GoString() string { return fmt.Sprintf("%#v", a) }

// LogValue is a as log/slog logs it: its run id, digest and the names it carries,
// never a variable's value, the proxy secret or the certificate.
func (a LinkRunAnswer) LogValue() slog.Value {
	names := slices.Sorted(maps.Keys(a.Variables))
	return slog.GroupValue(
		slog.String("run_id", a.RunID),
		slog.String("digest", a.Digest),
		slog.Any("variables", names),
		slog.String("proxy_secret", a.shown().ProxySecret),
		slog.Any("placeholders", a.Placeholders),
		slog.Any("reserved", a.Reserved),
	)
}

// LinkReloadAnswer is what the gateway answers a reload with,
// contracts/forager/v1/link-reload-answer.schema.json: the policy in force for the run
// now, its digest and the run's variables, placeholders, reserved names, image and the
// members of policy_applied the gateway decides. It never holds the proxy secret or the
// certificate authority.
type LinkReloadAnswer struct {
	Version      int                 `json:"version"`
	Policy       json.RawMessage     `json:"policy,omitzero"`
	Digest       string              `json:"digest,omitempty"`
	Variables    map[string]Variable `json:"variables,omitzero"`
	Placeholders []string            `json:"placeholders,omitempty"`
	Reserved     []string            `json:"reserved,omitempty"`
	Image        *LinkImage          `json:"image,omitempty"`
	// Applied are the members of dev.qory.run.policy_applied the gateway decides, as
	// [LinkRunAnswer.Applied].
	Applied json.RawMessage `json:"applied,omitzero"`
}

// Values are the answer's variables as values by name; nil when it has none.
func (a *LinkReloadAnswer) Values() map[string]string { return values(a.Variables) }

// LinkRefusal is the body of a coded refusal on the link,
// contracts/forager/v1/link-refusal.schema.json: the code, the names it concerns, and
// who refused, "gateway" or "apiary", the server's refusal passed on with its code and
// status. A refusal without From is malformed; the client reads it as the gateway's.
type LinkRefusal struct {
	Error string   `json:"error"`
	Names []string `json:"names,omitempty"`
	From  string   `json:"from,omitempty"`
	// Message is the refusal's text as its user is told it: on a run request the
	// gateway did not open, the error the run would have returned had the session
	// opened it itself.
	Message string `json:"message,omitempty"`
}

// values are variables as values by name; nil for none.
func values(vars map[string]Variable) map[string]string {
	if vars == nil {
		return nil
	}
	out := make(map[string]string, len(vars))
	for name, v := range vars {
		out[name] = v.Value
	}
	return out
}

// Link is the session's client of its gateway's link: discovery, the run request, the
// reload and the delivery of the session's batches, the protocol Forager speaks toward
// the server on the same paths, unsigned. Its transport authenticates both ends: on the
// local link, [NewLocalLink], the socket's peer is this process's user, checked before
// the link secret is written on each connection, and the secret opens every
// connection; behind a separate gateway, [NewRemoteLink], TLS 1.3 verifies the
// gateway, and the run credential on every request the session. Every URL it requests
// must have its origin, so nothing it sends leaves the link, and it follows no
// redirect.
//
// A Link never prints the link secret or the run credential: fmt and log/slog show it
// by its socket or its URL, and no error it returns contains either.
type Link struct {
	// userAgent is sent as User-Agent.
	userAgent string
	// origin is the scheme and host every URL of the link has.
	origin string
	// name is how errors name the link.
	name string
	// digests gets the digests of every answer of Discover, OpenRun and Reload other
	// than a 410; nil means nobody.
	digests func(Digests)
	// uid is the user the local link's socket's peer must be.
	uid  int
	http *http.Client
	// credential, address and tls are a separate gateway's, [NewRemoteLink]: the run
	// credential, asked for before each request; the one address, host:port; and the
	// TLS every connection to it is made with. All are empty on the local link.
	credential func(context.Context) (string, error)
	address    string
	tls        *tls.Config
}

// NewLocalLink returns the client of a gateway's local link. Each connection is the
// Local's [link.Local.DialContext]: to a gateway in this process in memory, never by the
// socket's path; else to the Unix socket at l.Socket, whose peer must be this process's
// user. Only then it writes the link's preamble with l.Secret, before HTTP/1.1, the same
// bytes either way. userAgent is sent as User-Agent, [accesskey.UserAgent]; digests,
// when not nil, gets the digests of every answer of Discover, OpenRun and Reload other
// than a 410, synchronously before the call returns, and Deliver's are in the
// [Delivery] it returns. A Local with neither a way in memory nor a socket, or whose
// secret no preamble carries, is refused; nothing is dialled.
func NewLocalLink(l link.Local, userAgent string, digests func(Digests)) (*Link, error) {
	if l.Socket == "" && !l.IsInMemory() {
		return nil, errors.New("the gateway's local link has no socket")
	}
	name := "the gateway's local link " + l.Socket
	if l.IsInMemory() {
		name = "the gateway's local link in this process"
	}
	if err := link.WriteLinkPreamble(io.Discard, l.Secret); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	k := &Link{userAgent: userAgent, origin: LocalOrigin, name: name, digests: digests, uid: os.Getuid()}
	k.http = &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return k.dialLocal(ctx, l)
			},
			DisableCompression: true,
			MaxIdleConns:       4,
			IdleConnTimeout:    90 * time.Second,
		},
		// A 3xx is a status like any other: nothing the session sends leaves the link.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return k, nil
}

// dialLocal opens one connection of the local link: in memory to a gateway in this
// process, else to the socket, whose peer's uid it checks; then it writes the preamble
// with the secret, in one write, within the context's deadline.
func (k *Link) dialLocal(ctx context.Context, l link.Local) (net.Conn, error) {
	secret := l.Secret
	c, err := l.DialContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", k.name, err)
	}
	if !l.IsInMemory() {
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			return nil, fmt.Errorf("%s: not a Unix socket", k.name)
		}
		uid, err := peerUID(uc)
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("%s: the socket's peer: %w", k.name, err)
		}
		if uid != k.uid {
			c.Close()
			return nil, fmt.Errorf("%s: the peer is uid %d, this process is uid %d: %w", k.name, uid, k.uid, ErrLinkPeer)
		}
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(link.PreambleWait)
	}
	c.SetWriteDeadline(deadline)
	if err := link.WriteLinkPreamble(c, secret); err != nil {
		c.Close()
		return nil, fmt.Errorf("%s: the preamble: %w", k.name, err)
	}
	c.SetWriteDeadline(time.Time{})
	return c, nil
}

// Format prints k by the link it speaks to, under every verb: never its secret.
func (k *Link) Format(f fmt.State, _ rune) { io.WriteString(f, k.String()) }

// String names the link, never its secret.
func (k *Link) String() string {
	if k == nil {
		return "server.Link(nil)"
	}
	return "server.Link{" + k.name + "}"
}

// GoString is k as %#v prints it, never its secret.
func (k *Link) GoString() string { return k.String() }

// LogValue is k as log/slog logs it: the link it speaks to, never its secret.
func (k *Link) LogValue() slog.Value { return slog.StringValue(k.String()) }

// Close closes the link's idle connections.
func (k *Link) Close() { k.http.CloseIdleConnections() }

// onLink refuses a URL that is not the link's origin and a path: on the local link,
// http://localhost and a path, with no port, user information, query or fragment. The
// error names what the URL is, never the URL, which could carry user information.
func (k *Link) onLink(what, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Scheme+"://"+u.Host != k.origin ||
		!strings.HasPrefix(u.Path, "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%s is not a path on the gateway's link, which every URL of the link is", what)
	}
	return nil
}

// linkAnswer is what the gateway answered one request on the link.
type linkAnswer struct {
	status  int
	body    []byte
	digests Digests
}

// send sends one request on the link and reads its answer, at most max bytes of body:
// a longer one is read as no body. The request carries User-Agent and the contract
// revision, and set's headers; no access key, instance, timestamp or signature. An
// error is a transport failure: no answer.
func (k *Link) send(ctx context.Context, method, u string, body []byte, max int, set func(http.Header)) (*linkAnswer, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if set != nil {
		set(req.Header)
	}
	if err := k.authorize(ctx, req.Header); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", k.userAgent)
	req.Header.Set(HeaderContractVersion, strconv.Itoa(Revision))
	resp, err := k.http.Do(req)
	if err != nil {
		// The transport's error names the request by its URL, which on the local link is
		// no place a user knows: the error alone, the caller names the request.
		var ue *url.Error
		if errors.As(err, &ue) {
			return nil, ue.Err
		}
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		b = nil
	}
	one := func(name string) string {
		if v := resp.Header.Values(name); len(v) == 1 {
			return v[0]
		}
		return ""
	}
	return &linkAnswer{status: resp.StatusCode, body: b, digests: Digests{Configuration: one(HeaderConfiguration), RunConfiguration: one(HeaderRunConfiguration)}}, nil
}

// end is the end of the run a 410's body says, one of [EndCodes], else run_closed.
func (a *linkAnswer) end() string {
	if r := accesskey.ReadRefusal(a.status, a.body); r != nil && slices.Contains(EndCodes, r.Code) {
		return r.Code
	}
	return accesskey.CodeRunClosed
}

// from is who refused, by the body's from: apiary when it says so, else the gateway.
func (a *linkAnswer) from() string {
	var doc struct {
		From string `json:"from"`
	}
	if jsonv2.Unmarshal(a.body, &doc) == nil && doc.From == accesskey.FromApiary {
		return accesskey.FromApiary
	}
	return accesskey.FromGateway
}

// refusal is the error of an answer that is not the one wanted: a 410 is the end of
// the run, its code one of [EndCodes]; a coded body is its code with its names and who
// refused; anything else names its status.
//
// A refusal's message, the text its user is told, is its Text, so its Error says it
// word for word. A 5xx whose code is internal, or that has none, is a failure without
// a code: a StatusError with the message.
func (a *linkAnswer) refusal(what string) error {
	var doc LinkRefusal
	jsonv2.Unmarshal(a.body, &doc)
	doc.Message = cleanMessage(doc.Message)
	if a.status == http.StatusGone {
		return &accesskey.Refusal{Code: a.end(), Status: a.status, Detail: what, From: a.from(), Text: doc.Message}
	}
	if a.status >= http.StatusInternalServerError && (doc.Error == "" || doc.Error == CodeInternal) {
		return &StatusError{What: what, Status: a.status, Message: doc.Message}
	}
	if r := accesskey.ReadRefusal(a.status, a.body); r != nil {
		r.Detail, r.From, r.Text = what, a.from(), doc.Message
		return r
	}
	return &StatusError{What: what, Status: a.status, Message: doc.Message}
}

// MaxMessage is the most characters of a refusal's message the client keeps.
const MaxMessage = 8192

// cleanMessage is a refusal's message as the client hands it on: every control
// character, C0, DEL and C1, but a tab and a newline, a space, and at most
// [MaxMessage] characters, so a message prints as the line its user is told and
// nothing more.
func cleanMessage(text string) string {
	out := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' && r != '\n' {
			return ' '
		}
		return r
	}, text))
	if len(out) > MaxMessage {
		out = out[:MaxMessage]
	}
	return string(out)
}

// CodeInternal is the code of a gateway's 500 to a run it could not open for a reason
// without a code of its own.
const CodeInternal = "internal"

// StatusError is an answer of the link with neither the one wanted nor a code: a
// gateway's 5xx, say, to a run it could not open, whose body may carry the error's text
// as its user is told it, Message.
type StatusError struct {
	// What is the request, and Status the answer's.
	What   string
	Status int
	// Message is the text of the failure the answer's body carries, empty for none.
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s: status %d", e.What, e.Status) }

// Ended reports the end of the run an error of the link carries: the code of a 410,
// one of [EndCodes], which the session records as the reason of its
// dev.qory.run.exited.
func Ended(err error) (string, bool) {
	var r *accesskey.Refusal
	if errors.As(err, &r) && r.Status == http.StatusGone {
		return r.Code, true
	}
	return "", false
}

// hand gives the answer's digests to the caller, unless it is a 410: a run that ended
// has nothing to reload.
func (k *Link) hand(a *linkAnswer) {
	if k.digests != nil && a.status != http.StatusGone {
		k.digests(a.digests)
	}
}

// fetch makes one request of a document on the link, which must answer 200; it
// validates the body against the schema and decodes it into out.
func (k *Link) fetch(ctx context.Context, what, method, u string, body []byte, set func(http.Header), schemaName string, out any) error {
	a, err := k.send(ctx, method, u, body, MaxDocument, set)
	if err != nil {
		return fmt.Errorf("%s %s: %w", what, k.at(u), err)
	}
	k.hand(a)
	if a.status != http.StatusOK {
		return a.refusal(what + " " + k.at(u))
	}
	if err := readLinkDocument(schemaName, a.body, out); err != nil {
		return &DocumentError{what, k.at(u), err}
	}
	return nil
}

// at is where a request of the link goes, as a user is told it: on the local link "at
// the gateway", never its URL, which names no place the user knows; else the URL.
func (k *Link) at(u string) string {
	if k.origin == LocalOrigin {
		return "at the gateway"
	}
	return u
}

// variableName is a name placeholders and reserved list.
var variableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// readLinkDocument reads a document of the link: through encoding/json/v2 first, which
// refuses a member name that appears twice and invalid UTF-8, then against the schema,
// then against the rules the schema does not state. Its errors say where in the
// document and which rule, never a value: an answer holds the run's proxy secret and
// variables.
func readLinkDocument(schemaName string, body []byte, out any) error {
	var v any
	if err := jsonv2.Unmarshal(body, &v); err != nil {
		var syn *jsontext.SyntacticError
		if errors.As(err, &syn) && syn.JSONPointer != "" {
			return fmt.Errorf("it is not one JSON value in UTF-8 with each member name once, at %s", syn.JSONPointer)
		}
		return errors.New("it is not one JSON value in UTF-8 with each member name once")
	}
	doc, err := contracts.Decode("link.json", body)
	if err != nil {
		return errors.New("it is not JSON")
	}
	schema, err := contracts.Compile(schemaName)
	if err != nil {
		return err
	}
	if err := schema.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if !errors.As(err, &ve) {
			return fmt.Errorf("%s refuses it", schemaName)
		}
		return fmt.Errorf("%s refuses %s", schemaName, strings.Join(leaves(ve), ", "))
	}
	if err := jsonv2.Unmarshal(body, out); err != nil {
		return fmt.Errorf("it does not decode as %s defines it and the link's members", schemaName)
	}
	return nil
}

// checkRunMembers refuses what the schemas do not hold: a variable's value over
// [MaxVariableValue] bytes, a placeholder or reserved name that is no variable's, and
// an image without a reference.
func checkRunMembers(vars map[string]Variable, placeholders, reserved []string, image *LinkImage) error {
	for name, v := range vars {
		if len(v.Value) > MaxVariableValue {
			return fmt.Errorf("the variable %s holds more than %d bytes", name, MaxVariableValue)
		}
	}
	for i, name := range placeholders {
		if !variableName.MatchString(name) {
			return fmt.Errorf("/placeholders/%d is no variable's name", i)
		}
	}
	for i, name := range reserved {
		if !variableName.MatchString(name) {
			return fmt.Errorf("/reserved/%d is no variable's name", i)
		}
	}
	if image != nil && image.Ref == "" {
		return errors.New("/image has no reference")
	}
	return nil
}

// Discover fetches the link's discovery from its well-known path. It refuses a
// discovery whose events or run URL is not on the link, http://localhost and a path on
// the local link and the gateway's origin and a path behind a separate gateway, and a
// proxy address that is not host:port, or, behind a separate gateway, not its one
// address.
func (k *Link) Discover(ctx context.Context) (*LinkDiscovery, error) {
	u := k.origin + WellKnown
	var d LinkDiscovery
	if err := k.fetch(ctx, "the link's discovery", http.MethodGet, u, nil, nil, "link-discovery.schema.json", &d); err != nil {
		return nil, err
	}
	if err := k.onLink("events.url", d.Events.URL); err != nil {
		return nil, &DocumentError{"the link's discovery", k.at(u), err}
	}
	if err := k.onLink("run.url", d.Run.URL); err != nil {
		return nil, &DocumentError{"the link's discovery", k.at(u), err}
	}
	if d.Proxy != nil {
		if _, port, err := net.SplitHostPort(d.Proxy.Address); err != nil || port == "" {
			return nil, &DocumentError{"the link's discovery", k.at(u), errors.New("proxy.address is not host:port")}
		}
		if err := k.oneAddress(d.Proxy.Address); err != nil {
			return nil, &DocumentError{"the link's discovery", k.at(u), err}
		}
	}
	return &d, nil
}

// runIDShape is a run id's form on the link: a UUID in the canonical lower-case form.
var runIDShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// OpenRun posts the run request to runURL, the discovery's run.url, and returns the
// run answer: a 200 the schema accepts, whose run_id is the request's. A 410 is the end
// of the run, [Ended]; a coded refusal is an [*accesskey.Refusal] with its status and
// who refused, From.
func (k *Link) OpenRun(ctx context.Context, runURL string, req LinkRunRequest) (*LinkRunAnswer, error) {
	if err := k.onLink("the run URL", runURL); err != nil {
		return nil, fmt.Errorf("%s: %w", k.name, err)
	}
	if !runIDShape.MatchString(req.RunID) {
		return nil, fmt.Errorf("the run request: the run id is not a UUID in the canonical lower-case form")
	}
	if req.Narrowing != nil && k.origin == LocalOrigin {
		return nil, errors.New("the run request: the local link takes no narrowing")
	}
	if req.Version == 0 {
		req.Version = 1
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("the run request: %w", err)
	}
	var a LinkRunAnswer
	if err := k.fetch(ctx, "the run request", http.MethodPost, runURL, body, func(h http.Header) { h.Set("Content-Type", LinkContentType) }, "link-run-answer.schema.json", &a); err != nil {
		return nil, err
	}
	if a.RunID != req.RunID {
		return nil, &DocumentError{"the run answer", k.at(runURL), errors.New("its run_id is not the request's")}
	}
	if err := checkRunMembers(a.Variables, a.Placeholders, a.Reserved, a.Image); err != nil {
		return nil, &DocumentError{"the run answer", k.at(runURL), err}
	}
	if err := CheckLabels(a.Labels); err != nil {
		return nil, &DocumentError{"the run answer", k.at(runURL), fmt.Errorf("/labels: %w", err)}
	}
	if a.Details != nil {
		if why := checkDetails(a.Details); why != "" {
			return nil, &DocumentError{"the run answer", k.at(runURL), errors.New("/details " + why)}
		}
	}
	return &a, nil
}

// Reload fetches the run's configuration again by its run id, a GET of
// <runURL>/<runID> with no query, and returns the reload answer. A 410 is the end of
// the run, [Ended]; a coded refusal is an [*accesskey.Refusal].
func (k *Link) Reload(ctx context.Context, runURL, runID string) (*LinkReloadAnswer, error) {
	if err := k.onLink("the run URL", runURL); err != nil {
		return nil, fmt.Errorf("%s: %w", k.name, err)
	}
	if !runIDShape.MatchString(runID) {
		return nil, errors.New("the reload: the run id is not a UUID in the canonical lower-case form")
	}
	u := strings.TrimSuffix(runURL, "/") + "/" + runID
	var a LinkReloadAnswer
	if err := k.fetch(ctx, "the reload", http.MethodGet, u, nil, nil, "link-reload-answer.schema.json", &a); err != nil {
		return nil, err
	}
	if err := checkRunMembers(a.Variables, a.Placeholders, a.Reserved, a.Image); err != nil {
		return nil, &DocumentError{"the reload answer", k.at(u), err}
	}
	return &a, nil
}

// Deliver posts one link batch to eventsURL, the discovery's events.url, as the
// delivery with the given id, with the run configuration digest when it holds one, and
// returns what the gateway answered, its Link set: a 2xx is accepted; a 410 ends the
// run with its End, one of [EndCodes], and its From; a 400 invalid_request ends it
// too, the gateway having ended the run, with batch_refused; anything else is retried. A
// coded answer other than a 2xx is also its Refusal. The digests of every answer but one that ends the run are in the Delivery. A transport failure or no answer within
// Timeout is an error. The body is the session's events of the run, with their ids and
// without sequence.
func (k *Link) Deliver(ctx context.Context, eventsURL, deliveryID string, body []byte, runDigest string) (Delivery, error) {
	if err := k.onLink("the events URL", eventsURL); err != nil {
		return Delivery{}, fmt.Errorf("%s: %w", k.name, err)
	}
	a, err := k.send(ctx, http.MethodPost, eventsURL, body, MaxRefusal, func(h http.Header) {
		h.Set("Content-Type", ContentType)
		h.Set(HeaderDelivery, deliveryID)
		if runDigest != "" {
			h.Set(HeaderRunConfiguration, runDigest)
		}
	})
	if err != nil {
		return Delivery{}, err
	}
	d := Delivery{Status: a.status, Link: true}
	if r := accesskey.ReadRefusal(a.status, a.body); r != nil {
		d.Code = r.Code
		if a.status < 200 || a.status > 299 {
			// The answer as the refusal it is: its code, names, who refused and its
			// message as the user is told it.
			if ref, ok := a.refusal("the events " + k.at(eventsURL)).(*accesskey.Refusal); ok {
				d.Refusal = ref
			}
		}
	}
	switch {
	case a.status == http.StatusGone:
		d.End, d.From = a.end(), a.from()
	case a.status == http.StatusBadRequest && d.Code == CodeInvalidRequest:
		// The gateway ends a run whose batch it refuses: its later requests are a 410
		// batch_refused, and the session records batch_refused as after one.
		d.End, d.From = event.ReasonBatchRefused, a.from()
	default:
		d.Digests = a.digests
	}
	return d, nil
}
