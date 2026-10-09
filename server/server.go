// Package server is Forager's client of the server contract.
//
// The server is the document of contracts/forager/v1/server.schema.json: a URL, an
// access key id and the pin, apiary_public_key, the server's keys every answer is
// verified under. [Read] validates one; the schema is the reader. The access key's
// secret lives outside the document, and a [Client] holds it as an [accesskey.Key]
// with the instance id. A [Client] speaks to the server the way the contract says:
// [Client.Discover] fetches the configuration document with a signed GET and learns
// where events go and where the run configuration is; [Client.RunConfiguration]
// fetches that; [Client.Deliver] posts one signed batch and reads the digests the
// answer contains; [Client.Ping] posts the ping a run starts with. Every request
// contains the access key id, the instance id and name, the contract revision and the
// user agent, and is signed with Ed25519 under the access key. Every answer but a 401
// is verified under the pin before its body or headers are read, and the client logs
// nothing.
//
// A refusal that means no run is an [*accesskey.Refusal] with its code: unauthorized
// for a 401, answer_unsigned for an answer that does not verify, and the server's own
// code from a signed answer's body, instance_limit or rate_limited say.
//
// A [Link] is the session's client of its gateway's link, the same protocol on the same
// paths, unsigned: the transport authenticates both ends. It is the one place an
// unsigned answer is read, and only an answer that came over the link: a [Client]
// never reads one.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
)

// The headers of the contract and the content type of a delivery.
const (
	HeaderAccessKeyID      = accesskey.HeaderAccessKeyID
	HeaderInstanceID       = accesskey.HeaderInstanceID
	HeaderInstanceName     = accesskey.HeaderInstanceName
	HeaderSignature        = accesskey.HeaderSignature
	HeaderTimestamp        = accesskey.HeaderTimestamp
	HeaderConfiguration    = accesskey.HeaderConfiguration
	HeaderRunConfiguration = accesskey.HeaderRunConfiguration
	HeaderContractVersion  = "X-Qory-Contract-Version"
	HeaderDelivery         = "X-Qory-Delivery"
	ContentType            = "application/cloudevents-batch+json"
)

// Revision is the contract revision the client announces, in the header and in the
// ping: the contract's own.
const Revision = contracts.Revision

// WellKnown is the path of the configuration document under the server's URL.
const WellKnown = "/.well-known/qory-configuration"

// Timeout is how long a server has to answer one request.
const Timeout = 10 * time.Second

// Window is how far a signed GET's timestamp may be from the receiver's clock,
// either way.
const Window = 300 * time.Second

// MaxDocument is the largest configuration or run configuration document read.
const MaxDocument = 1 << 20

// MaxRefusal is the largest body of an answer other than a document: a larger one
// counts as unsigned.
const MaxRefusal = accesskey.MaxAnswer

// MaxInterval is the longest heartbeat interval a ping may announce, in seconds.
const MaxInterval = 300

// Config is the server document: where Forager reports, as which access key, and
// the server keys it pins. The access key's secret is outside it.
type Config struct {
	Version     int    `json:"version"`
	URL         string `json:"url"`
	AccessKeyID string `json:"access_key_id"`
	// ApiaryPublicKey is the pin: every answer is verified under one of its keys.
	ApiaryPublicKey accesskey.Pin `json:"apiary_public_key"`
}

// Error is a document that is not a server document. A run does not start on it.
type Error struct {
	// Name is what the caller called the document: a file name, or "server".
	Name string
	Err  error
}

func (e *Error) Error() string { return "server " + e.Name + ": " + e.Err.Error() }

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// DocumentError is a document the server answered with a signed 200 and Forager
// refuses: the schema does, or its digest header is missing or misshapen. It means
// that fetching again gets the same, which a transport failure or another status does
// not.
type DocumentError struct {
	// What is the document's kind and URL the URL it was fetched from.
	What, URL string
	Err       error
}

func (e *DocumentError) Error() string { return e.What + " " + e.URL + ": " + e.Err.Error() }

// Unwrap returns the underlying error.
func (e *DocumentError) Unwrap() error { return e.Err }

// Read reads a server document from bytes, YAML or JSON by name's extension, JSON
// when it has none. A document without a pin is an [*accesskey.Refusal] with the code
// apiary_public_key_missing, decided before any request; any other refused document
// is a [*Error] naming name.
func Read(name string, b []byte) (*Config, error) {
	c, err := Parse(name, b)
	if err != nil {
		var missing *accesskey.Refusal
		if errors.As(err, &missing) {
			return nil, err
		}
		return nil, &Error{Name: name, Err: err}
	}
	return c, nil
}

// Parse validates the bytes of a server document against the schema and decodes it,
// and checks the pin's keys as [accesskey.Pin.Check] does. A document that contains an
// access key secret anywhere, in its bytes or, escaped, in a decoded string or member
// name, is [accesskey.ErrSecretInDocument] before a schema reads it, so no schema
// error quotes the secret.
func Parse(name string, b []byte) (*Config, error) {
	if accesskey.ContainsSecret(string(b)) {
		return nil, accesskey.ErrSecretInDocument
	}
	file := name
	if !strings.Contains(file, ".") {
		file += ".json"
	}
	doc, err := contracts.Decode(file, b)
	if err != nil {
		return nil, err
	}
	if accesskey.DocumentContainsSecret(doc) {
		return nil, accesskey.ErrSecretInDocument
	}
	if m, ok := doc.(map[string]any); ok {
		if pin, _ := m["apiary_public_key"].([]any); len(pin) == 0 {
			return nil, &accesskey.Refusal{Code: accesskey.CodeApiaryPublicKeyMissing, Detail: "server " + name + ": no pinned apiary_public_key"}
		}
	}
	var c Config
	if err := decode(name, "server.schema.json", b, &c); err != nil {
		return nil, err
	}
	if err := c.ApiaryPublicKey.Check(); err != nil {
		return nil, err
	}
	return &c, nil
}

// decode validates the bytes of a document against one schema of the contract and
// decodes them into out. name chooses YAML or JSON by its extension, JSON when it has
// none.
func decode(name, schemaName string, b []byte, out any) error {
	if !strings.Contains(name, ".") {
		name += ".json"
	}
	doc, err := contracts.Decode(name, b)
	if err != nil {
		return err
	}
	schema, err := contracts.Compile(schemaName)
	if err != nil {
		return err
	}
	if err := schema.Validate(doc); err != nil {
		return err
	}
	j, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return json.Unmarshal(j, out)
}

// Configuration is the configuration document the server answers discovery with:
// the access key's node, where events go and which, where the run configuration is
// when the server offers one, a secrets section for an access key allowed stored
// secrets, and the server's keys. A section Forager does not know is ignored.
type Configuration struct {
	Version int `json:"version"`
	// NodeID is the id of the access key's node, nd_, or node pool, np_, for display.
	NodeID string `json:"node_id"`
	Events Events `json:"events"`
	// Run is nil when the server offers no run configuration.
	Run *Endpoint `json:"run,omitempty"`
	// Secrets is nil unless the access key is allowed stored secrets.
	Secrets *Endpoint `json:"secrets,omitempty"`
	// ApiaryPublicKey lists the server's keys, for information: Forager verifies under
	// its pin alone.
	ApiaryPublicKey accesskey.Pin `json:"apiary_public_key"`
}

// Events is the events section: the URL to post to and the types wanted.
type Events struct {
	URL string `json:"url"`
	// Types are full type names, or "*" for every type. The ping is always sent.
	Types []string `json:"types"`
}

// Endpoint is a section that defines one URL: run, where the run configuration is
// fetched from, or secrets, listed for an access key allowed stored secrets.
type Endpoint struct {
	URL string `json:"url"`
}

// Wants reports whether the events section asks for events of the type: every type
// when it holds "*", else the listed ones. The ping is always wanted.
func (c *Configuration) Wants(typ string) bool {
	if typ == "dev.qory.ping" {
		return true
	}
	for _, e := range c.Events.Types {
		if e == "*" || e == typ {
			return true
		}
	}
	return false
}

// RunConfiguration is the run configuration document: the server's policy for the run,
// as the server's raw section, which the policy package reads, and the server's
// variables.
type RunConfiguration struct {
	Version int `json:"version"`
	// SecurityPolicy is nil when the document has none: the node's policy is then the
	// run's.
	SecurityPolicy json.RawMessage `json:"security_policy,omitzero"`
	// Variables are the server's variables, by name; nil when the document has none.
	Variables map[string]Variable `json:"variables,omitzero"`
}

// Variable is one of a run configuration's variables: its value. A member beside it is
// an attribute Forager may ignore, and does.
type Variable struct {
	Value string `json:"value"`
}

// Values are the run configuration's variables as values by name; nil when the
// document has none.
func (rc *RunConfiguration) Values() map[string]string {
	if rc.Variables == nil {
		return nil
	}
	out := make(map[string]string, len(rc.Variables))
	for name, v := range rc.Variables {
		out[name] = v.Value
	}
	return out
}

// Digests are what an answer says is in force: the server's digest of the
// configuration document and of the run's run configuration, each empty when the answer
// did not say. They are opaque: compared byte for byte, never recomputed.
type Digests struct {
	Configuration    string
	RunConfiguration string
}

// Client speaks to one server as one instance of one access key.
type Client struct {
	Config *Config
	// Key is the access key, held from its secret; it signs every request.
	Key *accesskey.Key
	// InstanceID is X-Qory-Instance-Id, signed into every request; InstanceName is
	// X-Qory-Instance-Name, for display, sent when not empty.
	InstanceID, InstanceName string
	// UserAgent is sent as User-Agent: qory-forager/<version>.
	UserAgent string
	// HTTP is the client used; nil means one with Timeout. Its redirect policy is
	// not used: the client follows no redirect.
	HTTP *http.Client
}

// Check refuses a client that cannot make a request the contract allows: no server
// document, no pin, which is apiary_public_key_missing, a pin [accesskey.Pin.Check]
// refuses, an access key id outside its form, no access key, or an instance id or name
// outside their pattern. It sends nothing.
func (c *Client) Check() error {
	if c.Config == nil {
		return errors.New("no server document")
	}
	if len(c.Config.ApiaryPublicKey) == 0 {
		return &accesskey.Refusal{Code: accesskey.CodeApiaryPublicKeyMissing, Detail: "the server document pins no apiary_public_key"}
	}
	if err := c.Config.ApiaryPublicKey.Check(); err != nil {
		return err
	}
	if err := accesskey.CheckID(c.Config.AccessKeyID); err != nil {
		return err
	}
	if c.Key == nil {
		return errors.New("a server needs the access key's secret, and the run has none")
	}
	if err := accesskey.CheckInstanceID(c.InstanceID); err != nil {
		return err
	}
	if c.InstanceName != "" {
		if err := accesskey.CheckName(c.InstanceName); err != nil {
			return fmt.Errorf("the instance's name: %w", err)
		}
	}
	return nil
}

// http is the client every request goes through: the caller's, copied, or one with
// Timeout, and in either case one that follows no redirect and keeps no cookie. Go
// copies a request's headers to wherever a redirect points, so a followed 3xx would
// hand the access key id, the signature and the timestamp to another host and take the
// answer from it. A 3xx is a status like any other.
func (c *Client) http() *http.Client {
	hc := &http.Client{Timeout: Timeout}
	if c.HTTP != nil {
		cp := *c.HTTP
		hc = &cp
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc.Jar = nil
	return hc
}

// answer is what the server answered one request: its status and body, and whether
// its signature verified under the pin. The headers of an answer that did not verify
// are not kept.
type answer struct {
	status int
	body   []byte
	signed bool
	header http.Header
}

// send signs one request and sends it, then reads the answer and verifies its
// signature under the pin, bound to this request's signature. A GET carries the
// timestamp; a POST's signature covers its body. A 401 is never signed, and a body
// over max, or a body over MaxRefusal with a status other than 200, counts as
// unsigned. An error is a transport failure: no answer.
func (c *Client) send(ctx context.Context, method, u string, body []byte, max int, set func(http.Header)) (*answer, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body == nil {
		req.Body, req.ContentLength = nil, 0
	}
	if set != nil {
		set(req.Header)
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set(HeaderAccessKeyID, c.Config.AccessKeyID)
	req.Header.Set(HeaderInstanceID, c.InstanceID)
	if c.InstanceName != "" {
		req.Header.Set(HeaderInstanceName, c.InstanceName)
	}
	req.Header.Set(HeaderContractVersion, strconv.Itoa(Revision))
	signed := accesskey.Request{AccessKeyID: c.Config.AccessKeyID, InstanceID: c.InstanceID, Method: method, Target: req.URL.RequestURI()}
	if method == http.MethodPost {
		signed.Body = body
	} else {
		signed.Timestamp = accesskey.Timestamp(time.Now())
		req.Header.Set(HeaderTimestamp, signed.Timestamp)
	}
	sig, err := c.Key.SignRequest(signed)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderSignature, sig)
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil {
		return nil, err
	}
	a := &answer{status: resp.StatusCode, body: b}
	if resp.StatusCode == http.StatusUnauthorized || len(b) > max || (resp.StatusCode != http.StatusOK && len(b) > MaxRefusal) {
		return a, nil
	}
	one := func(name string) (string, bool) {
		v := resp.Header.Values(name)
		return strings.Join(v, ""), len(v) <= 1
	}
	signature, ok1 := one(HeaderSignature)
	conf, ok2 := one(HeaderConfiguration)
	run, ok3 := one(HeaderRunConfiguration)
	if ok1 && ok2 && ok3 && c.Config.ApiaryPublicKey.VerifyAnswer(accesskey.Answer{Status: resp.StatusCode, RequestSignature: sig, Body: b, Configuration: conf, RunConfiguration: run}, signature) {
		a.signed, a.header = true, resp.Header
	}
	return a, nil
}

// refusal is the error of an answer at run start that is not the one wanted: a 401 is
// unauthorized, the server's refusal though unsigned; an answer that did not verify is
// answer_unsigned, which Forager decides; a signed answer is the code its body
// contains, or, without one, an error naming its status.
func (a *answer) refusal(what string) error {
	switch {
	case a.status == http.StatusUnauthorized:
		return &accesskey.Refusal{Code: accesskey.CodeUnauthorized, Status: a.status, Detail: what, From: accesskey.FromApiary}
	case !a.signed:
		return &accesskey.Refusal{Code: accesskey.CodeAnswerUnsigned, Status: a.status, Detail: what}
	}
	if r := accesskey.ReadRefusal(a.status, a.body); r != nil {
		r.Detail = what
		return r
	}
	return fmt.Errorf("%s: status %d", what, a.status)
}

// fetch makes one signed GET of a document, which must answer a signed 200 with the
// digest header named, validates the body against the schema and decodes it into out.
// The error names the URL and the status.
func (c *Client) fetch(ctx context.Context, what, u, digestHeader, schemaName string, out any) (string, error) {
	body, digest, err := c.fetchBody(ctx, what, u, digestHeader)
	if err != nil {
		return "", err
	}
	if err := decode(what+".json", schemaName, body, out); err != nil {
		return "", &DocumentError{what, u, err}
	}
	return digest, nil
}

// fetchBody makes one signed GET of a document, which must answer a signed 200 with
// the digest header named, and returns its bytes and the digest. The bytes are
// returned only once the answer's signature verifies under the pin, so nothing reads
// a body the server did not sign. The error names the URL and the status.
func (c *Client) fetchBody(ctx context.Context, what, u, digestHeader string) ([]byte, string, error) {
	a, err := c.send(ctx, http.MethodGet, u, nil, MaxDocument, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", what, u, err)
	}
	if a.status != http.StatusOK || !a.signed {
		return nil, "", a.refusal(what + " " + u)
	}
	digest := a.header.Get(digestHeader)
	if digest == "" {
		return nil, "", &DocumentError{what, u, fmt.Errorf("the answer contains no %s header", digestHeader)}
	}
	return a.body, digest, nil
}

// Discover fetches the configuration document from the server's well-known path and
// returns it with the server's digest of it. An error, transport, status or a document
// the schema refuses, means no run; it names the URL. A 401 is unauthorized, a signed
// refusal is the code its body contains, rate_limited say, and an answer that does not
// verify is answer_unsigned, each an [*accesskey.Refusal].
func (c *Client) Discover(ctx context.Context) (*Configuration, string, error) {
	if err := c.Check(); err != nil {
		return nil, "", err
	}
	var conf Configuration
	digest, err := c.fetch(ctx, "configuration", strings.TrimSuffix(c.Config.URL, "/")+WellKnown, HeaderConfiguration, "configuration.schema.json", &conf)
	if err != nil {
		return nil, "", err
	}
	return &conf, digest, nil
}

// RunConfiguration fetches the run configuration from the run section's URL for the
// run's labels, and returns it with the server's digest of it. Every label is one query
// parameter, its key the name and its value the value, added to any query the URL has,
// sorted by key and percent-encoded; no label is no query. Which labels name what the
// run works on is the server's to decide. The query is part of the signed target.
func (c *Client) RunConfiguration(ctx context.Context, runURL string, labels map[string]string) (*RunConfiguration, string, error) {
	u, err := url.Parse(runURL)
	if err != nil {
		return nil, "", fmt.Errorf("run configuration %s: %w", runURL, err)
	}
	q := u.Query()
	for k, v := range labels {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	body, digest, err := c.fetchBody(ctx, "run configuration", u.String(), HeaderRunConfiguration)
	if err != nil {
		return nil, "", err
	}
	rc, err := readRunConfiguration(body)
	if err != nil {
		return nil, "", &DocumentError{"run configuration", u.String(), err}
	}
	// The digest is recorded in the run's events, whose schema holds it to this shape;
	// it is not recomputed.
	if !digestShape.MatchString(digest) {
		return nil, "", &DocumentError{"run configuration", u.String(), fmt.Errorf("the %s header is not sha256= and 64 hex digits", HeaderRunConfiguration)}
	}
	return rc, digest, nil
}

// MaxLabels is how many labels a run may carry.
const MaxLabels = 16

// labelKeyShape is a label key's form.
var labelKeyShape = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

// CheckLabels refuses labels the contract's schema would: too many, a key outside its
// grammar, a value longer than 256 bytes or not UTF-8. Forager checks a run's labels
// with it before they are sent, and the receiver the labels a run configuration request
// carries.
func CheckLabels(labels map[string]string) error {
	if len(labels) > MaxLabels {
		return fmt.Errorf("%d labels; a run carries at most %d", len(labels), MaxLabels)
	}
	for k, v := range labels {
		if !labelKeyShape.MatchString(k) {
			return fmt.Errorf("the label key %q is not 1 to 64 of a-z, 0-9, underscore, dot and dash", k)
		}
		if len(v) > 256 || !utf8.ValidString(v) {
			return fmt.Errorf("the value of the label %s is longer than 256 bytes or not UTF-8", k)
		}
	}
	return nil
}

// digestShape is the shape of a server's digest as the events record it.
var digestShape = regexp.MustCompile(`^sha256=[0-9a-f]{64}$`)

// Delivery is what the server answered one batch.
type Delivery struct {
	Status int
	// Signed says the answer verified under the pin. An answer that did not is no
	// answer: it is retried, and nothing else of it is read.
	Signed bool
	// Link says the answer came over the gateway's link, where answers are unsigned and
	// the link's transport authenticates them: a [Link] sets it, and it is never set
	// toward the server, where Signed alone decides.
	Link bool
	// Code is the refusal code a signed answer's body contains, or an answer's on the
	// link, empty when none.
	Code string
	// End is, on the link, the end of the run at the gateway this answer says, one of
	// [EndCodes]: a 410's code, and run_closed for a batch the gateway refused
	// invalid_request. Empty for any other answer, and always toward the server.
	End string
	// From is, on the link, who ended or refused: [accesskey.FromApiary] when the
	// body says so, else [accesskey.FromGateway]. Empty toward the server.
	From string
	// Digests are the digests a signed answer, or an answer on the link, contains.
	Digests Digests
}

// Authentic reports whether the answer is one to read: signed under the pin toward the
// server, or an answer on the gateway's link.
func (d Delivery) Authentic() bool { return d.Signed || d.Link }

// Accepted reports whether the server accepted the batch: a signed 2xx, or a 2xx on
// the link.
func (d Delivery) Accepted() bool { return d.Authentic() && d.Status >= 200 && d.Status < 300 }

// Closed reports whether the server closed the run: a signed 410 run_closed; on the
// link, an answer with an End. The run ends, as at its time limit, and nothing further
// is sent.
func (d Delivery) Closed() bool {
	if d.Link {
		return d.End != ""
	}
	return d.Signed && d.Status == http.StatusGone && d.Code == accesskey.CodeRunClosed
}

// Stop reports whether the server wants nothing more for the run: a signed 410, or on
// the link an answer with an End. Its events go on to the file sink alone.
func (d Delivery) Stop() bool {
	if d.Link {
		return d.End != ""
	}
	return d.Signed && d.Status == http.StatusGone
}

// Deliver posts one body to the events URL as the delivery with the given id, with the
// run's run configuration digest when it holds one, and returns what the server
// answered. A transport failure or no answer within Timeout is an error.
func (c *Client) Deliver(ctx context.Context, eventsURL, deliveryID string, body []byte, runDigest string) (Delivery, error) {
	a, err := c.send(ctx, http.MethodPost, eventsURL, body, MaxRefusal, func(h http.Header) {
		h.Set("Content-Type", ContentType)
		h.Set(HeaderDelivery, deliveryID)
		if runDigest != "" {
			h.Set(HeaderRunConfiguration, runDigest)
		}
	})
	if err != nil {
		return Delivery{}, err
	}
	d := Delivery{Status: a.status, Signed: a.signed}
	if a.signed {
		d.Digests = Digests{Configuration: a.header.Get(HeaderConfiguration), RunConfiguration: a.header.Get(HeaderRunConfiguration)}
		if r := accesskey.ReadRefusal(a.status, a.body); r != nil {
			d.Code = r.Code
		}
	}
	return d, nil
}

// ErrNotAccepted is the error of a ping the server answered, signed, with neither a
// 2xx nor a code.
var ErrNotAccepted = errors.New("the server did not accept the ping")

// Ping delivers a batch of one ping event to the events URL and returns nil only on a
// signed 2xx. It is what makes a configured server fail closed: the run does not start
// otherwise. A 401 is unauthorized, an answer that does not verify answer_unsigned,
// and a signed refusal its code, instance_limit or rate_limited say, each an
// [*accesskey.Refusal]; the error names the URL and the status.
func (c *Client) Ping(ctx context.Context, eventsURL, deliveryID string, body []byte) error {
	a, err := c.send(ctx, http.MethodPost, eventsURL, body, MaxRefusal, func(h http.Header) {
		h.Set("Content-Type", ContentType)
		h.Set(HeaderDelivery, deliveryID)
	})
	if err != nil {
		return fmt.Errorf("ping %s: %w", eventsURL, err)
	}
	if a.signed && a.status >= 200 && a.status < 300 {
		return nil
	}
	err = a.refusal("ping " + eventsURL)
	var r *accesskey.Refusal
	if !errors.As(err, &r) {
		return fmt.Errorf("%w: %w", err, ErrNotAccepted)
	}
	return err
}
