// Package server is the runner's client of the server contract, and what the
// receiver shares with it: how a request is signed.
//
// The server is the document of contracts/runner/v1/server.schema.json: a URL, an
// access key and a secret. [Read] validates one; the schema is the reader. A [Client]
// speaks to the server the way the contract says: [Client.Discover] fetches the
// configuration document with a signed GET and learns where events go and where the run
// configuration is; [Client.RunConfiguration] fetches that; [Client.Deliver] posts one
// signed batch and reads the digests the answer carries. Every request carries the
// access key, the contract revision and the user agent, and the client logs nothing.
//
// [Sign] and [Verify] are the signature of a POST, over the raw body; [Canonical],
// [SignGET] and [VerifyGET] the signature of a GET, over the canonical string. The
// runner's sink and the reference receiver share these, so both sides hold one
// definition of what a valid request is.
package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/qoryai/runner/contracts"
)

// The headers of the contract and the content type of a delivery.
const (
	HeaderAccessKey        = "X-Qory-Access-Key"
	HeaderContractVersion  = "X-Qory-Contract-Version"
	HeaderDelivery         = "X-Qory-Delivery"
	HeaderSignature        = "X-Qory-Signature-256"
	HeaderTimestamp        = "X-Qory-Timestamp"
	HeaderConfiguration    = "X-Qory-Configuration"
	HeaderRunConfiguration = "X-Qory-Run-Configuration"
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

// Config is the server document: where the runner reports, as whom, and the secret
// that signs, which never travels.
type Config struct {
	Version   int    `json:"version"`
	URL       string `json:"url"`
	AccessKey string `json:"access_key"`
	Secret    string `json:"secret"`
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

// DocumentError is a document the server answered with 200 and the runner refuses:
// the schema does, or its digest header is missing or misshapen. It tells a caller
// that asking again gets the same, which a transport failure or another status does
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
// when it has none. A refused document is a [*Error] naming name.
func Read(name string, b []byte) (*Config, error) {
	c, err := Parse(name, b)
	if err != nil {
		return nil, &Error{Name: name, Err: err}
	}
	return c, nil
}

// Parse validates the bytes of a server document against the schema and decodes it.
func Parse(name string, b []byte) (*Config, error) {
	var c Config
	if err := decode(name, "server.schema.json", b, &c); err != nil {
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
// where events go and which, and where the run configuration is, when the server
// offers one. A section the runner does not know is ignored.
type Configuration struct {
	Version int    `json:"version"`
	Events  Events `json:"events"`
	// Run is nil when the server names no run configuration.
	Run *Run `json:"run,omitempty"`
}

// Events is the events section: the URL to post to and the types wanted.
type Events struct {
	URL string `json:"url"`
	// Types are full type names, or "*" for every type. The ping is always sent.
	Types []string `json:"types"`
}

// Run is the run section: where the run configuration is fetched from.
type Run struct {
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
	Variables map[string]string `json:"variables,omitzero"`
}

// Digests are what an answer says is in force: the server's digest of the
// configuration document and of the run's run configuration, each empty when the answer
// did not say. They are opaque: compared byte for byte, never recomputed.
type Digests struct {
	Configuration    string
	RunConfiguration string
}

// Sign returns the signature header value of a body: "sha256=" and the hex HMAC
// SHA-256 of the body keyed with the secret.
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// Verify reports whether header is the signature of body under the secret, compared in
// constant time.
func Verify(secret string, body []byte, header string) bool {
	return hmac.Equal([]byte(Sign(secret, body)), []byte(header))
}

// Canonical is the string a GET is signed over: the method upper case, the request
// target exactly as sent, and the timestamp as sent, joined by newlines with none at
// the end. The target is the path, then "?" and the query only when the query is
// non-empty; nothing is normalised on either side.
func Canonical(method, target, timestamp string) string {
	return strings.ToUpper(method) + "\n" + target + "\n" + timestamp
}

// SignGET returns the signature header value of a GET: "sha256=" and the hex HMAC
// SHA-256 of the canonical string keyed with the secret.
func SignGET(secret, method, target, timestamp string) string {
	return Sign(secret, []byte(Canonical(method, target, timestamp)))
}

// VerifyGET reports whether header is the signature of the GET under the secret,
// compared in constant time.
func VerifyGET(secret, method, target, timestamp, header string) bool {
	return hmac.Equal([]byte(SignGET(secret, method, target, timestamp)), []byte(header))
}

// Timestamp is the timestamp header value for a moment: Unix seconds, UTC, as a
// decimal integer.
func Timestamp(now time.Time) string { return strconv.FormatInt(now.Unix(), 10) }

// Client speaks to one server.
type Client struct {
	Config *Config
	// UserAgent is sent as User-Agent: qory-runner/<version>.
	UserAgent string
	// HTTP is the client used; nil means one with Timeout. Its redirect policy is
	// not used: the client follows no redirect.
	HTTP *http.Client
}

// http is the client every request goes through: the caller's, copied, or one with
// Timeout, and in either case one that follows no redirect. Go copies a request's
// headers to wherever a redirect points, so a followed 3xx would hand the access key,
// the signature and the timestamp to another host and take the answer from it. A 3xx
// is a status like any other.
func (c *Client) http() *http.Client {
	hc := &http.Client{Timeout: Timeout}
	if c.HTTP != nil {
		cp := *c.HTTP
		hc = &cp
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return hc
}

// headers sets what every request carries.
func (c *Client) headers(req *http.Request) {
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set(HeaderAccessKey, c.Config.AccessKey)
	req.Header.Set(HeaderContractVersion, strconv.Itoa(Revision))
}

// get makes one signed GET of u and returns the answer, whatever its status.
func (c *Client) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	ts := Timestamp(time.Now())
	c.headers(req)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, SignGET(c.Config.Secret, req.Method, req.URL.RequestURI(), ts))
	return c.http().Do(req)
}

// fetch makes one signed GET of a document, which must answer 200 with the digest
// header named, validates the body against the schema and decodes it into out. The
// error names the URL and the status.
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

// fetchBody makes one signed GET of a document, which must answer 200 with the digest
// header named, and returns its bytes and the digest. The error names the URL and the
// status.
func (c *Client) fetchBody(ctx context.Context, what, u, digestHeader string) ([]byte, string, error) {
	resp, err := c.get(ctx, u)
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", what, u, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocument+1))
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", what, u, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s %s: status %d", what, u, resp.StatusCode)
	}
	if len(body) > MaxDocument {
		return nil, "", &DocumentError{what, u, fmt.Errorf("the document is over %d bytes", MaxDocument)}
	}
	digest := resp.Header.Get(digestHeader)
	if digest == "" {
		return nil, "", &DocumentError{what, u, fmt.Errorf("the answer carries no %s header", digestHeader)}
	}
	return body, digest, nil
}

// Discover fetches the configuration document from the server's well-known path and
// returns it with the server's digest of it. An error, transport, status or a document
// the schema refuses, means no run; it names the URL.
func (c *Client) Discover(ctx context.Context) (*Configuration, string, error) {
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
// grammar, a value longer than 256 bytes or not UTF-8. The runner checks a run's labels
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

// Deliver posts one body to the events URL as the delivery with the given id, with the
// run's run configuration digest when it holds one, and returns the server's status and
// the digests its answer carries. A transport failure or no answer within Timeout is an
// error and no status.
func (c *Client) Deliver(ctx context.Context, eventsURL, deliveryID string, body []byte, runDigest string) (int, Digests, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, eventsURL, strings.NewReader(string(body)))
	if err != nil {
		return 0, Digests{}, err
	}
	c.headers(req)
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set(HeaderDelivery, deliveryID)
	req.Header.Set(HeaderSignature, Sign(c.Config.Secret, body))
	if runDigest != "" {
		req.Header.Set(HeaderRunConfiguration, runDigest)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return 0, Digests{}, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, Digests{Configuration: resp.Header.Get(HeaderConfiguration), RunConfiguration: resp.Header.Get(HeaderRunConfiguration)}, nil
}

// Accepted reports whether a status accepts a delivery.
func Accepted(status int) bool { return status >= 200 && status < 300 }

// Stop reports whether a status tells the runner to send nothing more for the run.
func Stop(status int) bool { return status == http.StatusGone }

// ErrNotAccepted is the error of a ping the server did not accept.
var ErrNotAccepted = errors.New("the server did not accept the ping")

// Ping delivers a batch of one ping event to the events URL and returns nil only on a
// 2xx. It is what makes a configured server fail closed: the run does not start
// otherwise. The error names the URL and the status.
func (c *Client) Ping(ctx context.Context, eventsURL, deliveryID string, body []byte) error {
	status, _, err := c.Deliver(ctx, eventsURL, deliveryID, body, "")
	if err != nil {
		return fmt.Errorf("ping %s: %w", eventsURL, err)
	}
	if !Accepted(status) {
		return fmt.Errorf("ping %s: status %d: %w", eventsURL, status, ErrNotAccepted)
	}
	return nil
}
