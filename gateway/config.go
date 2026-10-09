package gateway

import (
	"io"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/runcredential"
)

// Config is what a gateway is given: the server it is the node toward, the machine's
// policy and definitions, where it keeps each run's record, and how it reports.
type Config struct {
	// Server is the server the gateway reports every run to and takes each run's
	// configuration from; nil means files only, the machine's policy.
	Server *Server
	// Policy is the node's policy, the one the command passes; nil means none. Without
	// a server's policy it is each run's, and none is mode observe. Beside a server's
	// policy it narrows that one: the node only takes away.
	Policy *Policy
	// Credentials and Tools are the ones this machine defines; a run's policy selects
	// among them by name. Each needs a wall.
	Credentials []Credential
	Tools       []Tool
	// Version is Forager's version, reported in the ping and in the user agent of every
	// request to the Server; empty means "dev".
	Version string
	// Discovered, when not nil, is called once the Server's signed configuration
	// document is read, before Start returns, with what it lists of the access key: qory
	// prints the node id. An error it returns is no gateway, and nothing more is sent.
	Discovered func(Discovery) error
	// Dir is the gateway's directory: a run's record directory is Dir/runs/<run id>
	// unless RunDir says otherwise. One of Dir and RunDir is needed.
	Dir string
	// RunDir, when not nil, is the record directory of a run: on one machine qory's
	// RunsDir/<run id>, where the gateway writes events.jsonl, the run's numbered
	// stream, beside its delivery state, delivered.log and undelivered/.
	RunDir func(runID string) string
	// Events, when not nil, gets every numbered event of every run as one JSON line as
	// well, the line events.jsonl holds: a run with no receiver is followed on standard
	// output this way.
	Events io.Writer
	// Report receives one line per thing the gateway reports to its user; nil means
	// Stderr. It never receives the link secret, a proxy secret, an access key or an
	// image reference.
	Report func(string)
	// Heartbeat is the interval the link's discovery announces, and the ping toward the
	// Server: a whole number of seconds from 1 to 300; zero means 30 seconds. The
	// session sends a heartbeat every interval, and the gateway ends a run whose session
	// sends nothing for three.
	Heartbeat time.Duration
	// Listen is a separate gateway's one address, host:port, port 0 a port of the
	// system's choosing: the contract for the sessions of other machines, and the proxy
	// for their agents and for clients with no session, routed connection by connection.
	// Empty means the local link alone. Any address but loopback needs TLS; the local
	// link is served beside it either way, as without it.
	Listen string
	// TLS is the certificate and key Listen serves, TLS 1.3 alone; nil serves Listen
	// without TLS, which a loopback address alone may.
	TLS *TLS
	// RunCredentials are the issuers whose run credentials open a run on Listen,
	// gateway.run_credentials of the operator's forager.yaml; required with Listen.
	// Start checks them as runcredential.Issuers.Check does, reading each key's file
	// and each introspection client's secret. The gateway tracks run keys and does not
	// require them to be unique; each period of activity is a run. The run keys it
	// refuses after the issuer's end are kept in Dir, so a restart refuses them too.
	RunCredentials runcredential.Issuers
	// Runs is how the gateway keeps the runs of clients with no session.
	Runs RunsConfig
	// NoLinkSocket makes no link socket and no link directory: the gateway's local link
	// is served in memory alone, to a session in this process, the way
	// [Gateway.LocalLink] hands out, and no other process can reach it. qory run sets it.
	// False makes the socket, for a session in another process too. With Listen it
	// serves the one address as without it, for the sessions and clients of other
	// machines, beside a local link in memory alone and no socket.
	NoLinkSocket bool

	// quiet, when not zero, replaces three intervals as the time after which a run
	// whose session sends nothing ends; closeWait, when not zero, bounds each run's
	// flush. Tests set them.
	quiet, closeWait time.Duration
	// keepSpent, when not zero, replaces runcredential.MaxLeeway as how long past its
	// exp the gateway keeps what an ended run of the one address left. Tests set it.
	keepSpent time.Duration
	// clock, when not nil, is the time the gateway refuses a run key by, in place of
	// the system's. Tests set it.
	clock func() time.Time
	// opened, when not nil, is called once a run on the one address opened, before the
	// gateway looks again whether it refuses the run's run key. Tests set it.
	opened func()
	// uid, when not nil, is the user the link serves in place of this process's: a test
	// sets another, so that its own connections are a peer of another user's.
	uid *int
	// runAuth and proxyLogin, when not nil, decide the run credentials Listen is given,
	// in place of the verifier of RunCredentials and the runs of clients with no
	// session: tests set them.
	runAuth    runAuth
	proxyLogin proxyLogin
	// introspector, when not nil, is the introspection endpoint of an issuer that has
	// one, in place of runcredential's client of it: tests set it.
	introspector func(runcredential.Issuer) activeChecker
}

// TLS is the certificate and key a separate gateway serves on its one address, files in
// PEM: gateway.tls.certificate and gateway.tls.key of qory's configuration.
type TLS struct {
	// CertFile is the certificate chain, the gateway's own certificate first.
	CertFile string
	// KeyFile is the certificate's private key.
	KeyFile string
}

// RunsConfig is how the gateway keeps the runs of clients with no session.
type RunsConfig struct {
	// Quiet is how long such a run lasts with no connection before it ends, quiet:
	// gateway.runs.quiet of the operator's forager.yaml; zero means 30 minutes.
	Quiet time.Duration
}

// defaultRunsQuiet is [RunsConfig.Quiet] when the config sets none.
const defaultRunsQuiet = 30 * time.Minute

// Server is the server document, contracts/forager/v1/server.schema.json, as the caller
// passes it to Forager, with what signs and names every request: the server whose
// configuration document says where events go and where the run configuration is, the
// access key the gateway signs every request as, and the pin, the server's keys every
// answer is verified under. Start validates the document and fetches the configuration
// document before it serves the link.
type Server struct {
	// Version is the document version, 1.
	Version int `json:"version"`
	// URL is the server's origin: https, or http to a loopback address; no path.
	URL string `json:"url"`
	// AccessKeyID is the access key's id, "ak_" and 16 lower-case Crockford base32
	// characters, which the server assigned when the key enrolled.
	AccessKeyID string `json:"access_key_id"`
	// ApiaryPublicKey is the pin: the server's Ed25519 public keys, one or more. A
	// server without a pin is apiary_public_key_missing, before any request.
	ApiaryPublicKey accesskey.Pin `json:"apiary_public_key"`
	// AccessKey is the access key every request is signed with, held from its secret,
	// which the caller reads. It is never logged.
	AccessKey *accesskey.Key `json:"-"`
	// InstanceID is this instance's id, sent in X-Qory-Instance-Id and signed into every
	// request; it matches ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$. InstanceName is its display
	// name, sent in X-Qory-Instance-Name, unsigned; empty sends none.
	InstanceID   string `json:"-"`
	InstanceName string `json:"-"`
}

// Policy is the run's policy document, contracts/forager/v1/policy.schema.json, as the
// caller passes it to Forager.
type Policy = run.Policy

// PolicyEgress is the egress section of a [Policy].
type PolicyEgress = run.PolicyEgress

// PolicyCredential selects one credential the machine defines.
type PolicyCredential = run.PolicyCredential

// PolicyTool selects one tool the machine defines.
type PolicyTool = run.PolicyTool

// ReadPolicy reads a policy document from bytes, YAML or JSON by name's extension,
// JSON when it has none, and validates it against the schema.
func ReadPolicy(name string, b []byte) (*Policy, error) { return run.ReadPolicy(name, b) }

// Credential is one credential as the machine defines it, [Config.Credentials]. Its
// Check refuses a definition that cannot be one.
type Credential = run.Credential

// Tool is one tool as the machine defines it, [Config.Tools]. Its Check refuses a
// definition that cannot be one.
type Tool = run.Tool

// Discovery is what the server's configuration document lists of the access key.
type Discovery = run.Discovery

// Image is one image as the machine defines it; its Check refuses a definition that
// cannot be one. The session sends its images with each run request, and the gateway
// resolves a policy's selection among them.
type Image = run.Image

// Delivery is what the end of a gateway's runs, or a resend, came to toward the server.
type Delivery struct {
	// Undelivered is how many events the server did not accept; they are under the run's
	// record directory's undelivered/.
	Undelivered int
	// RunClosed says the run ended at the gateway before its session ended it: ClosedBy
	// says who, "apiary" when the server closed it with a signed 410, "gateway" when the
	// gateway ended it, and Reason the code of the 410 the session's later requests get:
	// run_closed from apiary; from the gateway, session_lost when it heard nothing from
	// the session for 3 heartbeat intervals, batch_refused when it refused a batch, and
	// behind a separate gateway credential_expired or run_ended_at_issuer.
	RunClosed bool
	ClosedBy  string
	Reason    string
	// Sent is how many events a resend delivered now, and Completed says a resend
	// recorded the run's exit, gateway_lost, which its record did not hold. Zero for
	// Close.
	Sent      int
	Completed bool
}
