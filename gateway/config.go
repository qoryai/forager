package gateway

import (
	"io"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/run"
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
	// Listen and TLS are a separate gateway's address and certificate. Only the local
	// link is served yet: Listen must be empty and TLS nil.
	Listen string
	TLS    *TLS

	// quiet, when not zero, replaces three intervals as the time after which a run
	// whose session sends nothing ends; closeWait, when not zero, bounds each run's
	// flush. Tests set them.
	quiet, closeWait time.Duration
}

// TLS is a separate gateway's certificate and key, files in PEM. A separate gateway is
// not served yet.
type TLS struct {
	Certificate, Key string
}

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
	// gateway ended it, and Reason the code, run_closed.
	RunClosed bool
	ClosedBy  string
	Reason    string
	// Sent is how many events a resend delivered now, and Completed says a resend
	// recorded the run's exit, gateway_lost, which its record did not hold. Zero for
	// Close.
	Sent      int
	Completed bool
}
