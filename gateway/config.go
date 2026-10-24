package gateway

import (
	"context"
	"crypto/x509"
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
	// policy it narrows that one: the node only takes away. Its allow list's entries
	// that name a host itself are the only ones that open this machine's addresses and
	// the private network addresses to a guarded proxy: to the run's proxy those that
	// the run's policy allows, and to the run's stack proxy those that StackHosts lists
	// exactly.
	Policy *Policy
	// Credentials and Tools are the ones this machine defines; a run's policy selects
	// among them by name. The gateway sets a credential's value for a run with or
	// without a wall; a tool needs a wall.
	Credentials []Credential
	Tools       []Tool
	// Selects are, behind a separate gateway, the credentials a run gets, with or
	// without a wall, when the server's policy selects none, each one of Credentials by
	// name. An entry that takes an argument names the run's label it takes, the forge
	// the run's forge label must be, and the pattern the label's value must match whole;
	// an entry the run's labels do not satisfy gives no credential, and the gateway
	// reports why. Selects needs a Listen.
	Selects []Selection
	// Version is Forager's version, reported in each run's registration and in the user
	// agent of every request to the Server; empty means "dev".
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
	// Stderr. A panic's report has the stack on the lines after its first. It never
	// receives a proxy secret, an access key, a run key or an image reference.
	Report func(string)
	// Heartbeat is the interval the link's discovery announces, and each run's
	// registration toward the Server: a whole number of seconds from 1 to 300; zero means 30 seconds. The
	// session sends a heartbeat every interval, and the gateway ends a run whose session
	// sends nothing for three.
	Heartbeat time.Duration
	// RunLimits are the limits of each run on the gateway, the same for every run, so
	// that one run cannot slow the others down. A field of zero is its default.
	RunLimits RunLimits
	// StackHosts are the hosts of a run's stack proxy, gateway.stack_hosts of qory's
	// configuration: each a lower-case host name, an IPv4 address or a *. suffix, in the
	// form of a policy's allow entry. Until the run's first join request the stack proxy
	// passes a CONNECT or a plain HTTP request to one of them, on any port, and refuses
	// every other, in enforce mode, with no certificate authority and no credential; the
	// run's policy is not checked. Behind a wall or a separate gateway it is guarded as
	// the run's proxy is: it reaches this machine's addresses and the private network
	// addresses only for a host that the allow list of Policy and StackHosts both list by
	// name, not by a *. pattern, and a link-local or cloud metadata address for none.
	// Each decision is a line of Report, never a dev.qory.run.egress, and a refusal at
	// RunLimits is reported at most once a second per limit. The stack proxy also
	// allows the stack_hosts of the run's run configuration, as the allow list, allow_first
	// and deny of Policy narrow them; they open none of the addresses above. Empty, with
	// no stack_hosts in the run configuration, means every host is refused.
	StackHosts []string
	// Listen is a separate gateway's one address, host:port, port 0 a port of the
	// system's choosing: the link for the sessions of other machines, the proxy for
	// their agents, and the relay of their starters' and keyed machines' requests to the
	// Server, routed connection by connection. It needs TLS, and a Server whose access
	// key is a gateway's, ng_: the gateway verifies each run key under the Server's pin,
	// attaches each run there and relays to its origin. A gateway with an address serves
	// no local link, in memory or on a socket, and runs no sessions of its own machine.
	// Empty means the local link alone.
	Listen string
	// TLS is the certificate and key Listen serves, TLS 1.3 alone, whose exporter binds
	// every connection of the link there; Listen needs it.
	TLS *TLS
	// NoLinkSocket makes no link socket and no link directory: the gateway's local link
	// is served in memory alone, to a session in this process, the way
	// [Gateway.LocalLink] hands out, and no other process can reach it. qory run sets it.
	// False makes the socket, for a session in another process too. A gateway with
	// Listen serves no local link either way.
	NoLinkSocket bool
	// LockMemory, on Linux, makes Start lock every page of this process in memory, the
	// pages mapped now and those mapped later, so that no key the gateway holds is
	// written to swap: gateway.lock_memory of qory's configuration. Start fails when the
	// lock fails, and on any other system when LockMemory is true. False locks nothing.
	LockMemory bool

	// quiet, when not zero, replaces three intervals as the time after which a run
	// whose session sends nothing ends; closeWait, when not zero, bounds each run's
	// flush. Tests set them.
	quiet, closeWait time.Duration
	// opened, when not nil, is called once a run on the one address opened. Tests set
	// it.
	opened func()
	// marked, when not nil, is called once the record of a run on the one address is
	// marked answered, with the context of its run request. Tests set it.
	marked func(context.Context)
	// uid, when not nil, is the user the link serves in place of this process's: a test
	// sets another, so that its own connections are a peer of another user's.
	uid *int
	// now, when not nil, is the clock the one address judges a run key's attach window
	// by, in place of time.Now. Tests set it.
	now func() time.Time
	// relayWait, when not zero, replaces relayWait, how long the relay waits for the
	// server. Tests set it.
	relayWait time.Duration
	// relayInFlight, when not zero, replaces relayInFlight, the most requests the relay
	// has with the server at once. Tests set it.
	relayInFlight int
	// openWaits and openWindow, when set, replace openWaits and openWindow, the tries
	// of Qory Apiary as a run opens. Tests set them.
	openWaits  []time.Duration
	openWindow time.Duration
	// upstreamRoots, when not nil, are the roots every run's proxy verifies a
	// terminated host's certificate against, in place of this machine's. Tests set them.
	upstreamRoots *x509.CertPool
	// certCheck, when not zero, replaces the constant [certCheck], how often at most the
	// one address checks its certificate and key files for a change. Tests set it.
	certCheck time.Duration
}

// RunLimits are the limits of each run on the gateway's proxy: gateway.run_limits of
// qory's configuration. Start refuses a field outside its range; zero is the field's
// default. Each run has counters of its own: one run at its limit refuses nothing of
// another's.
type RunLimits struct {
	// Connections is the most connections a run has open through the gateway at once:
	// CONNECT tunnels, blind or terminated, and plain HTTP requests in flight. From 1 to
	// 65536; zero means 256. The next connection is refused at once with 429 Too Many
	// Requests and Retry-After: 1. Until the run's first join request its stack proxy
	// ([Config.StackHosts]) counts its connections and requests apart from the run's
	// proxy, at the same limits.
	Connections int
	// RequestsPerSecond is how many requests a run sends a second, beyond Burst: every
	// CONNECT, plain request and request inside a terminated tunnel takes one token of
	// a bucket that gains RequestsPerSecond tokens a second. From 1 to 10000; zero means
	// 50. A request waits up to 5 seconds for a token, then is refused with 429 Too Many
	// Requests and Retry-After: 1. While Connections requests of the run wait, the next
	// that needs a token is refused at once, the same way.
	RequestsPerSecond int
	// Burst is the most tokens the bucket holds: how many requests a run sends at once
	// after a pause. From 1 to 100000; zero means 200.
	Burst int
}

// TLS is the certificate and key a separate gateway serves on its one address, files in
// PEM: gateway.tls.certificate and gateway.tls.key of qory's configuration.
type TLS struct {
	// CertFile is the certificate chain, the gateway's own certificate first.
	CertFile string
	// KeyFile is the certificate's private key.
	KeyFile string
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
	// request; it matches ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$; a separate gateway's caller
	// keeps it across restarts; with another id, a restarted gateway's attach again is
	// `run_attached`. InstanceName is its display name, sent in X-Qory-Instance-Name,
	// unsigned; empty sends none.
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

// Selection is one credential the gateway selects, [Config.Selects].
type Selection = run.Selection

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
	// Undelivered is how many events the server did not accept. Whatever was spooled
	// is under the run's record directory's undelivered/; a stop during a resend spools
	// nothing. For a resend they are all still in the record's events.jsonl.
	Undelivered int
	// RunClosed says a run ended at the gateway before its session ended it, the first
	// that did for Close, since a server's 410 ends no run; ClosedReason is the code of
	// the gateway's 410 its session's later requests get: session_lost when it heard
	// nothing from the session for 3 heartbeat intervals, batch_refused when it refused
	// a batch, and stopped when the server's end member carried the outcome the run's
	// starter gave.
	RunClosed    bool
	ClosedReason string
	// State and Reason are how the run ended, where the gateway knows it: the state and
	// the reason of the dev.qory.run.exited the gateway wrote of it, Reason empty when
	// that has none. For Close, of the run RunClosed is of: failed with session_lost,
	// failed with batch_refused, or, after stopped, the state and the reason of the end
	// member, the reason stopped for a cancelled end that has none. For a resend, failed
	// with gateway_lost, with Completed. Empty otherwise.
	State  string
	Reason string
	// Sent is how many events a resend delivered now, and Completed says a resend
	// recorded the run's exit, gateway_lost, which its record did not hold. Zero for
	// Close.
	Sent      int
	Completed bool
	// NotOpened says a resend sent nothing, and left the record as it is, since the run
	// never opened at the server: the server never accepted its registration, or the run
	// had no server. Sent and Undelivered are then 0. False for Close.
	NotOpened bool
	// Stopped says the server answered a signed 410 and wants no more events of the
	// run: during the run, so the record is marked stopped and the resend sent nothing,
	// Sent and Undelivered 0, and left undelivered/ as the run left it, which may hold
	// batches spooled before the stop; or during this resend, which sent nothing more
	// and marked the record stopped, Sent what the server accepted before the 410 and
	// Undelivered what was not sent, none of it spooled. Every event not sent is still
	// in the record's events.jsonl. False for Close.
	Stopped bool
}
