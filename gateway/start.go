package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/stream"
	"github.com/qoryai/forager/gateway/internal/tool"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/program"
	"github.com/qoryai/forager/server"
)

// Paths of the local link, each on [server.LocalOrigin].
const (
	eventsPath = "/v1/events"
	runPath    = "/v1/run-configuration"
)

// defaultHeartbeat is the interval when the config names none.
const defaultHeartbeat = 30 * time.Second

// Gateway is a gateway serving sessions on its local link, or those of other machines
// on its one address with [Config.Listen]: it opens each run, decides its connections by
// its policy through its proxy, numbers its events and sends them to the server.
type Gateway struct {
	cfg      Config
	report   func(string)
	interval int
	quiet    time.Duration

	// client is the server's, nil without one; conf and confDigest are its
	// configuration document and its digest, under confMu: read again when an answer
	// carries another digest.
	client     *server.Client
	confMu     sync.Mutex
	conf       *server.Configuration
	confDigest string
	// registrations are the registrations built for run ids, each kept for
	// [keepRegistration], so the retry of a run id whose session gave up as it opened
	// sends the same bytes, which the server answers alike, where other bytes would be
	// refused run_id_used.
	regMu         sync.Mutex
	registrations map[string]keptRegistration

	// base is the context of everything a run starts, cancelled when Close is done.
	base   context.Context
	cancel context.CancelFunc

	dir     string
	secret  secretValue
	ln      net.Listener
	link    *linkListener
	http    *http.Server
	proxies *proxy.Listener
	stream  *stream.Stream
	// svc is the gateway's one address, nil without [Config.Listen]; with it there is
	// no local link, ln, link, http and proxies all nil.
	svc *service
	// discovery is the link's discovery answer, and discoveryDigest its digest, the
	// X-Qory-Configuration of every answer.
	discovery       []byte
	discoveryDigest string

	mu      sync.Mutex
	closing bool
	// used are the run ids a run request named whose run has a record, open or not:
	// each is run_id_used from then on. runs are the runs that opened, live or ended.
	used  map[string]bool
	runs  map[string]*linkRun
	opens sync.WaitGroup
	// spent are the runs on the one address that ended and were let go of, by their run
	// id, each kept for [keepEnded]; spentErrs and the delivery hold what they came to,
	// for Close.
	spent     map[string]spentRun
	spentErrs []error
	// bySecret are the run ids of the session's runs, live, ended or spent, by the
	// SHA-256 of their run secret.
	bySecret map[[sha256.Size]byte]string

	closed   chan struct{}
	delivery Delivery
	closeErr error
}

// Start starts a gateway: with a server, it fetches the server's configuration
// document first and calls [Config.Discovered], and a refusal is an
// [*accesskey.Refusal]; then, without [Config.Listen], it makes the local link, served
// in memory to a session in this process and, unless [Config.NoLinkSocket], on a socket
// in a private directory of its own, and the shared proxy listener on loopback; with
// Listen, its one address alone. It serves sessions until Close, and sends nothing more
// before a session opens a run.
//
// Start refuses, before anything starts, a Listen that is not host:port, a Listen
// without TLS or without a Server, TLS files it cannot read or whose certificate and key
// do not match, and TLS without a Listen; and once discovery is read, a Listen whose
// access key is not a gateway's, whose node id is not ng_.
func Start(ctx context.Context, cfg Config) (*Gateway, error) {
	cert, err := checkService(&cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Dir == "" && cfg.RunDir == nil {
		return nil, errors.New("the gateway needs a directory, or a record directory for each run")
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = defaultHeartbeat
	}
	if cfg.Heartbeat < time.Second || cfg.Heartbeat > server.MaxInterval*time.Second || cfg.Heartbeat%time.Second != 0 {
		return nil, fmt.Errorf("the heartbeat interval %s is not a whole number of seconds from 1 to the %d the link's discovery announces at most", cfg.Heartbeat, server.MaxInterval)
	}
	if cfg.Policy != nil {
		b, _ := json.Marshal(cfg.Policy)
		if _, err := policy.Read("policy", b); err != nil {
			return nil, err
		}
	}
	for _, c := range cfg.Credentials {
		if err := c.Check(); err != nil {
			return nil, err
		}
	}
	for _, t := range cfg.Tools {
		if err := t.Check(); err != nil {
			return nil, err
		}
	}
	report := cfg.Report
	if report == nil {
		report = func(line string) { fmt.Fprintln(os.Stderr, "qory run:", line) }
	}
	g := &Gateway{cfg: cfg, report: report, interval: int(cfg.Heartbeat / time.Second), used: map[string]bool{}, runs: map[string]*linkRun{}, closed: make(chan struct{}),
		spent: map[string]spentRun{}}
	g.quiet = 3 * cfg.Heartbeat
	if cfg.quiet != 0 {
		g.quiet = cfg.quiet
	}
	if cfg.Server != nil {
		client, err := newClient(cfg.Server, cfg.Version)
		if err != nil {
			return nil, err
		}
		conf, digest, err := client.Discover(ctx)
		if err != nil {
			return nil, err
		}
		if cfg.Discovered != nil {
			if err := cfg.Discovered(Discovery{NodeID: conf.NodeID, Secrets: conf.Secrets != nil}); err != nil {
				return nil, err
			}
		}
		if cfg.Listen != "" && !strings.HasPrefix(conf.NodeID, "ng_") {
			return nil, fmt.Errorf("the access key's node %s is not a gateway, ng_: the gateway's address %s needs a gateway's access key", conf.NodeID, cfg.Listen)
		}
		g.client, g.conf, g.confDigest = client, conf, digest
	}
	g.base, g.cancel = context.WithCancel(context.WithoutCancel(ctx))
	ok := false
	defer func() {
		if !ok {
			g.cancel()
		}
	}()
	if cfg.Listen != "" {
		// A gateway with an address serves other machines alone: no local link, and no
		// proxy on loopback.
		g.stream = stream.New(stream.Config{Dir: cfg.Dir, RunDir: cfg.RunDir, Events: cfg.Events, Report: report, CloseWait: cfg.closeWait})
		if g.svc, err = g.startService(cert); err != nil {
			return nil, err
		}
		ok = true
		return g, nil
	}
	secret, err := newSecret()
	if err != nil {
		return nil, err
	}
	g.secret = newSecretValue(secret)
	if !cfg.NoLinkSocket {
		if err := g.listenLink(); err != nil {
			return nil, err
		}
		defer func() {
			if !ok {
				g.ln.Close()
				os.RemoveAll(g.dir)
			}
		}()
	}
	var refused sync.Once
	g.proxies, err = proxy.NewListener("", func(why string) {
		// Told once, as today's session tells it for its one run: a peer that keeps
		// trying says nothing new.
		refused.Do(func() { report(why) })
	})
	if err != nil {
		return nil, err
	}
	g.stream = stream.New(stream.Config{Dir: cfg.Dir, RunDir: cfg.RunDir, Events: cfg.Events, Report: report, CloseWait: cfg.closeWait})
	g.discovery, _ = json.Marshal(server.LinkDiscovery{
		Version: 1,
		Events:  server.LinkEvents{URL: server.LocalOrigin + eventsPath, Types: []string{"*"}, IntervalSeconds: g.interval},
		Run:     server.Endpoint{URL: server.LocalOrigin + runPath},
		Proxy:   &server.LinkProxy{Address: g.proxies.Addr()},
	})
	sum := sha256.Sum256(g.discovery)
	g.discoveryDigest = "sha256=" + hex.EncodeToString(sum[:])
	uid := os.Getuid()
	if cfg.uid != nil {
		uid = *cfg.uid
	}
	g.link = newLinkListener(g.ln, secret, uid)
	g.http = &http.Server{Handler: g.handler(localSide), ReadHeaderTimeout: link.PreambleWait, ErrorLog: quietLog()}
	go g.http.Serve(g.link)
	ok = true
	return g, nil
}

// listenLink makes the link's socket in a private directory of the gateway's. The
// listener removes the socket when it closes; the directory goes with Close.
func (g *Gateway) listenLink() error {
	dir, err := os.MkdirTemp("", link.LinkDirPrefix)
	if err != nil {
		return err
	}
	socket := filepath.Join(dir, link.LinkSocketName)
	if err := os.Chmod(dir, link.LinkDirMode); err != nil {
		os.RemoveAll(dir)
		return err
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		os.RemoveAll(dir)
		return err
	}
	if err := os.Chmod(socket, link.LinkSocketMode); err != nil {
		ln.Close()
		os.RemoveAll(dir)
		return err
	}
	g.dir, g.ln = dir, ln
	return nil
}

// socket is the link's socket, empty when the gateway made none.
func (g *Gateway) socket() string {
	if g.dir == "" {
		return ""
	}
	return filepath.Join(g.dir, link.LinkSocketName)
}

// newSecret makes the link secret: 32 bytes from the system's random source, in
// base64url without padding.
func newSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// newClient is the signed client of the server document s.
func newClient(s *Server, version string) (*server.Client, error) {
	b, _ := json.Marshal(s)
	cfg, err := server.Read("server", b)
	if err != nil {
		return nil, err
	}
	return &server.Client{Config: cfg, Key: s.AccessKey, InstanceID: s.InstanceID, InstanceName: s.InstanceName, UserAgent: accesskey.UserAgent(version)}, nil
}

// Addr is the address of the gateway's proxy, host:port: with [Config.Listen] its one
// address, as it listens, where a bound connection opens a run's proxy with the relay's
// preamble and the run key; else on loopback, where every connection opens with the
// relay's preamble and a live run's proxy secret.
func (g *Gateway) Addr() string {
	if g.svc != nil {
		return g.svc.addr()
	}
	return g.proxies.Addr()
}

// LocalLink is what a session in this process needs of the gateway: the way to its link
// in memory, which a session's client takes in place of the socket, so no other process
// can stand in for the gateway at the socket's path; the link's socket, for a session
// in another process, empty with [Config.NoLinkSocket], and its secret; the proxy's address, the gateway's own files,
// which a walled run must not mount, and the names a walled run must not pass. A
// gateway with [Config.Listen] runs no sessions of its machine: its Local has no socket
// and no proxy, and every connection to it fails.
func (g *Gateway) LocalLink() link.Local {
	if g.svc != nil {
		return link.Local{Files: g.files(), Reserved: g.reserved()}.InMemory(func(context.Context) (net.Conn, error) {
			return nil, errNoSessions
		})
	}
	return link.Local{
		Socket:   g.socket(),
		Secret:   g.secret.reveal(),
		Proxy:    g.proxies.Addr(),
		Files:    g.files(),
		Reserved: g.reserved(),
	}.InMemory(g.link.dial)
}

// errNoSessions is a connection to the local link of a gateway with an address.
var errNoSessions = errors.New("the gateway serves other machines on its address, and runs no sessions")

// String names the gateway by its proxy's address and its link's socket, or by its one
// address when it has one, never a secret.
func (g *Gateway) String() string {
	if g == nil {
		return "gateway.Gateway(nil)"
	}
	if g.svc != nil {
		return "gateway.Gateway{address " + g.svc.addr() + "}"
	}
	where := g.socket()
	if where == "" {
		where = "in memory"
	}
	return "gateway.Gateway{proxy " + g.proxies.Addr() + ", link " + where + "}"
}

// Format prints g as String does, under every verb and flag: never its secret.
func (g *Gateway) Format(f fmt.State, _ rune) { io.WriteString(f, g.String()) }

// GoString is g as %#v prints it, never its secret.
func (g *Gateway) GoString() string { return g.String() }

// LogValue is g as log/slog logs it, never its secret.
func (g *Gateway) LogValue() slog.Value { return slog.StringValue(g.String()) }

// files are the gateway's own files, each with the phrase a refused mount names it by:
// the directories of the machine's credentials' and tools' programs and the
// credentials' files, and the pattern of the tools' socket directories, in the order a
// session checked them in before the gateway was apart from it; then, Kept, the
// directories the gateway keeps: the link's directory and the pattern of every
// gateway's, the gateway's directory, and where the runs' records are, which a session
// checks last, after every file of Forager's it checked before the gateway was apart
// from it.
func (g *Gateway) files() []link.File {
	var out []link.File
	for _, c := range g.cfg.Credentials {
		if len(c.Adapter) > 0 {
			for _, d := range program.Dirs(c.Adapter[0]) {
				out = append(out, link.File{Path: d, What: "the directory of the credential " + c.Name + "'s program"})
			}
		}
		if c.File != "" {
			out = append(out, link.File{Path: c.File, What: "the file the credential " + c.Name + " is read from"})
		}
	}
	for _, t := range g.cfg.Tools {
		if len(t.Command) > 0 {
			for _, d := range program.Dirs(t.Command[0]) {
				out = append(out, link.File{Path: d, What: "the directory of the tool " + t.Name + "'s program"})
			}
		}
	}
	out = append(out,
		link.File{Path: tool.SocketDirs(), What: "where the tools' sockets are made"},
		link.File{Path: g.dir, What: "the gateway's link directory", Kept: true},
		link.File{Path: filepath.Join(os.TempDir(), link.LinkDirPrefix+"*"), What: "where the gateways' links are made", Kept: true})
	if g.cfg.Dir != "" {
		out = append(out, link.File{Path: g.cfg.Dir, What: "the gateway's directory", Kept: true})
	}
	if g.cfg.RunDir != nil {
		// The directory the record directories are made in, named by the record
		// directory of a run id no run has.
		const none = "00000000-0000-0000-0000-000000000000"
		if dir := g.cfg.RunDir(none); filepath.Base(dir) == none {
			out = append(out, link.File{Path: filepath.Dir(dir), What: "where the run directories are kept", Kept: true})
		} else if dir != "" {
			out = append(out, link.File{Path: dir, What: "where the run directories are kept", Kept: true})
		}
	}
	var unique []link.File
	for _, f := range out {
		if f.Path != "" && !slices.ContainsFunc(unique, func(u link.File) bool { return u.Path == f.Path }) {
			unique = append(unique, f)
		}
	}
	return unique
}

// reserved are the variables the machine's credentials are read from, of Forager's own
// environment.
func (g *Gateway) reserved() []string {
	var out []string
	for _, c := range g.cfg.Credentials {
		if c.Env != "" && !slices.Contains(out, c.Env) {
			out = append(out, c.Env)
		}
	}
	return out
}

// Close stops taking runs and ends the gateway. It is called once the session is over,
// so it waits for no session: a run still live ends at once, without an exit, which a
// resend of its record completes as gateway_lost, and lets go of its secret, proxy,
// tools and credentials. Each run's events are flushed toward the server within
// [stream.CloseWait] (or the Config's own bound), whatever ctx allows, whose values
// alone pass on; then the link's directory is removed and the proxy stops. The
// Delivery is what the runs came to: their undelivered events, and who closed a run
// that ended at the gateway, and how it ended. Close again waits for the first.
func (g *Gateway) Close(ctx context.Context) (Delivery, error) {
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		<-g.closed
		return g.delivery, g.closeErr
	}
	g.closing = true
	g.mu.Unlock()
	g.opens.Wait()
	g.mu.Lock()
	runs := make([]*linkRun, 0, len(g.runs))
	for _, lr := range g.runs {
		runs = append(runs, lr)
	}
	g.mu.Unlock()
	for _, lr := range runs {
		lr.end(ending{code: accesskey.CodeRunClosed, from: accesskey.FromGateway})
	}
	var errs []error
	for _, lr := range runs {
		<-lr.done
		if lr.err != nil {
			errs = append(errs, lr.err)
		}
		g.delivery.Undelivered += lr.result.Undelivered
		g.closedRun(lr)
	}
	g.mu.Lock()
	errs = append(errs, g.spentErrs...)
	g.mu.Unlock()
	shut, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	if g.svc != nil {
		errs = append(errs, g.svc.close(shut))
	} else {
		if err := g.http.Shutdown(shut); err != nil {
			g.http.Close()
		}
		g.link.Close()
		errs = append(errs, g.proxies.Close())
	}
	cancel()
	if g.dir != "" {
		errs = append(errs, os.RemoveAll(g.dir))
	}
	g.cancel()
	g.closeErr = errors.Join(errs...)
	close(g.closed)
	return g.delivery, g.closeErr
}

// Wait returns once Close is done.
func (g *Gateway) Wait() { <-g.closed }
