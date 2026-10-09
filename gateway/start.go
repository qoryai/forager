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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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

// Gateway is a gateway serving sessions on its local link: it opens each run, decides
// its connections by its policy through the shared proxy, numbers its events and sends
// them to the server.
type Gateway struct {
	cfg      Config
	report   func(string)
	interval int
	quiet    time.Duration

	// client, conf and confDigest are the server's, nil without one.
	client     *server.Client
	conf       *server.Configuration
	confDigest string

	// base is the context of everything a run starts, cancelled when Close is done.
	base   context.Context
	cancel context.CancelFunc

	dir     string
	secret  string
	ln      net.Listener
	link    *linkListener
	http    *http.Server
	proxies *proxy.Listener
	stream  *stream.Stream
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

	closed   chan struct{}
	delivery Delivery
	closeErr error
}

// Start starts a gateway: with a server, it fetches the server's configuration
// document first and calls [Config.Discovered], and a refusal is an
// [*accesskey.Refusal]; then it makes the local link, a socket in a private directory
// of its own, and the shared proxy listener on loopback, and serves sessions until
// Close. It sends nothing more before a session opens a run.
func Start(ctx context.Context, cfg Config) (*Gateway, error) {
	if cfg.Listen != "" || cfg.TLS != nil {
		return nil, errors.New("a separate gateway, with an address and a certificate of its own, is not served yet; the gateway serves its local link alone")
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
	g := &Gateway{cfg: cfg, report: report, interval: int(cfg.Heartbeat / time.Second), used: map[string]bool{}, runs: map[string]*linkRun{}, closed: make(chan struct{})}
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
		g.client, g.conf, g.confDigest = client, conf, digest
	}
	g.base, g.cancel = context.WithCancel(context.WithoutCancel(ctx))
	ok := false
	defer func() {
		if !ok {
			g.cancel()
		}
	}()
	secret, err := newSecret()
	if err != nil {
		return nil, err
	}
	g.secret = secret
	if g.dir, err = os.MkdirTemp("", link.LinkDirPrefix); err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			os.RemoveAll(g.dir)
		}
	}()
	if err := os.Chmod(g.dir, link.LinkDirMode); err != nil {
		return nil, err
	}
	socket := filepath.Join(g.dir, link.LinkSocketName)
	if g.ln, err = net.Listen("unix", socket); err != nil {
		return nil, err
	}
	// The listener removes the socket when it closes; the directory goes with Close.
	if err := os.Chmod(socket, link.LinkSocketMode); err != nil {
		g.ln.Close()
		return nil, err
	}
	var refused sync.Once
	g.proxies, err = proxy.NewListener("", func(why string) {
		// Told once, as today's session tells it for its one run: a peer that keeps
		// trying says nothing new.
		refused.Do(func() { report(why) })
	})
	if err != nil {
		g.ln.Close()
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
	g.http = &http.Server{Handler: g.handler(), ReadHeaderTimeout: link.PreambleWait, ErrorLog: quietLog()}
	go g.http.Serve(g.link)
	ok = true
	return g, nil
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

// Addr is the address of the gateway's proxy, host:port on loopback: every connection
// opens with the relay's preamble and a live run's proxy secret.
func (g *Gateway) Addr() string { return g.proxies.Addr() }

// LocalLink is what a session on this machine needs of the gateway: the link's socket
// and secret, the proxy's address, the gateway's own files, which a walled run must not
// mount, and the variables the gateway sets for a run, which the session must not set.
func (g *Gateway) LocalLink() link.Local {
	return link.Local{
		Socket:   filepath.Join(g.dir, link.LinkSocketName),
		Secret:   g.secret,
		Proxy:    g.proxies.Addr(),
		Files:    g.files(),
		Reserved: g.reserved(),
	}
}

// files are the gateway's own files: the link's directory and the pattern of every
// gateway's, the files and the program directories of the machine's credentials and
// tools, the pattern of the tools' socket directories, and where the runs' records are.
func (g *Gateway) files() []string {
	out := []string{g.dir, filepath.Join(os.TempDir(), link.LinkDirPrefix+"*")}
	for _, c := range g.cfg.Credentials {
		if len(c.Adapter) > 0 {
			out = append(out, program.Dirs(c.Adapter[0])...)
		}
		if c.File != "" {
			out = append(out, c.File)
		}
	}
	for _, t := range g.cfg.Tools {
		if len(t.Command) > 0 {
			out = append(out, program.Dirs(t.Command[0])...)
		}
	}
	out = append(out, tool.SocketDirs())
	if g.cfg.Dir != "" {
		out = append(out, g.cfg.Dir)
	}
	if g.cfg.RunDir != nil {
		// The directory the record directories are made in, named by the record
		// directory of a run id no run has.
		const none = "00000000-0000-0000-0000-000000000000"
		if dir := g.cfg.RunDir(none); filepath.Base(dir) == none {
			out = append(out, filepath.Dir(dir))
		} else if dir != "" {
			out = append(out, dir)
		}
	}
	var unique []string
	for _, p := range out {
		if p != "" && !slices.Contains(unique, p) {
			unique = append(unique, p)
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
// that ended at the gateway. Close again waits for the first.
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
		if lr.closed && !g.delivery.RunClosed {
			g.delivery.RunClosed, g.delivery.ClosedBy, g.delivery.Reason = true, lr.endFrom, lr.endCode
		}
	}
	shut, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	if err := g.http.Shutdown(shut); err != nil {
		g.http.Close()
	}
	cancel()
	g.link.Close()
	errs = append(errs, g.proxies.Close(), os.RemoveAll(g.dir))
	g.cancel()
	g.closeErr = errors.Join(errs...)
	close(g.closed)
	return g.delivery, g.closeErr
}

// Wait returns once Close is done.
func (g *Gateway) Wait() { <-g.closed }
