package linktest

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The paths the fake gateway lists in its discovery.
const (
	EventsPath = "/v1/events"
	RunPath    = "/v1/run-configuration"
)

// ProxySecret is the proxy secret a fake gateway's default run answer gives on the
// local link.
const ProxySecret = "fake-proxy-secret-0123456789abcdef"

// Reply is one answer of the fake gateway: its status, its body, marshalled as JSON
// unless it is a []byte, none when nil, and headers of its own beside the digest; and,
// on a separate gateway, how it is signed.
type Reply struct {
	Status int
	Body   any
	Header http.Header
	// Signing is how a separate gateway signs this answer, [SignedOwn] by default, which
	// [Fake.AnswerUnderUnnamedKey] changes for every answer.
	Signing Signing
}

// Signing is how a fake separate gateway signs one answer.
type Signing int

// The ways a fake separate gateway signs an answer.
const (
	// SignedOwn is the fake's way for every answer: its own key, unless
	// [Fake.AnswerUnderUnnamedKey] says otherwise.
	SignedOwn Signing = iota
	// SignedUnnamed is a signature under a key no run key of the fake's names.
	SignedUnnamed
	// Unsigned is no signature.
	Unsigned
)

// Fake is a scriptable gateway on a local link, or a separate one, [StartRemoteFake]:
// it answers discovery, run requests, reloads and batches as
// contracts/forager/v1/README.md §The gateway's link says, and records what it
// received. The local link's proxy is a listener on loopback that records the preamble
// every connection opens with, and answers every request on it 200 "ok". Every answer
// carries the run-configuration digest set with SetRunDigest, and the On functions
// replace an answer; each may be set before the session runs.
type Fake struct {
	*Gateway

	proxy net.Listener

	mu sync.Mutex
	// interval is the heartbeat interval the discovery announces, in seconds.
	interval  int
	proxyAddr string
	runDigest string
	digests   []string
	onRun     func(server.LinkRunRequest) Reply
	onReload  func(runID string) Reply
	onBatch   func([]map[string]any) Reply
	// origin is a separate gateway's, https and its one address; empty on the local
	// link. prefix begins every path of its link, /qory-link; empty on the local link.
	origin    string
	prefix    string
	remote    *remote
	requests  []server.LinkRunRequest
	raw       [][]byte
	batches   [][]map[string]any
	reloads   []string
	runIDs    []string
	bearers   []string
	preambles []string
	proxied   []string
}

// StartFake starts a fake gateway with a heartbeat interval of one second, until the
// test ends.
func StartFake(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{interval: 1}
	ln, err := net.Listen("tcp", link.Loopback)
	if err != nil {
		t.Fatal(err)
	}
	f.proxy = ln
	t.Cleanup(func() { ln.Close() })
	go f.serveProxy()
	f.Gateway = Start(t, http.HandlerFunc(f.serve))
	return f
}

// Local is the link as a session receives it, with the gateway's proxy.
func (f *Fake) Local() link.Local {
	l := f.Gateway.Local()
	l.Proxy = f.ProxyAddr()
	return l
}

// ProxyAddr is the fake proxy's address, which the discovery names.
func (f *Fake) ProxyAddr() string {
	if f.proxy == nil {
		return ""
	}
	return f.proxy.Addr().String()
}

// SetDiscoveryProxy sets the proxy address the discovery names, in place of the fake
// proxy's own.
func (f *Fake) SetDiscoveryProxy(addr string) {
	f.mu.Lock()
	f.proxyAddr = addr
	f.mu.Unlock()
}

// SetInterval sets the heartbeat interval the discovery announces, in seconds.
func (f *Fake) SetInterval(seconds int) {
	f.mu.Lock()
	f.interval = seconds
	f.mu.Unlock()
}

// BatchDigests are the run-configuration digests the batches received carried, one per
// batch, empty for none.
func (f *Fake) BatchDigests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.digests)
}

// SetRunDigest sets the run-configuration digest every answer carries from now on.
func (f *Fake) SetRunDigest(d string) {
	f.mu.Lock()
	f.runDigest = d
	f.mu.Unlock()
}

// OnRun replaces the answer to a run request, [Fake.RunAnswer] by default.
func (f *Fake) OnRun(h func(server.LinkRunRequest) Reply) { f.mu.Lock(); f.onRun = h; f.mu.Unlock() }

// OnReload replaces the answer to a reload, a reload answer of no policy by default.
func (f *Fake) OnReload(h func(runID string) Reply) { f.mu.Lock(); f.onReload = h; f.mu.Unlock() }

// OnBatch replaces the answer to a batch, a 200 by default.
func (f *Fake) OnBatch(h func([]map[string]any) Reply) { f.mu.Lock(); f.onBatch = h; f.mu.Unlock() }

// Requests are the run requests received, decoded.
func (f *Fake) Requests() []server.LinkRunRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// RawRequests are the bodies of the run requests received, as they came.
func (f *Fake) RawRequests() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.raw)
}

// Batches are the batches received, each its events decoded.
func (f *Fake) Batches() [][]map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.batches)
}

// Events are the events of every batch received, in order.
func (f *Fake) Events() []map[string]any {
	var out []map[string]any
	for _, b := range f.Batches() {
		out = append(out, b...)
	}
	return out
}

// Reloads are the run ids of the reloads received.
func (f *Fake) Reloads() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reloads)
}

// RunIDs are the X-Qory-Run-Id values the batches received carried, in order, joined
// by a comma when one carried several, empty for none.
func (f *Fake) RunIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.runIDs)
}

// Bearers are the values of Authorization every request of a separate gateway's link
// carried, in order, joined by a comma when one carried several, empty for none.
func (f *Fake) Bearers() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.bearers)
}

// Preambles are the first lines of the connections the fake proxy received, without
// their newline.
func (f *Fake) Preambles() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.preambles)
}

// Proxied are the request lines the fake proxy answered.
func (f *Fake) Proxied() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.proxied)
}

// RunAnswer is the fake's default answer to a run request on the local link: the
// request's run id and labels, no policy, with the members of policy_applied of none,
// the proxy secret ProxySecret, and behind a wall the image the request's default names,
// none when it names none.
func RunAnswer(req server.LinkRunRequest) map[string]any {
	labels := req.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	a := RemoteRunAnswer(req)
	a["labels"], a["proxy_secret"] = labels, ProxySecret
	return a
}

// RemoteRunAnswer is the fake's default answer to a run request behind a separate
// gateway: [RunAnswer] without the labels, which are the starter's registration's, and
// without a proxy secret, since the run key opens the proxy's connections.
func RemoteRunAnswer(req server.LinkRunRequest) map[string]any {
	a := map[string]any{
		"version": 1, "run_id": req.RunID,
		"applied": map[string]any{"mode": "observe", "allow": []string{}, "deny": []string{}, "source": "none"},
	}
	if req.Wall && req.Images != nil && req.Images.Default != "" {
		img := map[string]any{"ref": req.Images.Default}
		for _, d := range req.Images.Definitions {
			if d.Name == req.Images.Default {
				img = map[string]any{"name": d.Name, "ref": d.Ref}
				if d.Runtime != "" {
					img["runtime"] = d.Runtime
				}
				if d.Docker {
					img["docker"] = true
				}
			}
		}
		a["image"] = img
	}
	return a
}

// Refusal is the body of a coded refusal on the link.
func Refusal(code, from string, names ...string) map[string]any {
	r := map[string]any{"error": code, "from": from}
	if len(names) > 0 {
		r["names"] = names
	}
	return r
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	discovery, runPath, eventsPath := server.WellKnown, f.prefix+RunPath, f.prefix+EventsPath
	var reply Reply
	if f.remote != nil {
		discovery = link.RemoteDiscoveryPath
		f.bearers = append(f.bearers, strings.Join(r.Header.Values("Authorization"), ","))
	}
	switch {
	case f.remote != nil && !f.remote.bearer(r.Header.Values("Authorization")):
		// As the real gateway refuses a bearer value that is no run key it accepts.
		reply = Reply{Status: 400, Body: map[string]any{"error": "run_key_invalid", "from": "gateway", "message": "the gateway refused the run: run_key_invalid"}}
	case r.Method == http.MethodGet && r.URL.Path == discovery:
		origin, proxy := server.LocalOrigin, f.ProxyAddr()
		if f.origin != "" {
			// A separate gateway lists its own origin, and names its one address as its
			// proxy.
			origin, proxy = f.origin, r.Host
		}
		if f.proxyAddr != "" {
			proxy = f.proxyAddr
		}
		reply = Reply{Status: 200, Body: map[string]any{
			"version": 1,
			"events":  map[string]any{"url": origin + eventsPath, "types": []string{"*"}, "interval_seconds": f.interval},
			"run":     map[string]any{"url": origin + runPath},
			"proxy":   map[string]any{"address": proxy},
		}}
	case r.Method == http.MethodPost && r.URL.Path == runPath:
		var req server.LinkRunRequest
		json.Unmarshal(body, &req)
		f.requests = append(f.requests, req)
		f.raw = append(f.raw, body)
		switch h := f.onRun; {
		case h != nil:
			f.mu.Unlock()
			reply = h(req)
			f.mu.Lock()
		case f.remote != nil:
			reply = Reply{Status: 200, Body: RemoteRunAnswer(req)}
		default:
			reply = Reply{Status: 200, Body: RunAnswer(req)}
		}
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, runPath+"/"):
		id := strings.TrimPrefix(r.URL.Path, runPath+"/")
		f.reloads = append(f.reloads, id)
		if h := f.onReload; h != nil {
			f.mu.Unlock()
			reply = h(id)
			f.mu.Lock()
		} else {
			reply = Reply{Status: 200, Body: map[string]any{"version": 1, "applied": map[string]any{"mode": "observe", "allow": []string{}, "deny": []string{}, "source": "none"}}}
		}
	case r.Method == http.MethodPost && r.URL.Path == eventsPath:
		var evs []map[string]any
		json.Unmarshal(body, &evs)
		f.batches = append(f.batches, evs)
		f.digests = append(f.digests, r.Header.Get(server.HeaderRunConfiguration))
		f.runIDs = append(f.runIDs, strings.Join(r.Header.Values(server.HeaderRunID), ","))
		if h := f.onBatch; h != nil {
			f.mu.Unlock()
			reply = h(evs)
			f.mu.Lock()
		} else {
			reply = Reply{Status: 200}
		}
	default:
		reply = Reply{Status: 404}
	}
	// A handler may have set the digest while it answered.
	digest := f.runDigest
	rm := f.remote
	f.mu.Unlock()
	for k, v := range reply.Header {
		w.Header()[k] = v
	}
	if digest != "" && reply.Status != http.StatusGone {
		w.Header().Set(server.HeaderRunConfiguration, digest)
	}
	var out []byte
	switch b := reply.Body.(type) {
	case nil:
	case []byte:
		out = b
	default:
		out, _ = json.Marshal(b)
	}
	if out != nil {
		w.Header().Set("Content-Type", "application/json")
	}
	if rm != nil {
		rm.sign(w.Header(), r, body, reply.Status, out, reply.Signing)
	}
	w.WriteHeader(reply.Status)
	w.Write(out)
}

// serveProxy answers every connection to the fake proxy: it records the first line,
// then answers each HTTP request it reads with 200 "ok".
func (f *Fake) serveProxy() {
	for {
		c, err := f.proxy.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			r := bufio.NewReader(c)
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			f.mu.Lock()
			f.preambles = append(f.preambles, strings.TrimSuffix(line, "\n"))
			f.mu.Unlock()
			if !strings.HasPrefix(line, link.RelayPreamble+" ") {
				// No preamble: the line is the request's own.
				f.mu.Lock()
				f.proxied = append(f.proxied, strings.TrimSpace(line))
				f.mu.Unlock()
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				return
			}
			f.answerProxied(c, r)
		}()
	}
}

// answerProxied answers each HTTP request it reads from r, after a connection's
// preamble, with 200 "ok" on w, and records its request line; after a request with
// Connection: close it answers no other, as a proxy does.
func (f *Fake) answerProxied(w io.Writer, r *bufio.Reader) {
	for {
		req, err := http.ReadRequest(r)
		if err != nil {
			return
		}
		io.Copy(io.Discard, req.Body)
		f.mu.Lock()
		f.proxied = append(f.proxied, req.Method+" "+req.RequestURI)
		f.mu.Unlock()
		if req.Close {
			io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			return
		}
		if _, err := io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
			return
		}
	}
}
