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

// ProxySecret is the proxy secret a fake gateway's default run answer gives.
const ProxySecret = "fake-proxy-secret-0123456789abcdef"

// RunSecret is the run secret a fake gateway's default run answer gives.
const RunSecret = "fake-run-secret-0123456789abcdefghij"

// Reply is one answer of the fake gateway: its status, its body, marshalled as JSON
// unless it is a []byte, none when nil, and headers of its own beside the digest.
type Reply struct {
	Status int
	Body   any
	Header http.Header
}

// Fake is a scriptable gateway on a local link: it answers discovery, run requests,
// reloads and batches as contracts/forager/v1/README.md §The gateway's link says, and
// records what it received. Its proxy is a listener on loopback that records the
// preamble every connection opens with, and answers every request on it 200 "ok".
// Every answer carries the run-configuration digest set with SetRunDigest, and the
// On functions replace an answer; each may be set before the session runs.
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
	requests  []server.LinkRunRequest
	raw       [][]byte
	batches   [][]map[string]any
	reloads   []string
	secrets   []string
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
	f.Gateway = Start(t, "fake-link-secret-0123456789", http.HandlerFunc(f.serve))
	return f
}

// Local is the link as a session receives it, with the gateway's proxy.
func (f *Fake) Local() link.Local {
	l := f.Gateway.Local()
	l.Proxy = f.ProxyAddr()
	return l
}

// ProxyAddr is the fake proxy's address, which the discovery names.
func (f *Fake) ProxyAddr() string { return f.proxy.Addr().String() }

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

// RunSecrets are the X-Qory-Run-Secret values the reloads and batches received carried,
// in order, joined by a comma when one carried several, empty for none.
func (f *Fake) RunSecrets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.secrets)
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

// RunAnswer is the fake's default answer to a run request: the request's run id and
// labels, no policy, with the members of policy_applied of none, the proxy secret
// ProxySecret, the run secret RunSecret, and behind a wall the image the request's
// default names, none when it names none.
func RunAnswer(req server.LinkRunRequest) map[string]any {
	labels := req.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	a := map[string]any{
		"version": 1, "run_id": req.RunID, "credential": "none", "labels": labels, "proxy_secret": ProxySecret, "run_secret": RunSecret,
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
	var reply Reply
	switch {
	case r.Method == http.MethodGet && r.URL.Path == server.WellKnown:
		proxy := f.ProxyAddr()
		if f.proxyAddr != "" {
			proxy = f.proxyAddr
		}
		reply = Reply{Status: 200, Body: map[string]any{
			"version": 1,
			"events":  map[string]any{"url": server.LocalOrigin + EventsPath, "types": []string{"*"}, "interval_seconds": f.interval},
			"run":     map[string]any{"url": server.LocalOrigin + RunPath},
			"proxy":   map[string]any{"address": proxy},
		}}
	case r.Method == http.MethodPost && r.URL.Path == RunPath:
		var req server.LinkRunRequest
		json.Unmarshal(body, &req)
		f.requests = append(f.requests, req)
		f.raw = append(f.raw, body)
		if h := f.onRun; h != nil {
			f.mu.Unlock()
			reply = h(req)
			f.mu.Lock()
		} else {
			reply = Reply{Status: 200, Body: RunAnswer(req)}
		}
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, RunPath+"/"):
		id := strings.TrimPrefix(r.URL.Path, RunPath+"/")
		f.reloads = append(f.reloads, id)
		f.secrets = append(f.secrets, strings.Join(r.Header.Values(server.HeaderRunSecret), ","))
		if h := f.onReload; h != nil {
			f.mu.Unlock()
			reply = h(id)
			f.mu.Lock()
		} else {
			reply = Reply{Status: 200, Body: map[string]any{"version": 1, "applied": map[string]any{"mode": "observe", "allow": []string{}, "deny": []string{}, "source": "none"}}}
		}
	case r.Method == http.MethodPost && r.URL.Path == EventsPath:
		var evs []map[string]any
		json.Unmarshal(body, &evs)
		f.batches = append(f.batches, evs)
		f.digests = append(f.digests, r.Header.Get(server.HeaderRunConfiguration))
		f.secrets = append(f.secrets, strings.Join(r.Header.Values(server.HeaderRunSecret), ","))
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
			for {
				req, err := http.ReadRequest(r)
				if err != nil {
					return
				}
				io.Copy(io.Discard, req.Body)
				f.mu.Lock()
				f.proxied = append(f.proxied, req.Method+" "+req.RequestURI)
				f.mu.Unlock()
				if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
					return
				}
			}
		}()
	}
}
