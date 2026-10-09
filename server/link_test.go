package server_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// The link's secret and a run of the tests.
const (
	linkSecret  = "link-secret-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	proxySecret = "proxy-secret-BBBBBBBBBBBBBBBBBBBBBBBB"
	runSecret   = "run-secret-CCCCCCCCCCCCCCCCCCCCCCCCCC"
	runID       = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
	userAgent   = "qory-forager/test"
	runDigest   = "sha256=" + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	confDigest  = "sha256=" + "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
	policyHex   = "0083089af881510432ef44e416ccef8c5e84f33678e1de98411520b97f277c78"
)

// discovery is the local link's discovery the fake gateway answers with.
const discovery = `{"version":1,"events":{"url":"http://localhost/v1/events","types":["*"],"interval_seconds":30},"run":{"url":"http://localhost/v1/run-configuration"},"proxy":{"address":"127.0.0.1:41000"},"later":{"a":1}}`

// runAnswer is a run answer with the members the link adds to the schema's.
var runAnswer = `{"version":1,"run_id":"` + runID + `","credential":"none","policy":{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}},"digest":"` + policyHex + `","variables":{"NODE_ENV":{"value":"test"}},"proxy_secret":"` + proxySecret + `","run_secret":"` + runSecret + `","placeholders":["GIT_TOKEN"],"reserved":["EXAMPLE_SOURCE_KEY","EXAMPLE_OTHER_KEY"],"image":{"name":"base","ref":"registry.example/base@sha256:00","runtime":"sysbox-runc"},"labels":{"forge":"example-forge","repository":"example-namespace/project"},"details":{"requester":"requester"},"applied":{"mode":"enforce","allow":["api.example"],"source":"config","digest":"` + policyHex + `"}}`

// reloadAnswer is a reload answer with the members the link adds to the schema's.
const reloadAnswer = `{"version":1,"policy":{"version":1,"egress":{"mode":"observe"}},"digest":"` + policyHex + `","variables":{"NODE_ENV":{"value":"prod"}},"placeholders":[],"reserved":["EXAMPLE_SOURCE_KEY"],"applied":{"mode":"observe","allow":[],"source":"config","digest":"` + policyHex + `"}}`

// newLink is the client of the fake gateway's link, with the digests it hands on.
func newLink(t *testing.T, g *linktest.Gateway) (*server.Link, *[]server.Digests) {
	t.Helper()
	var mu sync.Mutex
	got := &[]server.Digests{}
	k, err := server.NewLocalLink(g.Local(), userAgent, func(d server.Digests) {
		mu.Lock()
		defer mu.Unlock()
		*got = append(*got, d)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k, got
}

// answer writes a status and a body with the digests.
func answer(w http.ResponseWriter, status int, body string) {
	w.Header().Set(server.HeaderConfiguration, confDigest)
	w.Header().Set(server.HeaderRunConfiguration, runDigest)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

// TestTheLinkSpeaksTheContractOverTheSocket pins one run's requests on the local
// link: each connection opens with the preamble, every request carries User-Agent and
// the contract revision and none of the signed requests' headers, the run request
// carries the run's passes and images, a batch its content type and delivery id, and
// every answer's digests reach the caller.
func TestTheLinkSpeaksTheContractOverTheSocket(t *testing.T) {
	var mu sync.Mutex
	var problems []string
	var request server.LinkRunRequest
	note := func(f string, a ...any) { mu.Lock(); problems = append(problems, fmt.Sprintf(f, a...)); mu.Unlock() }
	g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "localhost" || r.Header.Get("User-Agent") != userAgent || r.Header.Get(server.HeaderContractVersion) != strconv.Itoa(server.Revision) {
			note("%s %s: host %q, headers %v", r.Method, r.URL, r.Host, r.Header)
		}
		for _, h := range []string{server.HeaderAccessKeyID, server.HeaderInstanceID, server.HeaderInstanceName, server.HeaderSignature, server.HeaderTimestamp, "Authorization"} {
			if r.Header.Get(h) != "" {
				note("%s %s carries %s", r.Method, r.URL, h)
			}
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == server.WellKnown:
			answer(w, 200, discovery)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/run-configuration":
			if r.Header.Get("Content-Type") != server.LinkContentType {
				note("run request content type %q", r.Header.Get("Content-Type"))
			}
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			err := json.Unmarshal(b, &request)
			mu.Unlock()
			if err != nil {
				note("run request %s: %v", b, err)
			}
			answer(w, 200, runAnswer)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/run-configuration/"+runID && r.URL.RawQuery == "":
			answer(w, 200, reloadAnswer)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/events":
			if r.Header.Get("Content-Type") != server.ContentType || r.Header.Get(server.HeaderDelivery) != "d1" || r.Header.Get(server.HeaderRunConfiguration) != runDigest {
				note("batch headers %v", r.Header)
			}
			answer(w, 202, "")
		default:
			note("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	k, digests := newLink(t, g)
	ctx := context.Background()
	d, err := k.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d.Events.URL != "http://localhost/v1/events" || d.Events.IntervalSeconds != 30 || d.Run.URL != "http://localhost/v1/run-configuration" || d.Proxy == nil || d.Proxy.Address != "127.0.0.1:41000" {
		t.Errorf("discovery %+v", d)
	}
	req := server.LinkRunRequest{RunID: runID, Wall: true, Labels: map[string]string{"forge": "example-forge"}, About: &server.About{Title: "Fix the failing build"},
		Passes: []string{"NODE_ENV", "HOME"}, Images: &server.LinkImages{Default: "base", Definitions: []server.LinkImage{{Name: "base", Ref: "registry.example/base@sha256:00", Runtime: "sysbox-runc"}}}}
	a, err := k.OpenRun(ctx, d.Run.URL, req)
	if err != nil {
		t.Fatal(err)
	}
	if a.RunID != runID || a.ProxySecret != proxySecret || a.Digest != policyHex || a.Values()["NODE_ENV"] != "test" || len(a.Placeholders) != 1 || len(a.Reserved) != 2 || a.Image == nil || a.Image.Ref != "registry.example/base@sha256:00" || !strings.Contains(string(a.Policy), "api.example") ||
		a.Labels["repository"] != "example-namespace/project" || string(a.Details) != `{"requester":"requester"}` {
		t.Errorf("run answer %+v", a)
	}
	mu.Lock()
	if request.Version != 1 || request.RunID != runID || !request.Wall || request.About == nil || len(request.Passes) != 2 || request.Images == nil || request.Images.Default != "base" || len(request.Images.Definitions) != 1 || request.Narrowing != nil {
		t.Errorf("the gateway read the run request %+v", request)
	}
	mu.Unlock()
	re, err := k.Reload(ctx, d.Run.URL, runID)
	if err != nil {
		t.Fatal(err)
	}
	if re.Values()["NODE_ENV"] != "prod" || re.Digest != policyHex || len(re.Reserved) != 1 || re.Placeholders == nil {
		t.Errorf("reload answer %+v", re)
	}
	del, err := k.Deliver(ctx, d.Events.URL, "d1", []byte(`[]`), runDigest)
	if err != nil {
		t.Fatal(err)
	}
	if !del.Accepted() || del.Signed || !del.Link || del.Digests != (server.Digests{Configuration: confDigest, RunConfiguration: runDigest}) {
		t.Errorf("delivery %+v", del)
	}
	if len(*digests) != 3 {
		t.Errorf("%d digests handed on, want 3: %v", len(*digests), *digests)
	}
	for _, dg := range *digests {
		if dg.Configuration != confDigest || dg.RunConfiguration != runDigest {
			t.Errorf("digests %+v", dg)
		}
	}
	if g.Rejected.Load() != 0 || g.Accepted.Load() == 0 {
		t.Errorf("%d connections rejected, %d accepted", g.Rejected.Load(), g.Accepted.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range problems {
		t.Error(p)
	}
}

// TestTheLinkChecksItsPeerBeforeItsSecret pins that the session writes nothing to a
// socket whose peer is another user: the error says so, and the peer receives no byte.
func TestTheLinkChecksItsPeerBeforeItsSecret(t *testing.T) {
	socket := linktest.SocketPath(t)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			received <- -1
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c)
		received <- len(b)
	}()
	k, err := server.NewLocalLink(link.Local{Socket: socket, Secret: linkSecret}, userAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.SetPeerUID(k, os.Getuid()+1)
	_, err = k.Discover(context.Background())
	if !errors.Is(err, server.ErrLinkPeer) {
		t.Fatalf("a peer of another user: %v", err)
	}
	if n := <-received; n != 0 {
		t.Errorf("the peer received %d bytes", n)
	}
	if strings.Contains(err.Error(), linkSecret) {
		t.Errorf("the error contains the secret: %v", err)
	}
}

// TestAConnectionWithoutTheSecretIsClosed pins the fake gateway's side, as the gateway
// reads the link: a session with another secret is closed unanswered, and no request
// reaches the handler.
func TestAConnectionWithoutTheSecretIsClosed(t *testing.T) {
	var hits atomic.Int32
	g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); answer(w, 200, discovery) }))
	other := g.Local()
	other.Secret = "another-secret-CCCCCCCCCCCCCCCCCCCCCCCC"
	k, err := server.NewLocalLink(other, userAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if _, err := k.Discover(context.Background()); err == nil {
		t.Fatal("a session with another secret was answered")
	} else if strings.Contains(err.Error(), other.Secret) || strings.Contains(err.Error(), linkSecret) {
		t.Errorf("the error contains a secret: %v", err)
	}
	if hits.Load() != 0 || g.Rejected.Load() == 0 || g.Accepted.Load() != 0 {
		t.Errorf("%d requests answered, %d rejected, %d accepted", hits.Load(), g.Rejected.Load(), g.Accepted.Load())
	}
	right, _ := newLink(t, g)
	if _, err := right.Discover(context.Background()); err != nil || hits.Load() != 1 {
		t.Errorf("the right secret: %v, %d requests", err, hits.Load())
	}
}

// TestTheLinkFollowsNoRedirect pins that a 3xx on the link is a status like any other:
// nothing is requested where it points.
func TestTheLinkFollowsNoRedirect(t *testing.T) {
	var elsewhere atomic.Int32
	g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			elsewhere.Add(1)
			answer(w, 200, discovery)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	k, _ := newLink(t, g)
	_, err := k.Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Errorf("a redirect: %v", err)
	}
	if _, err := k.OpenRun(context.Background(), "http://localhost/v1/run-configuration", server.LinkRunRequest{RunID: runID}); err == nil || !strings.Contains(err.Error(), "status 307") {
		t.Errorf("a redirect of the run request: %v", err)
	}
	if elsewhere.Load() != 0 {
		t.Errorf("the redirect was followed %d times", elsewhere.Load())
	}
}

// TestADiscoveryOffTheLinkIsRefused pins that every URL of the local link's discovery
// is http://localhost and a path: another host, scheme, a port, user information, a
// query or no path is refused, as is a proxy address that is not host:port, and a
// discovery the schema refuses.
func TestADiscoveryOffTheLinkIsRefused(t *testing.T) {
	doc := func(events, run, proxy string) string {
		return `{"version":1,"events":{"url":"` + events + `","types":["*"],"interval_seconds":30},"run":{"url":"` + run + `"}` + proxy + `}`
	}
	ok := "http://localhost/v1/x"
	for name, body := range map[string]string{
		"loopback by address":   doc("http://127.0.0.1/v1/events", ok, ""),
		"https":                 doc(ok, "https://localhost/v1/run", ""),
		"a port":                doc("http://localhost:8080/v1/events", ok, ""),
		"user information":      doc(ok, "http://user:pw@localhost/v1/run", ""),
		"a query":               doc("http://localhost/v1/events?x=1", ok, ""),
		"no path":               doc("http://localhost", ok, ""),
		"another host":          doc(ok, "https://gateway.example/v1/run", ""),
		"a proxy with no port":  doc(ok, ok, `,"proxy":{"address":"127.0.0.1"}`),
		"no heartbeat interval": `{"version":1,"events":{"url":"http://localhost/e","types":["*"]},"run":{"url":"http://localhost/r"}}`,
		"a node":                `{"version":1,"node_id":"nd_x","events":{"url":"http://localhost/e","types":["*"],"interval_seconds":30},"run":{"url":"http://localhost/r"}}`,
	} {
		g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w, 200, body) }))
		k, _ := newLink(t, g)
		_, err := k.Discover(context.Background())
		var de *server.DocumentError
		if !errors.As(err, &de) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), "pw@") {
			t.Errorf("%s: the error quotes the URL: %v", name, err)
		}
	}
	k, _ := newLink(t, linktest.Start(t, linkSecret, http.NotFoundHandler()))
	for _, u := range []string{"https://gateway.example/v1/run", "http://127.0.0.1/v1/run"} {
		if _, err := k.OpenRun(context.Background(), u, server.LinkRunRequest{RunID: runID}); err == nil {
			t.Errorf("a run request to %s was sent", u)
		}
		if _, err := k.Reload(context.Background(), u, runID); err == nil {
			t.Errorf("a reload of %s was sent", u)
		}
		if _, err := k.Deliver(context.Background(), u, "d", []byte("[]"), ""); err == nil {
			t.Errorf("a batch to %s was sent", u)
		}
	}
}

// TestTheLinksRefusalsSayWhoRefused pins the coded refusals on the link: the code, the
// status and the names, From apiary when the body says so and the gateway otherwise,
// and a status with no code an error that names it.
func TestTheLinksRefusalsSayWhoRefused(t *testing.T) {
	for _, c := range []struct {
		status           int
		body, code, from string
		names            []string
	}{
		{409, `{"error":"run_id_used"}`, "run_id_used", accesskey.FromGateway, nil},
		{400, `{"error":"invalid_request","names":["narrowing"],"from":"gateway"}`, "invalid_request", accesskey.FromGateway, []string{"narrowing"}},
		{403, `{"error":"policy_refused","names":["egress"],"from":"apiary"}`, "policy_refused", accesskey.FromApiary, []string{"egress"}},
		{401, `{"error":"unauthorized","from":"apiary"}`, "unauthorized", accesskey.FromApiary, nil},
		{409, `{"error":"instance_limit","from":"someone"}`, "instance_limit", accesskey.FromGateway, nil},
	} {
		g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w, c.status, c.body) }))
		k, digests := newLink(t, g)
		_, err := k.OpenRun(context.Background(), "http://localhost/v1/run-configuration", server.LinkRunRequest{RunID: runID})
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != c.code || r.Status != c.status || r.From != c.from || fmt.Sprint(r.Names) != fmt.Sprint(c.names) {
			t.Errorf("%d %s: %#v", c.status, c.body, err)
		}
		if _, ended := server.Ended(err); ended {
			t.Errorf("%d %s ends the run", c.status, c.body)
		}
		if len(*digests) != 1 {
			t.Errorf("%d %s: %d digests handed on", c.status, c.body, len(*digests))
		}
	}
	g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	k, _ := newLink(t, g)
	_, err := k.Reload(context.Background(), "http://localhost/v1/run-configuration", runID)
	var r *accesskey.Refusal
	if err == nil || errors.As(err, &r) || !strings.Contains(err.Error(), "status 500") {
		t.Errorf("a 500 with no code: %v", err)
	}
}

// TestA410OnTheLinkEndsTheRun pins the end of a run at the gateway: a 410 on any
// request carries its code, run_closed, credential_expired, run_ended_at_issuer,
// session_lost or batch_refused, and run_closed for another code or none, and who ended it, apiary when the body says so
// and the gateway otherwise; it hands on no digests; and a batch's 410 ends the run
// with the code.
func TestA410OnTheLinkEndsTheRun(t *testing.T) {
	for body, want := range map[string][2]string{
		`{"error":"run_closed","from":"apiary"}`:           {"run_closed", accesskey.FromApiary},
		`{"error":"run_closed","from":"gateway"}`:          {"run_closed", accesskey.FromGateway},
		`{"error":"credential_expired","from":"gateway"}`:  {"credential_expired", accesskey.FromGateway},
		`{"error":"run_ended_at_issuer","from":"gateway"}`: {"run_ended_at_issuer", accesskey.FromGateway},
		`{"error":"session_lost","from":"gateway"}`:        {"session_lost", accesskey.FromGateway},
		`{"error":"batch_refused","from":"gateway"}`:       {"batch_refused", accesskey.FromGateway},
		`{"error":"something_else"}`:                       {"run_closed", accesskey.FromGateway},
		``:                                                 {"run_closed", accesskey.FromGateway},
	} {
		g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w, http.StatusGone, body) }))
		k, digests := newLink(t, g)
		ctx := context.Background()
		_, err := k.OpenRun(ctx, "http://localhost/v1/run-configuration", server.LinkRunRequest{RunID: runID})
		if code, ok := server.Ended(err); !ok || code != want[0] || from(err) != want[1] {
			t.Errorf("run request, %q: %v, from %q", body, err, from(err))
		}
		_, err = k.Reload(ctx, "http://localhost/v1/run-configuration", runID)
		if code, ok := server.Ended(err); !ok || code != want[0] || from(err) != want[1] {
			t.Errorf("reload, %q: %v", body, err)
		}
		_, err = k.Discover(ctx)
		if code, ok := server.Ended(err); !ok || code != want[0] {
			t.Errorf("discovery, %q: %v", body, err)
		}
		d, err := k.Deliver(ctx, "http://localhost/v1/events", "d1", []byte("[]"), "")
		if err != nil || !d.Closed() || !d.Stop() || d.Accepted() || d.End != want[0] || d.From != want[1] || d.Digests != (server.Digests{}) {
			t.Errorf("batch, %q: %+v %v", body, d, err)
		}
		if len(*digests) != 0 {
			t.Errorf("%q: %d digests handed on after a 410", body, len(*digests))
		}
	}
}

// TestABatchTheGatewayRefusesEndsTheRun pins a 400 invalid_request to a batch: the
// gateway ended the run, so the batch's answer ends it with batch_refused, from the
// gateway; another refusal of a batch, or a status with no code, is retried.
func TestABatchTheGatewayRefusesEndsTheRun(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		end    string
	}{
		{400, `{"error":"invalid_request","names":["subject"]}`, "batch_refused"},
		{400, `{"error":"something_else"}`, ""},
		{400, ``, ""},
		{503, `{"error":"invalid_request"}`, ""},
		{409, `{"error":"run_id_used"}`, ""},
	} {
		g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w, c.status, c.body) }))
		k, _ := newLink(t, g)
		d, err := k.Deliver(context.Background(), "http://localhost/v1/events", "d1", []byte("[]"), "")
		if err != nil || d.End != c.end || d.Closed() != (c.end != "") || d.Stop() != (c.end != "") || d.Accepted() {
			t.Errorf("%d %s: %+v %v", c.status, c.body, d, err)
		}
		if c.end != "" && (d.From != accesskey.FromGateway || d.Digests != (server.Digests{})) {
			t.Errorf("%d %s: %+v", c.status, c.body, d)
		}
		if c.end == "" && d.Digests.RunConfiguration != runDigest {
			t.Errorf("%d %s: the digests of a retried answer are not handed on: %+v", c.status, c.body, d)
		}
	}
}

// TestAnAnswerTheLinkRefusesQuotesNoValue pins that a run answer the schema refuses,
// whose run id is not the request's, or whose added members are malformed, is a
// document error that quotes none of its values, the proxy secret above all.
func TestAnAnswerTheLinkRefusesQuotesNoValue(t *testing.T) {
	bad := "not a secret the schema allows!!" + proxySecret
	for name, body := range map[string]string{
		"a proxy secret the schema refuses": strings.Replace(runAnswer, proxySecret, bad, 1),
		"another run id":                    strings.Replace(runAnswer, runID, "0192f0c1-7d4e-7a2b-8c3d-000000000000", 1),
		"no credential":                     strings.Replace(runAnswer, `"credential":"none",`, "", 1),
		"a credential of no kind it names":  strings.Replace(runAnswer, `"credential":"none"`, `"credential":"apiary"`, 1),
		"a placeholder that is no name":     strings.Replace(runAnswer, `"placeholders":["GIT_TOKEN"]`, `"placeholders":["GIT TOKEN `+proxySecret+`"]`, 1),
		"an image without a reference":      strings.Replace(runAnswer, `"ref":"registry.example/base@sha256:00"`, `"ref":""`, 1),
		"a member twice":                    strings.Replace(runAnswer, `"version":1,`, `"version":1,"proxy_secret":"`+proxySecret+`",`, 1),
		"a digest without a policy":         strings.Replace(runAnswer, `"policy":{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}},`, "", 1),
		"details that are no object":        strings.Replace(runAnswer, `"details":{"requester":"requester"}`, `"details":["`+proxySecret+`"]`, 1),
		"a label key outside its grammar":   strings.Replace(runAnswer, `"forge":"example-forge"`, `"Forge":"example-forge"`, 1),
	} {
		g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { answer(w, 200, body) }))
		k, _ := newLink(t, g)
		_, err := k.OpenRun(context.Background(), "http://localhost/v1/run-configuration", server.LinkRunRequest{RunID: runID})
		var de *server.DocumentError
		if !errors.As(err, &de) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), proxySecret) || strings.Contains(err.Error(), "!!") {
			t.Errorf("%s: the error quotes a value: %v", name, err)
		}
	}
	g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer(w, 200, `{"version":1,"proxy_secret":"`+proxySecret+`"}`)
	}))
	k, _ := newLink(t, g)
	if _, err := k.Reload(context.Background(), "http://localhost/v1/run-configuration", runID); err == nil || strings.Contains(err.Error(), proxySecret) {
		t.Errorf("a reload answer with the proxy secret: %v", err)
	}
	if _, err := k.OpenRun(context.Background(), "http://localhost/v1/run-configuration", server.LinkRunRequest{RunID: runID, Narrowing: &server.LinkNarrowing{}}); err == nil {
		t.Error("a narrowing was sent on the local link")
	}
	if _, err := k.Reload(context.Background(), "http://localhost/v1/run-configuration", "../"+runID); err == nil {
		t.Error("a reload of a run id that is none was sent")
	}
}

// TestTheLinkNeverShowsItsSecret pins that the link secret appears in no error, no
// print under any verb of the client or of its value, and no log line, and that a run
// answer prints and logs without its proxy secret.
func TestTheLinkNeverShowsItsSecret(t *testing.T) {
	if _, err := server.NewLocalLink(link.Local{Socket: "/x", Secret: "with space " + linkSecret}, userAgent, nil); err == nil || strings.Contains(err.Error(), linkSecret) {
		t.Errorf("a secret no preamble carries: %v", err)
	}
	if _, err := server.NewLocalLink(link.Local{Secret: linkSecret}, userAgent, nil); err == nil || strings.Contains(err.Error(), linkSecret) {
		t.Errorf("no socket: %v", err)
	}
	k, err := server.NewLocalLink(link.Local{Socket: linktest.SocketPath(t), Secret: linkSecret}, userAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%T"} {
		fmt.Fprintf(&out, verb+"\n", k)
		fmt.Fprintf(&out, verb+"\n", *k)
	}
	log := slog.New(slog.NewJSONHandler(&out, nil))
	log.Info("link", "link", k, "value", *k)
	slog.New(slog.NewTextHandler(&out, nil)).Info("link", "link", k)
	_, err = k.Discover(context.Background())
	fmt.Fprintf(&out, "%v\n", err)
	_, err = k.Deliver(context.Background(), "http://localhost/v1/events", "d", []byte("[]"), "")
	fmt.Fprintf(&out, "%v\n", err)
	if err == nil {
		t.Error("a link with no gateway delivered")
	}
	g := linktest.Start(t, linkSecret, http.NotFoundHandler())
	k2, _ := server.NewLocalLink(g.Local(), userAgent, nil)
	server.SetPeerUID(k2, os.Getuid()+1)
	_, err = k2.Discover(context.Background())
	fmt.Fprintf(&out, "%v\n", err)
	a := server.LinkRunAnswer{RunID: runID, ProxySecret: proxySecret}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		fmt.Fprintf(&out, verb+"\n", a)
		fmt.Fprintf(&out, verb+"\n", &a)
	}
	log.Info("answer", "answer", a)
	if strings.Contains(out.String(), linkSecret) || strings.Contains(out.String(), proxySecret) {
		t.Errorf("a secret is shown:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "[redacted]") || !strings.Contains(out.String(), "server.LinkRunAnswer{") {
		t.Errorf("the run answer is not shown redacted:\n%s", out.String())
	}
}

// TestALinkInMemoryNeverDialsItsSocket pins the client of a gateway in this process: each
// connection is the Local's way in memory, it carries the same preamble with the
// secret, and the socket's path is never dialled, whatever listens there. A Local that
// has that way needs no socket.
func TestALinkInMemoryNeverDialsItsSocket(t *testing.T) {
	socket := linktest.SocketPath(t)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialled := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			dialled <- struct{}{}
			c.Close()
		}
	}()
	preambles := make(chan bool, 4)
	dial := func(context.Context) (net.Conn, error) {
		client, gateway := net.Pipe()
		go func() {
			defer gateway.Close()
			gateway.SetReadDeadline(time.Now().Add(5 * time.Second))
			ok, err := link.ReadLinkPreamble(bufio.NewReader(gateway), linkSecret)
			preambles <- ok && err == nil
		}()
		return client, nil
	}
	for _, l := range []link.Local{
		link.Local{Socket: socket, Secret: linkSecret}.InMemory(dial),
		link.Local{Secret: linkSecret}.InMemory(dial),
	} {
		k, err := server.NewLocalLink(l, userAgent, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = k.Discover(context.Background())
		if err == nil || strings.Contains(err.Error(), linkSecret) {
			t.Errorf("a gateway in memory that answers nothing: %v", err)
		}
		if ok := <-preambles; !ok {
			t.Error("the connection in memory did not open with the link's preamble")
		}
		k.Close()
	}
	select {
	case <-dialled:
		t.Error("the socket's path was dialled")
	case <-time.After(100 * time.Millisecond):
	}
}
