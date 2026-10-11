package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// remoteRunID is the run of the tests behind a separate gateway.
const remoteRunID = runID

// remoteLink is the client of the fake separate gateway's link for the run key, its
// authority trusted.
func remoteLink(t *testing.T, f *linktest.Fake, runKey string) *server.Link {
	t.Helper()
	k, err := server.NewRemoteLink(runKey, server.RemoteTLS{CAFile: f.CAFile()}, userAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	return k
}

// TestTheRemoteLinkSpeaksTheContractOverTLS pins one run's requests behind a separate
// gateway: each connection bound before anything is sent, the discovery at
// /qory-link/configuration, the run request with its narrowing, the reload and a batch,
// each with the run key as Authorization: Bearer and no X-Qory-Run-Id, and each answer
// verified under the key the run key names; no proxy of the environment is used.
func TestTheRemoteLinkSpeaksTheContractOverTLS(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	f := linktest.StartRemoteFake(t)
	key := f.RunKey(t, remoteRunID)
	k := remoteLink(t, f, key)
	ctx := context.Background()
	d, err := k.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(f.URL(), "https://")
	if d.Proxy == nil || d.Proxy.Address != host || k.ProxyAddress() != host || !strings.HasPrefix(d.Run.URL, f.URL()+"/qory-link/") {
		t.Errorf("the discovery %+v, the link's one address %s", d, k.ProxyAddress())
	}
	narrowing := &server.LinkNarrowing{Egress: server.LinkNarrowingEgress{Allow: []string{"api.example"}}}
	a, err := k.OpenRun(ctx, d.Run.URL, server.LinkRunRequest{RunID: remoteRunID, Narrowing: narrowing})
	if err != nil {
		t.Fatal(err)
	}
	if a.RunID != remoteRunID || a.ProxySecret != "" {
		t.Errorf("the run answer %+v", a)
	}
	if _, err := k.Reload(ctx, d.Run.URL, remoteRunID); err != nil {
		t.Fatal(err)
	}
	if dl, err := k.Deliver(ctx, d.Events.URL, "d-1", []byte("[]"), ""); err != nil || !dl.Accepted() {
		t.Fatalf("the batch: %+v %v", dl, err)
	}
	if want := []string{"Bearer " + key, "Bearer " + key, "Bearer " + key, "Bearer " + key}; fmt.Sprint(f.Bearers()) != fmt.Sprint(want) {
		t.Errorf("Authorization %q, want the run key on every request", f.Bearers())
	}
	if fmt.Sprint(f.RunIDs()) != "[]" {
		t.Errorf("X-Qory-Run-Id behind a separate gateway: %q", f.RunIDs())
	}
	if raw := f.RawRequests(); len(raw) != 1 || !bytes.Contains(raw[0], []byte(`"narrowing":{"egress":{"allow":["api.example"]}}`)) {
		t.Errorf("the run request %s", raw)
	}
	if f.Bound() == 0 || len(f.Leaked()) != 0 {
		t.Errorf("%d connections bound, %q sent after a failed proof", f.Bound(), f.Leaked())
	}
}

// TestTheRemoteLinkTakesARunKeyAlone pins what NewRemoteLink refuses before it sends
// anything: a run key it cannot read, which the error names by the part that is wrong,
// never by its value; a CAFile that is missing or holds no certificate; and a pin that
// is not 32 bytes in standard base64 with padding.
func TestTheRemoteLinkTakesARunKeyAlone(t *testing.T) {
	f := linktest.StartRemoteFake(t)
	key := f.RunKey(t, remoteRunID)
	for name, bad := range map[string]string{
		"empty":            "",
		"another prefix":   "qrx_" + strings.TrimPrefix(key, "qrk_"),
		"no signature":     key[:strings.LastIndex(key, ".")],
		"a payload of no ": "qrk_bm90LWpzb24." + key[strings.LastIndex(key, ".")+1:],
	} {
		_, err := server.NewRemoteLink(bad, server.RemoteTLS{}, userAgent, nil)
		var re *runkey.Error
		if !errors.As(err, &re) || !errors.Is(err, runkey.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		} else if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("%s: the error quotes the run key: %v", name, err)
		}
	}
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	os.WriteFile(notPEM, []byte("no certificate"), 0o600)
	sum := sha256.Sum256([]byte("a key"))
	for name, trust := range map[string]server.RemoteTLS{
		"a missing CA file": {CAFile: filepath.Join(t.TempDir(), "none.pem")},
		"a CA file not PEM": {CAFile: notPEM},
		"a hex pin":         {CertificateSHA256: fmt.Sprintf("%x", sum)},
		"a pin unpadded":    {CertificateSHA256: base64.RawStdEncoding.EncodeToString(sum[:])},
		"a short pin":       {CertificateSHA256: base64.StdEncoding.EncodeToString(sum[:16])},
	} {
		if _, err := server.NewRemoteLink(key, trust, userAgent, nil); err == nil {
			t.Errorf("%s: a link", name)
		}
	}
	if len(f.Bearers()) != 0 || f.Bound() != 0 {
		t.Error("a refused link sent something")
	}
}

// TestTheRemoteLinkChecksTheChain pins the chain check of the gateway's certificate: the
// system's roots, which know no test authority, trust nothing of the fake, and a
// gateway that is not trusted is sent nothing, not even the binding.
func TestTheRemoteLinkChecksTheChain(t *testing.T) {
	f := linktest.StartRemoteFake(t)
	k, err := server.NewRemoteLink(f.RunKey(t, remoteRunID), server.RemoteTLS{}, userAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if _, err := k.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("the system's roots: %v", err)
	}
	if c, err := k.DialProxy(context.Background()); err == nil {
		c.Close()
		t.Error("the proxy of an untrusted gateway was dialled")
	}
	if f.Bound() != 0 || len(f.Bearers()) != 0 || len(f.Preambles()) != 0 {
		t.Error("an untrusted gateway was sent something")
	}
}

// TestTheRemoteLinkChecksTheHostName pins that the chain is verified for the host name
// of the run key's gateway_url: a certificate for 127.0.0.1 is no certificate of
// localhost.
func TestTheRemoteLinkChecksTheHostName(t *testing.T) {
	f := linktest.StartRemoteFake(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(f.URL(), "https://"))
	k := remoteLink(t, f, f.RunKeyAt(t, remoteRunID, "https://localhost:"+port))
	if _, err := k.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "localhost") {
		t.Errorf("another host name: %v", err)
	}
	if f.Bound() != 0 {
		t.Error("a gateway of another name was bound")
	}
}

// TestTheRemoteLinkRefusesTLS12 pins TLS 1.3 alone: a gateway that offers no more than
// TLS 1.2 is sent nothing, its proxy as its link.
func TestTheRemoteLinkRefusesTLS12(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	k, err := server.NewRemoteLink(runKeyFor(t, srv.URL), server.RemoteTLS{CAFile: ca}, userAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if _, err := k.Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("TLS 1.2: %v", err)
	}
	if c, err := k.DialProxy(context.Background()); err == nil {
		c.Close()
		t.Error("the proxy over TLS 1.2 was dialled")
	}
	if hits.Load() != 0 {
		t.Error("a TLS 1.2 gateway was sent a request")
	}
}

// runKeyFor is a run key of a gateway at gatewayURL under a key of its own, signed under
// a server key of its own.
func runKeyFor(t *testing.T, gatewayURL string) string {
	t.Helper()
	g, _ := accesskey.Generate()
	signer, _ := accesskey.Generate()
	instance, _ := accesskey.NewInstanceID()
	now := time.Now().UTC().Truncate(time.Second)
	k, err := runkey.Key{
		RunID: remoteRunID, Workspace: "ws_f1xt0re000000000", NodeID: "np_f1xt0re000000000", Gateway: "ng_f1xt0re000000000",
		InstanceID: instance, GatewayURL: gatewayURL, GatewayKeys: []accesskey.PublicKey{g.PublicKey()}, Issued: now, AttachBy: now.Add(time.Minute),
	}.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestAGatewayThatCannotProveItsKeyIsSentNothing pins the binding's failures: a gateway
// whose answer to QORY-BIND has a signature over another connection, a fingerprint the
// run key does not name, or no answer at all, fails with the one text, on the link and
// on its proxy, and is sent neither the run key nor anything else after QORY-BIND.
func TestAGatewayThatCannotProveItsKeyIsSentNothing(t *testing.T) {
	for name, p := range map[string]linktest.Proof{
		"another connection's signature":  linktest.ProofBadSignature,
		"a key the run key does not name": linktest.ProofUnnamedKey,
		"no answer":                       linktest.ProofNone,
	} {
		f := linktest.StartRemoteFake(t)
		f.SetProof(p)
		key := f.RunKey(t, remoteRunID)
		k := remoteLink(t, f, key)
		want := "the gateway at " + f.URL() + " could not prove it holds a key the run key names"
		_, err := k.Discover(context.Background())
		var ge *server.GatewayKeyError
		if !errors.As(err, &ge) || !ge.Unproven || ge.URL != f.URL() || ge.Error() != want {
			t.Errorf("%s: the link: %v", name, err)
		}
		if c, err := k.DialProxy(context.Background()); err == nil {
			c.Close()
			t.Errorf("%s: the proxy was dialled", name)
		} else if !errors.As(err, &ge) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: the proxy: %v", name, err)
		}
		time.Sleep(50 * time.Millisecond)
		if f.Bound() != 0 || len(f.Bearers()) != 0 || len(f.Preambles()) != 0 || len(f.Leaked()) != 0 {
			t.Errorf("%s: sent after a failed proof: %q, bearers %q, preambles %q", name, f.Leaked(), f.Bearers(), f.Preambles())
		}
		if err != nil && strings.Contains(err.Error(), key) {
			t.Errorf("%s: the error quotes the run key", name)
		}
	}
}

// TestAnAnswerUnderAnotherKeyIsNoAnswer pins the signature of every answer: an answer
// signed under a key the run key does not name, or with none, is the other text,
// before the run opens and once it runs, and nothing of it reaches the caller.
func TestAnAnswerUnderAnotherKeyIsNoAnswer(t *testing.T) {
	for _, unsigned := range []bool{false, true} {
		f := linktest.StartRemoteFake(t)
		k := remoteLink(t, f, f.RunKey(t, remoteRunID))
		want := "the gateway at " + f.URL() + " answered under a key the run key does not name"
		ctx := context.Background()
		d, err := k.Discover(ctx)
		if err != nil {
			t.Fatal(err)
		}
		f.AnswerUnderUnnamedKey(t, unsigned)
		var ge *server.GatewayKeyError
		if _, err := k.OpenRun(ctx, d.Run.URL, server.LinkRunRequest{RunID: remoteRunID}); !errors.As(err, &ge) || ge.Unproven || err.Error() != want {
			t.Errorf("unsigned %v: the run request: %v", unsigned, err)
		}
		f.AnswerUnderOwnKey()
		if _, err := k.OpenRun(ctx, d.Run.URL, server.LinkRunRequest{RunID: remoteRunID}); err != nil {
			t.Fatal(err)
		}
		f.AnswerUnderUnnamedKey(t, unsigned)
		if dl, err := k.Deliver(ctx, d.Events.URL, "d-1", []byte("[]"), ""); !errors.As(err, &ge) || err.Error() != want || dl.Accepted() {
			t.Errorf("unsigned %v: a batch mid-run: %+v %v", unsigned, dl, err)
		}
		if _, err := k.Reload(ctx, d.Run.URL, remoteRunID); !errors.As(err, &ge) || err.Error() != want {
			t.Errorf("unsigned %v: a reload mid-run: %v", unsigned, err)
		}
	}
}

// TestTheRemoteProxyOpensWithTheRunKey pins the proxy's connection behind a separate
// gateway: bound as the link is, then QORY-RELAY and the run key, then the agent's
// traffic.
func TestTheRemoteProxyOpensWithTheRunKey(t *testing.T) {
	f := linktest.StartRemoteFake(t)
	key := f.RunKey(t, remoteRunID)
	k := remoteLink(t, f, key)
	c, err := k.DialProxy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET http://api.example/ HTTP/1.1\r\nHost: api.example\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("through the proxy: %v %v", res, err)
	}
	if want := []string{"QORY-RELAY " + key}; fmt.Sprint(f.Preambles()) != fmt.Sprint(want) || f.Bound() != 1 {
		t.Errorf("the preambles %q, %d bound", f.Preambles(), f.Bound())
	}
}

// TestTheRemoteLinkPassesTheGatewaysRefusalsOn pins the refusals of a separate gateway
// as the local link's, signed as every answer is: the code, the status, the names and
// who refused, and the refusal's message as its text, word for word; to a batch, in the
// Delivery's Refusal.
func TestTheRemoteLinkPassesTheGatewaysRefusalsOn(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
		names  []string
		text   string
	}{
		{401, "unauthorized", nil, "the gateway refused the run: unauthorized"},
		{403, "placeholder_conflict", []string{"GIT_TOKEN"}, "the run passes a value for the placeholder GIT_TOKEN"},
	} {
		f := linktest.StartRemoteFake(t)
		body := map[string]any{"error": c.code, "from": "gateway", "message": c.text}
		if c.names != nil {
			body["names"] = c.names
		}
		refuse := linktest.Reply{Status: c.status, Body: body}
		f.OnRun(func(server.LinkRunRequest) linktest.Reply { return refuse })
		f.OnBatch(func([]map[string]any) linktest.Reply { return refuse })
		k := remoteLink(t, f, f.RunKey(t, remoteRunID))
		d, err := k.Discover(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		_, err = k.OpenRun(context.Background(), d.Run.URL, server.LinkRunRequest{RunID: remoteRunID})
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != c.code || r.Status != c.status || r.From != accesskey.FromGateway || fmt.Sprint(r.Names) != fmt.Sprint(c.names) || err.Error() != c.text {
			t.Errorf("%s: %#v", c.code, err)
		}
		// A batch's answer carries the same refusal, which a resend stops on.
		dl, err := k.Deliver(context.Background(), d.Events.URL, "d", []byte("[]"), "")
		if r := dl.Refusal; err != nil || dl.Accepted() || dl.Stop() || dl.Code != c.code || r == nil || r.Code != c.code || r.Status != c.status || r.From != accesskey.FromGateway || fmt.Sprint(r.Names) != fmt.Sprint(c.names) || r.Error() != c.text {
			t.Errorf("%s: the batch's answer %+v %v", c.code, dl, err)
		}
	}
}

// TestARemoteDiscoveryOffTheGatewayIsRefused pins that a separate gateway's discovery
// names its one address as its proxy, and that a request to a URL of another origin, or
// of its own origin off /qory-link/, is never sent.
func TestARemoteDiscoveryOffTheGatewayIsRefused(t *testing.T) {
	for _, proxy := range []string{"proxy.example:3128", "127.0.0.1:1"} {
		f := linktest.StartRemoteFake(t)
		f.SetDiscoveryProxy(proxy)
		var de *server.DocumentError
		if _, err := remoteLink(t, f, f.RunKey(t, remoteRunID)).Discover(context.Background()); !errors.As(err, &de) {
			t.Errorf("the proxy %s: %v", proxy, err)
		}
	}
	f := linktest.StartRemoteFake(t)
	k := remoteLink(t, f, f.RunKey(t, remoteRunID))
	for _, u := range []string{"https://elsewhere.example/qory-link/v1/run-configuration", "http://" + strings.TrimPrefix(f.URL(), "https://") + "/qory-link/v1/run-configuration", f.URL() + linktest.RunPath} {
		if _, err := k.OpenRun(context.Background(), u, server.LinkRunRequest{RunID: remoteRunID}); err == nil {
			t.Errorf("a run request to %s was sent", u)
		}
		if _, err := k.Deliver(context.Background(), u, "d", []byte("[]"), ""); err == nil {
			t.Errorf("a batch to %s was sent", u)
		}
	}
	if len(f.Bearers()) != 0 {
		t.Error("a request off the gateway's link was sent")
	}
}

// TestTheRemoteLinkFollowsNoRedirect pins that a redirect is a status like any other:
// nothing of the run goes where it points.
func TestTheRemoteLinkFollowsNoRedirect(t *testing.T) {
	f := linktest.StartRemoteFake(t)
	f.OnReload(func(string) linktest.Reply {
		return linktest.Reply{Status: http.StatusTemporaryRedirect, Header: http.Header{"Location": {"/qory-link/elsewhere"}}}
	})
	k := remoteLink(t, f, f.RunKey(t, remoteRunID))
	if _, err := k.Reload(context.Background(), f.URL()+linktest.RemotePrefix+linktest.RunPath, remoteRunID); err == nil || !strings.Contains(err.Error(), "307") {
		t.Errorf("a redirect: %v", err)
	}
	if len(f.Bearers()) != 1 {
		t.Errorf("%d requests, the redirect followed", len(f.Bearers()))
	}
}

// TestTheRemoteLinkNeverShowsTheRunKey pins that the run key is in no print or log of
// the link, which shows the gateway's URL.
func TestTheRemoteLinkNeverShowsTheRunKey(t *testing.T) {
	f := linktest.StartRemoteFake(t)
	key := f.RunKey(t, remoteRunID)
	k := remoteLink(t, f, key)
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("link", "link", k)
	for _, out := range []string{fmt.Sprint(k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), fmt.Sprintf("%#v", *k), k.String(), b.String()} {
		if strings.Contains(out, key[4:40]) || !strings.Contains(out, f.URL()) {
			t.Errorf("printed as %s", out)
		}
	}
}

// TestTheLocalLinkHasNoProxyOverTLS pins that DialProxy is a separate gateway's alone.
func TestTheLocalLinkHasNoProxyOverTLS(t *testing.T) {
	k, err := server.NewLocalLink(link.Local{Socket: "/nonexistent/qory-link-x/sock"}, userAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.DialProxy(context.Background()); err == nil {
		t.Error("the local link dialled a proxy over TLS")
	}
	if k.ProxyAddress() != "" {
		t.Errorf("the local link's one address %q", k.ProxyAddress())
	}
}
