package gateway_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// gitPkt is s as one pkt-line of git's protocol.
func gitPkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// pushAnswer is a git host's answer to a push in side-band-64k: progress on band 2,
// then a report status on band 1 with every ref ok.
var pushAnswer = gitPkt("\x02Resolving deltas: 100% (1/1)\n") +
	gitPkt("\x01"+gitPkt("unpack ok\n")+gitPkt("ok refs/heads/main\n")+"0000") + "0000"

// pushRun is a run whose proxy terminates the forge host, localhost, with its session
// joined and exited, and a client that pushes through the run's proxy to an origin
// that serves answer: the first piece of it, then the rest once hold is closed, when
// hold is not nil.
type pushRun struct {
	h      *harness
	runID  string
	client *http.Client
	port   string
	// reached is closed once the origin has the push.
	reached chan struct{}
}

func startPushRun(t *testing.T, first string, hold chan struct{}, rest string) *pushRun {
	t.Helper()
	t.Setenv(pushSource, pushValue)
	certFile, keyFile, roots := testCertificate(t, t.TempDir())
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	reached := make(chan struct{})
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
		io.WriteString(w, first)
		w.(http.Flusher).Flush()
		close(reached)
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		io.WriteString(w, rest)
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())

	cfg := gateway.Config{
		Credentials: []gateway.Credential{{Name: "forge", Env: pushSource, Hosts: []string{"localhost"}, Scheme: "basic", Username: "x-access-token"}},
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}},
			Credentials: []gateway.PolicyCredential{{Name: "forge"}}}}
	gateway.SetUpstreamRoots(&cfg, roots)
	h := start(t, cfg)
	h.secrets = append(h.secrets, pushValue)
	a := h.open(server.LinkRunRequest{})
	runID := a.RunID
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	if n := h.joined(runID); n != 1 {
		t.Fatalf("the join is session %d", n)
	}
	if d := h.post(sessionStarted(runID, 1), sessionExited(runID, 1)); !d.Accepted() {
		t.Fatalf("the session's batch: %+v", d)
	}
	trusted := x509.NewCertPool()
	if !trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority)) {
		t.Fatal("the run answer has no certificate authority")
	}
	client := relay(h.g.Addr(), a.ProxySecret)
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
	return &pushRun{h: h, runID: runID, client: client, port: port, reached: reached}
}

// push sends a push to example-org/app through the run's proxy and returns what the
// session read of the answer.
func (p *pushRun) push() (string, error) {
	resp, err := p.client.Post("https://localhost:"+p.port+"/example-org/app.git/git-receive-pack", "application/x-git-receive-pack-request", strings.NewReader("0000"))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// writesAndEnd are the record's target writes, its push's egress and its end, in
// order, each target write with its state.
func writesAndEnd(lines []recorded) []string {
	var out []string
	for _, l := range lines {
		switch {
		case l.Type == event.RunTargetWrite:
			out = append(out, fmt.Sprint(l.Type, " ", l.Data["system"], " ", l.Data["path"], " ", l.Data["state"]))
		case l.Type == event.RunEgress && l.Data["method"] == "HTTPS":
			out = append(out, l.Type)
		case l.Type == event.RunExited:
			out = append(out, l.Type)
		}
	}
	return out
}

// requestIDs are the request_id of each target write and egress of the push.
func requestIDs(lines []recorded) []any {
	var out []any
	for _, l := range lines {
		if l.Type == event.RunTargetWrite || l.Type == event.RunEgress && l.Data["method"] == "HTTPS" {
			out = append(out, l.Data["request_id"])
		}
	}
	return out
}

// TestAPushThroughTheRunsProxyIsATargetWrite pins a git push through the run's proxy
// after the session exited, as qory's push step sends it: the session reads git's
// answer unchanged, and the run's record has the write's started, the request's
// dev.qory.run.egress and the write's changed, with the host as system and the
// repository as path, all three with the egress's request_id, before run.exited.
func TestAPushThroughTheRunsProxyIsATargetWrite(t *testing.T) {
	p := startPushRun(t, pushAnswer, nil, "")
	got, err := p.push()
	if err != nil || got != pushAnswer {
		t.Fatalf("the session read %q, %v; want git's answer", got, err)
	}
	if d := p.h.post(append(pushStep(p.runID, 1), exited(p.runID))...); !d.Accepted() {
		t.Fatalf("the push step's batch: %+v", d)
	}
	rec := p.h.record(p.runID)
	want := []string{event.RunTargetWrite + " localhost example-org/app started", event.RunEgress, event.RunTargetWrite + " localhost example-org/app changed", event.RunExited}
	if got := writesAndEnd(rec); !slices.Equal(got, want) {
		t.Errorf("the record %q; want %q", got, want)
	}
	ids := requestIDs(rec)
	if len(ids) != 3 || ids[0] == nil || ids[0] != ids[1] || ids[1] != ids[2] {
		t.Errorf("the request ids %v; want the egress's on both writes", ids)
	}
}

// TestAWriteOpenAtTheRunsEndIsCut pins a push the run ends during: the gateway's end of
// the run, here at a batch it refuses, and the session's close of the run each give the
// write's cut after its started and before run.exited, and no state after.
func TestAWriteOpenAtTheRunsEndIsCut(t *testing.T) {
	for name, end := range map[string]func(p *pushRun){
		"the gateway ends the run": func(p *pushRun) {
			// A batch with an egress, which the gateway writes, ends the run batch_refused.
			p.h.post(ev(p.runID, event.RunEgress, map[string]any{"host": "a.example", "port": 443, "method": "CONNECT", "decision": "allowed", "mode": "observe", "rule": "", "outcome": "connected"}))
		},
		"the session closes the run": func(p *pushRun) {
			if d := p.h.post(exited(p.runID)); !d.Accepted() {
				t.Fatalf("the close: %+v", d)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			hold := make(chan struct{})
			p := startPushRun(t, gitPkt("\x02Counting objects: 1\n"), hold, pushAnswer[len(gitPkt("\x02Resolving deltas: 100% (1/1)\n")):])
			done := make(chan struct{})
			go func() {
				defer close(done)
				p.push()
			}()
			<-p.reached
			end(p)
			eventually(t, "run.exited", func() bool { return slices.Contains(types(p.h.record(p.runID)), event.RunExited) })
			close(hold)
			<-done
			rec := p.h.record(p.runID)
			var writes []string
			for _, s := range writesAndEnd(rec) {
				if s != event.RunEgress {
					writes = append(writes, s)
				}
			}
			want := []string{event.RunTargetWrite + " localhost example-org/app started", event.RunTargetWrite + " localhost example-org/app cut", event.RunExited}
			if !slices.Equal(writes, want) {
				t.Errorf("the record %q; want %q", writes, want)
			}
		})
	}
}
