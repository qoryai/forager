package session_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// separateAt starts a separate gateway at addr on the directory dir, attached at a.
func separateAt(t *testing.T, a *apiary, dir, addr, certFile, keyFile string) *gateway.Gateway {
	t.Helper()
	g, err := gateway.Start(context.Background(), gateway.Config{
		Dir: dir, Listen: addr, Heartbeat: time.Second, Version: "test",
		TLS:    &gateway.TLS{CertFile: certFile, KeyFile: keyFile},
		Server: &gateway.Server{Version: 1, URL: a.srv.URL, AccessKeyID: "ak_f1xt0re00000000g", ApiaryPublicKey: a.pin, AccessKey: a.key, InstanceID: "i_test"},
		Report: func(l string) { t.Log("the gateway reported:", l) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// closeSeparate closes g and returns its Delivery.
func closeSeparate(t *testing.T, g *gateway.Gateway) gateway.Delivery {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := g.Close(ctx)
	if err != nil {
		t.Errorf("the gateway's Close: %v", err)
	}
	return d
}

// TestARunGoesOnThroughAGatewayRestart is a run end to end behind a separate gateway
// that restarts mid-run: Close suspends the run, the gateway is down for 3 seconds, and
// a gateway that starts on the same address and directory reopens the run at the
// session's first request. In each case the run ends as if nothing stopped: the server
// receives every sequence once and one run.exited, the session's, succeeded; no event
// of the session, of the gateway's record or of the server has run_closed,
// gateway_lost or session_lost; the run is attached twice under the same run key, with
// the same instance id; nothing is undelivered; and the run's CA key goes at its end.
//
// The cases: the agent's request through the proxy after the restart, which gets the
// reopened proxy's 403; the session's last flush while the gateway is down; and a
// re-attach that gets a 503 three times before its 200.
func TestARunGoesOnThroughAGatewayRestart(t *testing.T) {
	cases := []struct {
		name string
		// down is true when the agent ends while the gateway is down, so the session's
		// last batches wait for the restart; otherwise the agent requests a denied URL
		// after the restart.
		down bool
		// fails is how many re-attaches get a 503.
		fails int
	}{
		{name: "a request after the restart"},
		{name: "the last flush while the gateway is down", down: true},
		{name: "a re-attach answered 503 three times", fails: 3},
	}
	// The session's last flush waits up to 60 seconds for the gateway that starts again.
	finalWait := session.SetFinalWait(60 * time.Second)
	t.Cleanup(func() { session.SetFinalWait(finalWait) })
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newApiary(t)
			certFile, keyFile, caFile := separateCertificate(t)
			dir := t.TempDir()
			g := separateAt(t, a, dir, "127.0.0.1:0", certFile, keyFile)
			addr := g.Addr()
			defer func() {
				if g != nil {
					closeSeparate(t, g)
				}
			}()

			files := t.TempDir()
			wait, got := filepath.Join(files, "wait"), filepath.Join(files, "got")
			env := []string{"FAKE_WAIT=" + wait}
			if !c.down {
				env = append(env, "FAKE_DENIED_URL=http://denied.example/after", "FAKE_GOT="+got)
			}
			sp := spec(t, env...)
			sp.Timeout = 2 * time.Minute
			sp.RunID = event.NewRunID()
			sp.Gateway = session.RemoteGateway{RunKey: a.runKey(t, sp.RunID, "https://"+addr, a.key), TLS: server.RemoteTLS{CAFile: caFile}}
			own := filepath.Join(sp.RunsDir, sp.RunID)
			records := filepath.Join(dir, "runs", sp.RunID)

			done := make(chan *session.Result, 1)
			var closed *session.Closed
			go func() {
				res, cl, err := runClosed(context.Background(), sp)
				if err != nil {
					t.Error(err)
				}
				closed = cl
				done <- res
			}()
			// The agent runs: the open's and the join's policy_applied are in the
			// session's record, and the server received the run's first batch.
			waitFor(t, func() bool {
				if _, err := os.Stat(filepath.Join(own, "session.jsonl")); err != nil {
					return false
				}
				return len(ofType(events(t, &session.Result{Dir: own}), "dev.qory.run.policy_applied")) == 2 && len(a.receivedTypes()) > 0
			})

			if d := closeSeparate(t, g); d.RunClosed {
				t.Errorf("the first gateway's Delivery %+v; want no run closed", d)
			}
			if !exists(filepath.Join(records, "ca.key")) {
				t.Fatal("the suspended run has no ca.key")
			}
			down := time.Now()
			if c.down {
				// The agent ends, and the session closes the run, while the gateway is
				// down. The session's flush before its session.exited ends after
				// closeWait, 3 s in these tests; then the session's last flush waits for
				// the gateway's restart.
				os.WriteFile(wait, nil, 0o600)
				waitFor(t, func() bool {
					return len(ofType(events(t, &session.Result{Dir: own}), "dev.qory.run.exited")) == 1
				})
				if len(done) > 0 {
					t.Fatal("the session ended before the gateway's restart")
				}
			}
			time.Sleep(time.Until(down.Add(3 * time.Second)))
			a.mu.Lock()
			a.failAttaches = c.fails
			a.mu.Unlock()
			g = separateAt(t, a, dir, addr, certFile, keyFile)
			if !c.down {
				os.WriteFile(wait, nil, 0o600)
			}

			var res *session.Result
			select {
			case res = <-done:
			case <-time.After(3 * time.Minute):
				t.Fatal("the session did not end")
			}
			if res == nil {
				t.FailNow()
			}
			if res.State != event.StateSucceeded || res.RunClosed || closed == nil || closed.Undelivered != 0 {
				t.Errorf("result %+v, closed %+v", res, closed)
			}
			if !c.down {
				if b, _ := os.ReadFile(got); string(b) != "http://denied.example/after 403\n" {
					t.Errorf("the agent's request after the restart: %q; want a 403", b)
				}
			}

			waitFor(t, func() bool {
				got := a.receivedTypes()
				return len(got) > 0 && got[len(got)-1] == "dev.qory.run.exited"
			})
			a.mu.Lock()
			received, tried := slices.Clone(a.received), slices.Clone(a.tried)
			a.mu.Unlock()
			// The record's first line, run.registered, is never posted.
			checkSequences(t, "the server", received, 2)
			checkSequences(t, "the gateway's record", record(t, &session.Result{Dir: records}), 1)
			exited := ofType(received, "dev.qory.run.exited")
			if len(exited) != 1 || data(exited[0])["state"] != event.StateSucceeded || data(exited[0])["exit_code"] != float64(0) {
				t.Errorf("the server's run.exited %v; want one, the session's, succeeded", exited)
			}
			for what, evs := range map[string][]map[string]any{
				"the server": received, "the gateway's record": record(t, &session.Result{Dir: records}), "the session's record": events(t, res),
			} {
				b, _ := json.Marshal(evs)
				for _, lost := range []string{"run_closed", "gateway_lost", "session_lost"} {
					if strings.Contains(string(b), lost) {
						t.Errorf("%s has %s: %v", what, lost, types(evs))
					}
				}
			}

			if len(tried) != 2+c.fails {
				t.Errorf("%d attaches; want %d", len(tried), 2+c.fails)
			}
			var succeeded int
			for _, at := range tried {
				k, err := runkey.Parse(at.runKey)
				if err != nil || at.runKey != tried[0].runKey || at.instance != tried[0].instance {
					t.Errorf("an attach under another run key or instance: %+v, %v", at, err)
					continue
				}
				if k.RunID != sp.RunID {
					t.Errorf("an attach of run %s", k.RunID)
				}
				if !at.failed {
					succeeded++
				}
			}
			if succeeded != 2 {
				t.Errorf("%d attaches got a 200; want 2", succeeded)
			}

			waitFor(t, func() bool { return !exists(filepath.Join(records, "ca.key")) })
			if d := closeSeparate(t, g); d.Undelivered != 0 || d.RunClosed {
				t.Errorf("the second gateway's Delivery %+v", d)
			}
			g = nil
		})
	}
}

// checkSequences checks that evs have the sequences from first to first+len(evs)-1,
// each once.
func checkSequences(t *testing.T, what string, evs []map[string]any, first int) {
	t.Helper()
	seen := map[int]int{}
	for _, e := range evs {
		s, _ := e["sequence"].(string)
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Errorf("%s: an event with the sequence %q", what, s)
			continue
		}
		seen[n]++
	}
	for n := first; n < first+len(evs); n++ {
		if seen[n] != 1 {
			t.Errorf("%s has sequence %d %d times; want once in %d to %d: %v", what, n, seen[n], first, first+len(evs)-1, types(evs))
		}
	}
}

// exists reports whether file is there.
func exists(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}
