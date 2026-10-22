package session_test

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session"
)

// The tests of this file pin (*session.Run).EngineProxy: the engine proxy of a run with
// no wall, open during a host step, with the run's certificate in the certificates
// directory. qory opens it in a build step; these tests use a fetch step.

// engineCase is a run that engineRun opened: its spec, its fake gateway, its fetch
// step, the certificates directory, the preamble the gateway's proxy sees and what the
// run reported.
type engineCase struct {
	sp       runSpec
	g        *linktest.Fake
	step     *session.Step
	certs    string
	preamble string
	reports  func() []string
}

// engineRun opens a run with no wall, an engine proxy at a free address and the run's
// authority, behind a separate gateway when separate is set, with its certificates
// written under a directory of the test, and starts a fetch step.
func engineRun(t *testing.T, separate bool, env ...string) (*session.Run, engineCase) {
	t.Helper()
	certs := t.TempDir()
	t.Cleanup(session.SetEngineCertsDir(certs))
	roots := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(roots, []byte(machineRoots), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.SetMachineBundles([]string{roots}))
	sp, g := specGateway(t, env...)
	preamble := link.RelayPreamble + " " + linktest.ProxySecret
	if separate {
		g = startRemote(t)
		g.SetInterval(30)
		key := g.RunKey(t, event.NewRunID())
		sp.Gateway, preamble = remoteGateway(g, key), link.RelayPreamble+" "+key
	}
	credentialAnswer(g)
	sp.EngineProxy = &session.EngineProxy{Addr: freeLoopback(t), Password: enginePassword}
	reports := reportsOf(t, &sp)
	r, err := session.Open(context.Background(), opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	step, err := r.StartStep(event.StepFetch, "fetch example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	return r, engineCase{sp: sp, g: g, step: step, certs: certs, preamble: preamble, reports: reports}
}

// certFiles are the paths of the files under dir, relative to it.
func certFiles(dir string) []string {
	var out []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	return out
}

// TestTheEngineProxyReachesTheRunsProxy pins the engine proxy on one machine and behind
// a separate gateway: a request with its password reaches the gateway's proxy, a request
// without it or with another password is closed unanswered, the run's certificate is in
// the certificates directory for each host that can be a directory name while it is
// open, and after close nothing of it is left, and the password is in no file of the
// run directory, no request to the link and no report.
func TestTheEngineProxyReachesTheRunsProxy(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(map[bool]string{false: "one machine", true: "separate gateway"}[separate], func(t *testing.T) {
			r, c := engineRun(t, separate)
			addr, certs := c.sp.EngineProxy.Addr, c.certs
			stop, err := r.EngineProxy([]string{"registry.example", "*.registry.example", "registry.example"})
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join("registry.example", "qory-run-"+r.ID()+".crt")
			if got := certFiles(certs); !slices.Equal(got, []string{file}) {
				t.Errorf("while open, the certificates directory has %q, want %q", got, file)
			}
			if b, _ := os.ReadFile(filepath.Join(certs, file)); string(b) != authority {
				t.Errorf("the certificate is %q, want the run's", b)
			}
			if status, body := throughHost(t, "http://qory:"+enginePassword+"@"+addr, "http://registry.example/v2/"); status != http.StatusOK || body != "ok" {
				t.Errorf("the request through the engine proxy got %d %q", status, body)
			}
			if got := stray(addr); got != "closed unanswered\nclosed unanswered\n" {
				t.Errorf("the engine proxy took a connection without its password:\n%s", got)
			}
			if got := c.g.Preambles(); !slices.Equal(got, []string{c.preamble}) {
				t.Errorf("the gateway's proxy saw %q, want %q", got, c.preamble)
			}
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			refused(t, addr, "after its close")
			if got, _ := os.ReadDir(certs); len(got) != 0 {
				t.Errorf("after the close, the certificates directory has %v", got)
			}
			if err := stop(); err != nil {
				t.Errorf("a second close: %v", err)
			}
			c.step.Exit(event.StateSucceeded, 0)
			if _, err := r.Close(context.Background(), session.Outcome{State: event.StateSucceeded}); err != nil {
				t.Fatal(err)
			}
			noSecretIn(t, enginePassword, r.Dir(), c.g, c.reports())
		})
	}
}

// TestTheEngineProxyEnds pins the ends of an engine proxy other than its close: the next
// join and the run's close close its port and remove its certificate, after which its
// close returns nil, and a write that fails for the second host leaves no certificate
// and no listener, and a later call opens the engine proxy.
func TestTheEngineProxyEnds(t *testing.T) {
	ctx := context.Background()
	for _, end := range []string{"Join", "Run.Close"} {
		t.Run(end, func(t *testing.T) {
			r, c := engineRun(t, false, "FAKE_EXIT=0")
			stop, err := r.EngineProxy([]string{"registry.example"})
			if err != nil {
				t.Fatal(err)
			}
			c.step.Exit(event.StateSucceeded, 0)
			if end == "Join" {
				_, err = r.Join(ctx, c.sp.SessionSpec)
			} else {
				_, err = r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			refused(t, c.sp.EngineProxy.Addr, "after "+end)
			if got := certFiles(c.certs); len(got) != 0 {
				t.Errorf("after %s, the certificates directory has %q", end, got)
			}
			if err := stop(); err != nil {
				t.Errorf("a close after %s: %v", end, err)
			}
		})
	}
	t.Run("a failed write", func(t *testing.T) {
		r, c := engineRun(t, false)
		certs := c.certs
		defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		// A file where the second host's directory would be: the write into it fails.
		if err := os.WriteFile(filepath.Join(certs, "b.example"), []byte("not a directory"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := r.EngineProxy([]string{"a.example", "b.example"})
		if want := "Make " + certs + " writable for this user"; err == nil || !strings.HasPrefix(err.Error(), want) || strings.Contains(err.Error(), enginePassword) {
			t.Errorf("EngineProxy: %v, want an error that starts with %s", err, want)
		}
		if got := certFiles(certs); !slices.Equal(got, []string{"b.example"}) {
			t.Errorf("after the failed write, the certificates directory has %q", got)
		}
		refused(t, c.sp.EngineProxy.Addr, "after a failed write")
		stop, err := r.EngineProxy(nil)
		if err != nil {
			t.Fatalf("EngineProxy after a failed write: %v", err)
		}
		stop()
	})
}

// TestAnEngineProxyThatCannotOpen pins each refusal of EngineProxy: an error that
// starts with the fix and contains no password, and no listener at the address.
func TestAnEngineProxyThatCannotOpen(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	for _, c := range []struct {
		name, want string
		change     func(r *session.Run, step *session.Step)
	}{
		{"a walled run", "Open the engine proxy in a run with no wall: a walled run's image step listens at the engine proxy's address.", nil},
		{"no engine proxy", "Set OpenSpec.EngineProxy to the engine's proxy setting: the run has no engine proxy.", nil},
		{"no host step", "Start a host step before you open the engine proxy: the engine proxy opens only during a host step.",
			func(_ *session.Run, step *session.Step) { step.Exit(event.StateSucceeded, 0) }},
		{"a second holder", "Close the engine proxy before you open it again: the engine has one proxy setting, and the run's engine proxy is open.",
			func(r *session.Run, _ *session.Step) {
				if _, err := r.EngineProxy(nil); err != nil {
					t.Fatal(err)
				}
			}},
		{"an address in use", "Run one image step or engine proxy at a time on this machine: the engine has one proxy setting, and its forwarder cannot listen at " + taken.Addr().String() + " (", nil},
		{"a closed run", "Open a new run for the engine proxy: the run is closed.",
			func(r *session.Run, _ *session.Step) {
				r.Close(context.Background(), session.Outcome{State: event.StateSucceeded})
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t)
			credentialAnswer(g)
			sp.EngineProxy = &session.EngineProxy{Addr: freeLoopback(t), Password: enginePassword}
			switch c.name {
			case "a walled run":
				sp.Wall, sp.Image = &openWall{}, "example.com/agent:1"
			case "no engine proxy":
				sp.EngineProxy = nil
			case "an address in use":
				sp.EngineProxy.Addr = taken.Addr().String()
			}
			r, err := session.Open(context.Background(), opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(context.Background(), session.Outcome{State: event.StateSucceeded})
			step, err := r.StartStep(event.StepFetch, "fetch example.com/app")
			if err != nil {
				t.Fatal(err)
			}
			if c.change != nil {
				c.change(r, step)
			}
			_, err = r.EngineProxy(nil)
			if err == nil || !strings.HasPrefix(err.Error(), c.want) || strings.Contains(err.Error(), enginePassword) {
				t.Errorf("EngineProxy: %v, want %s", err, c.want)
			}
			if c.name != "an address in use" && c.name != "a second holder" && sp.EngineProxy != nil {
				refused(t, sp.EngineProxy.Addr, "after a refusal")
			}
		})
	}
}

// TestAnEngineProxyDuringAJoin pins EngineProxy while a join runs: when the join request
// reaches the gateway, EngineProxy returns the error whose fix is to wait for Join.
func TestAnEngineProxyDuringAJoin(t *testing.T) {
	ctx := context.Background()
	r, c := engineRun(t, false, "FAKE_EXIT=0")
	c.step.Exit(event.StateSucceeded, 0)
	var during error
	c.g.OnJoin(func(linktest.Join) linktest.Reply {
		_, during = r.EngineProxy(nil)
		return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": 1}}
	})
	if _, err := r.Join(ctx, c.sp.SessionSpec); err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	if want := "Open the engine proxy after Join returns: a session of the run is still running."; during == nil || during.Error() != want {
		t.Errorf("EngineProxy during the join: %v, want %s", during, want)
	}
	refused(t, c.sp.EngineProxy.Addr, "after a refusal during a join")
}

// TestAnEngineProxysCertificateThatStaysIsReported pins a certificate that the next join
// or the run's close cannot remove: OpenSpec.Report gets the line whose fix is to remove
// the file by hand.
func TestAnEngineProxysCertificateThatStaysIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes a file from a directory of mode 0500")
	}
	ctx := context.Background()
	for _, end := range []string{"Join", "Run.Close"} {
		t.Run(end, func(t *testing.T) {
			r, c := engineRun(t, false, "FAKE_EXIT=0")
			if _, err := r.EngineProxy([]string{"registry.example"}); err != nil {
				t.Fatal(err)
			}
			host := filepath.Join(c.certs, "registry.example")
			if err := os.Chmod(host, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(host, 0o755) })
			c.step.Exit(event.StateSucceeded, 0)
			var err error
			if end == "Join" {
				_, err = r.Join(ctx, c.sp.SessionSpec)
			} else {
				_, err = r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close(ctx, session.Outcome{State: event.StateSucceeded})
			f := filepath.Join(host, "qory-run-"+r.ID()+".crt")
			want := "Remove " + f + " by hand: the run's certificate stays trusted for registry.example until it is removed (remove " + f + ": permission denied)."
			if got := c.reports(); !slices.Contains(got, want) {
				t.Errorf("after %s, the reports %q lack %q", end, got, want)
			}
		})
	}
}
