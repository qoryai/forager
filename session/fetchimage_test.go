package session_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/internal/linktest"
	refusals "github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// The tests of this file pin (*session.Run).FetchImage: the run's image by reference
// fetched as a host step, through the engine proxy when the run has one.

// enginePassword is the fake password of the daemon's proxy setting, 43 characters of
// base64url as the machine's start unit writes one.
const enginePassword = "FakeEngineProxyPassword-0123456789abcdefghi"

// freeLoopback is a loopback host:port no listener has, as a start unit writes into
// the daemon's proxy setting.
func freeLoopback(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// pullingWall is a targetWall whose pull, in place of the engine, runs during: it notes
// what each pull was given.
type pullingWall struct {
	targetWall
	during func(ctx context.Context) error
	cas    [][]byte
	hosts  [][]string
}

func (w *pullingWall) Pull(ctx context.Context, req wall.Request, ca []byte, hosts []string) error {
	w.pulls, w.cas, w.hosts = append(w.pulls, req), append(w.cas, ca), append(w.hosts, hosts)
	if w.during != nil {
		return w.during(ctx)
	}
	return nil
}

// imageWithCredentials has g answer the run's image by reference, as byReference does,
// with the run's authority and a credential for the registry's token endpoint,
// auth.registry.example.
func imageWithCredentials(g *linktest.Fake) {
	g.OnRun(func(req server.LinkRunRequest) linktest.Reply {
		a := linktest.RunAnswer(req)
		a["image"] = map[string]any{"ref": pinned, "reference": true}
		a["relay_image"] = "example.com/agent:1"
		a["applied"].(map[string]any)["image"] = pinned
		a["certificate_authority"] = authority
		a["credential_hosts"] = []any{map[string]any{"name": "registry", "hosts": []string{"auth.registry.example"}, "placeholders": []string{}}}
		return linktest.Reply{Status: 200, Body: a}
	})
}

// TestTheImageIsFetchedThroughTheEngineProxy pins FetchImage with an engine proxy, on
// one machine and behind a separate gateway: the image step is the run's first step,
// named after the reference; during the pull alone a forwarder listens at the engine
// proxy's address, passes a request with its password on to the gateway's proxy and
// closes one without it unanswered; the wall's pull gets the run's certificate and the
// hosts of the run's credentials; the join that follows writes no image step and asks
// the wall for the image by reference, which it pulls no more; and the password is in
// no file of the run directory, no request to the link and no report.
func TestTheImageIsFetchedThroughTheEngineProxy(t *testing.T) {
	for _, separate := range []bool{false, true} {
		name := "one machine"
		if separate {
			name = "separate gateway"
		}
		t.Run(name, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			if separate {
				g = startRemote(t)
				g.SetInterval(30)
				sp.Gateway = session.RemoteGateway{RunKey: g.RunKey(t, event.NewRunID())}
			}
			imageWithCredentials(g)
			// A runtime with no model keys: the run's one credential is the registry's.
			sp.Runtime = nil
			addr := freeLoopback(t)
			w := &pullingWall{}
			w.during = func(context.Context) error {
				if status, body := throughHost(t, "http://qory:"+enginePassword+"@"+addr, "http://registry.example/v2/"); status != http.StatusOK || body != "ok" {
					t.Errorf("the request through the engine proxy got %d %q", status, body)
				}
				if got := stray(addr); got != "closed unanswered\nclosed unanswered\n" {
					t.Errorf("the engine proxy took a connection without its password:\n%s", got)
				}
				return nil
			}
			sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
			sp.EngineProxy = &session.EngineProxy{Addr: addr, Password: enginePassword}
			reports := reportsOf(t, &sp)
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.FetchImage(ctx); err != nil {
				t.Fatal(err)
			}
			if c, err := net.Dial("tcp", addr); err == nil {
				c.Close()
				t.Error("the engine proxy takes a connection after the image step")
			}
			if got := g.Proxied(); !slices.Equal(got, []string{"GET http://registry.example/v2/"}) {
				t.Errorf("the gateway's proxy answered %q", got)
			}
			if len(w.cas) != 1 || string(w.cas[0]) != authority || !slices.Equal(w.hosts[0], []string{"auth.registry.example"}) {
				t.Errorf("the pull got the certificate %q and the hosts %q", w.cas, w.hosts)
			}
			res, err := r.Join(ctx, sp.SessionSpec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded}); err != nil {
				t.Fatal(err)
			}
			want := wall.Request{RunID: r.ID(), Image: pinned, RelayImage: "example.com/agent:1", Pull: true}
			if len(w.pulls) != 1 || !reflect.DeepEqual(w.pulls[0], want) || !reflect.DeepEqual(w.req, want) {
				t.Errorf("the wall pulled %+v and was asked for %+v, want one pull of %+v", w.pulls, w.req, want)
			}
			steps := []string{"step 1 image " + pinned, "step 1 succeeded -1", "step 2 join join session 1", "step 2 succeeded -1", "session 1 started",
				"step 3 wall start the wall", "step 3 succeeded -1", "session 1 exited", "run exited"}
			if got := stepOrder(events(t, res)); !slices.Equal(got, steps) {
				t.Errorf("the steps:\n%q\nwant\n%q", got, steps)
			}
			noSecretIn(t, enginePassword, r.Dir(), g, reports())
		})
	}
}

// TestTheImageIsFetchedOverTheMachinesNetwork pins FetchImage without an engine proxy:
// the image step, and a pull with no certificate and no hosts; and that a run whose
// image the machine defines has nothing to fetch, with no step.
func TestTheImageIsFetchedOverTheMachinesNetwork(t *testing.T) {
	sp, g := specGateway(t, "FAKE_EXIT=0")
	imageWithCredentials(g)
	w := &pullingWall{}
	sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.FetchImage(ctx); err != nil {
		t.Fatal(err)
	}
	if len(w.pulls) != 1 || w.cas[0] != nil || w.hosts[0] != nil {
		t.Errorf("the pulls %+v, with %q and %q", w.pulls, w.cas, w.hosts)
	}
	closed, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stepOrder(events(t, &session.Result{Dir: closed.Dir})), []string{"step 1 image " + pinned, "step 1 succeeded -1", "run exited"}; !slices.Equal(got, want) {
		t.Errorf("the steps %q, want %q", got, want)
	}

	sp, g = specGateway(t, "FAKE_EXIT=0")
	selecting(g, "")
	w = &pullingWall{}
	sp.Wall, sp.Image, sp.Images = w, "base", images
	r, err = session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.FetchImage(ctx); err != nil || len(w.pulls) != 0 {
		t.Errorf("an image the machine defines: %v, pulled %+v", err, w.pulls)
	}
	closed, err = r.Close(ctx, session.Outcome{State: event.StateSucceeded})
	if err != nil {
		t.Fatal(err)
	}
	if got := stepOrder(events(t, &session.Result{Dir: closed.Dir})); !slices.Equal(got, []string{"run exited"}) {
		t.Errorf("an image the machine defines has the steps %q", got)
	}
}

// TestAFetchThatFailsEndsItsStep pins a pull that fails: its line in the step, the step
// failed with -1, the error returned with the engine proxy's password replaced, and an
// image whose user is root a refusal, image_user_root; a pull whose context ends ends
// its step cancelled; the engine proxy takes no connection after either; and a later
// join fetches the image in its image step.
func TestAFetchThatFailsEndsItsStep(t *testing.T) {
	for _, c := range []struct {
		name   string
		err    error
		cancel bool
		state  string
		line   string
	}{
		{"a pull that fails", errors.New("wall docker: docker pull: exit status 1: proxyconnect tcp: http://qory:" + enginePassword + "@127.0.0.1 refused"), false, "failed",
			"wall docker: docker pull: exit status 1: proxyconnect tcp: http://qory:qory-proxy-password@127.0.0.1 refused"},
		{"an image whose user is root", refusals.New(refusals.ImageUserRoot, []string{pinned}, "the image %s runs as root; a run's image runs as the wall's user", pinned), false, "failed",
			"the image " + pinned + " runs as root; a run's image runs as the wall's user: image_user_root: " + pinned},
		{"a pull whose context ends", context.Canceled, true, "cancelled", "context canceled"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, g := specGateway(t, "FAKE_EXIT=0")
			byReference(g)
			addr := freeLoopback(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := &pullingWall{}
			w.during = func(context.Context) error {
				if len(w.pulls) > 1 {
					return nil
				}
				if c.cancel {
					cancel()
				}
				return c.err
			}
			sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
			sp.EngineProxy = &session.EngineProxy{Addr: addr, Password: enginePassword}
			r, err := session.Open(context.Background(), opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			err = r.FetchImage(ctx)
			var ref *session.Refusal
			switch {
			case err == nil:
				t.Fatal("the fetch returned no error")
			case strings.Contains(err.Error(), enginePassword):
				t.Errorf("the error contains the password: %v", err)
			case c.name == "an image whose user is root" && (!errors.As(err, &ref) || ref.Code != refusals.ImageUserRoot):
				t.Errorf("the refusal: %v", err)
			}
			if conn, err := net.Dial("tcp", addr); err == nil {
				conn.Close()
				t.Error("the engine proxy takes a connection after the image step")
			}
			if _, err := r.Join(context.Background(), sp.SessionSpec); err != nil {
				t.Fatal(err)
			}
			closed, err := r.Close(context.Background(), session.Outcome{State: event.StateSucceeded})
			if err != nil {
				t.Fatal(err)
			}
			got := stepOrder(events(t, &session.Result{Dir: closed.Dir}))
			want := []string{"step 1 image " + pinned, "log <nil> 1 " + c.line, "step 1 " + c.state + " -1", "step 2 join join session 1"}
			if len(got) < len(want) || !slices.Equal(got[:len(want)], want) || !slices.Contains(got, "step 3 image "+pinned) {
				t.Errorf("the steps:\n%q\nwant them to start with\n%q\nand the join to fetch the image in step 3", got, want)
			}
			if len(w.pulls) != 2 {
				t.Errorf("the wall pulled %d times, want 2", len(w.pulls))
			}
		})
	}
}

// TestAFetchThatCannotStartWritesNothing pins each error of FetchImage before its step,
// with its text, and that the record then has no step of it: a run without a wall, a
// session that runs, a closed run, a host step that is open, a second fetch, and an
// engine proxy whose address is not a loopback host:port or whose password is empty.
func TestAFetchThatCannotStartWritesNothing(t *testing.T) {
	ctx := context.Background()
	open := func(t *testing.T, change func(*runSpec)) (*session.Run, *pullingWall, runSpec, *linktest.Fake) {
		t.Helper()
		sp, g := specGateway(t, "FAKE_EXIT=0")
		w := &pullingWall{}
		sp.Wall, sp.Image, sp.ImagesAllow = w, "example.com/agent:1", []string{"registry.example/"}
		if change != nil {
			change(&sp)
		}
		if sp.Wall != nil {
			byReference(g)
		}
		r, err := session.Open(ctx, opened(sp))
		if err != nil {
			t.Fatal(err)
		}
		return r, w, sp, g
	}
	closeSteps := func(t *testing.T, r *session.Run) []string {
		t.Helper()
		closed, err := r.Close(ctx, session.Outcome{State: event.StateSucceeded})
		if err != nil {
			t.Fatal(err)
		}
		return stepOrder(events(t, &session.Result{Dir: closed.Dir}))
	}

	t.Run("no wall", func(t *testing.T) {
		r, _, _, _ := open(t, func(sp *runSpec) { sp.Wall, sp.Image, sp.ImagesAllow, sp.Forwarder = nil, "", nil, nil })
		if err := r.FetchImage(ctx); err == nil || err.Error() != "Open the run with a wall to fetch its image: a run without a wall has no image." {
			t.Errorf("FetchImage: %v", err)
		}
		if got := closeSteps(t, r); !slices.Equal(got, []string{"run exited"}) {
			t.Errorf("the steps %q", got)
		}
	})
	t.Run("a session that runs", func(t *testing.T) {
		r, _, sp, g := open(t, nil)
		var during error
		g.OnJoin(func(linktest.Join) linktest.Reply {
			during = r.FetchImage(ctx)
			return linktest.Reply{Status: 200, Body: map[string]any{"version": 1, "session": 1}}
		})
		if _, err := r.Join(ctx, sp.SessionSpec); err != nil {
			t.Fatal(err)
		}
		if during == nil || during.Error() != "Start the image's fetch after Join returns: a session of the run is still running." {
			t.Errorf("FetchImage during the join: %v", during)
		}
		closeSteps(t, r)
	})
	t.Run("a closed run", func(t *testing.T) {
		r, _, _, _ := open(t, nil)
		closeSteps(t, r)
		if err := r.FetchImage(ctx); err == nil || err.Error() != "open a new run for the host step: the run is closed" {
			t.Errorf("FetchImage: %v", err)
		}
	})
	t.Run("an open host step", func(t *testing.T) {
		r, w, _, _ := open(t, nil)
		s, err := r.StartStep(event.StepFetch, "fetch github.com/example-org/app")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.FetchImage(ctx); err == nil || err.Error() != "Exit step 1 before the image's fetch: one host step is open at a time." {
			t.Errorf("FetchImage: %v", err)
		}
		if err := s.Exit(event.StateSucceeded, 0); err != nil {
			t.Fatal(err)
		}
		if got := closeSteps(t, r); !slices.Equal(got, []string{"step 1 fetch fetch github.com/example-org/app", "step 1 succeeded 0", "run exited"}) || len(w.pulls) != 0 {
			t.Errorf("the steps %q, the pulls %+v", got, w.pulls)
		}
	})
	t.Run("a second fetch", func(t *testing.T) {
		r, w, _, _ := open(t, nil)
		if err := r.FetchImage(ctx); err != nil {
			t.Fatal(err)
		}
		if err := r.FetchImage(ctx); err == nil || err.Error() != "Fetch the run's image once: step 1 fetched it." {
			t.Errorf("FetchImage: %v", err)
		}
		if got := closeSteps(t, r); !slices.Equal(got, []string{"step 1 image " + pinned, "step 1 succeeded -1", "run exited"}) || len(w.pulls) != 1 {
			t.Errorf("the steps %q, the pulls %+v", got, w.pulls)
		}
	})
	for _, c := range []struct {
		addr, password, want string
	}{
		{"127.0.0.1", enginePassword, `Set the engine proxy's address to a loopback host:port, such as 127.0.0.1:3129: "127.0.0.1" is not one.`},
		{"192.0.2.1:3129", enginePassword, `Set the engine proxy's address to a loopback host:port, such as 127.0.0.1:3129: "192.0.2.1:3129" is not one.`},
		{"127.0.0.1:0", enginePassword, `Set the engine proxy's address to a loopback host:port, such as 127.0.0.1:3129: "127.0.0.1:0" is not one.`},
		{"localhost:3129", enginePassword, `Set the engine proxy's address to a loopback host:port, such as 127.0.0.1:3129: "localhost:3129" is not one.`},
		{"127.0.0.1:3129", "", "Give the engine proxy the password from the daemon's proxy setting: the password is empty."},
	} {
		t.Run("the engine proxy "+c.addr, func(t *testing.T) {
			r, w, _, _ := open(t, func(sp *runSpec) { sp.EngineProxy = &session.EngineProxy{Addr: c.addr, Password: c.password} })
			if err := r.FetchImage(ctx); err == nil || err.Error() != c.want {
				t.Errorf("FetchImage: %v, want %s", err, c.want)
			}
			if got := closeSteps(t, r); !slices.Equal(got, []string{"run exited"}) || len(w.pulls) != 0 {
				t.Errorf("the steps %q, the pulls %+v", got, w.pulls)
			}
		})
	}
}
