package run_test

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
)

// pathHost is the host the tests of this file request: a tool serves it, so the proxy
// never dials it.
const pathHost = "api.example"

// serving answers every request on a Unix socket with 200, standing in for the host.
func serving(t *testing.T) string {
	t.Helper()
	// A socket path has a short limit on some systems; the test's directory can exceed it.
	dir, err := os.MkdirTemp("", "qu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// underProxy is the proxy of a run whose node's policy is p, as the gateway sets it up
// for the run behind a wall, with a tool serving pathHost; and what it records.
func underProxy(t *testing.T, p *run.Policy, sock string) (*proxy.Proxy, func() proxy.Decision) {
	t.Helper()
	return proxyOf(t, open(t, run.Config{RunID: runID, Node: p, Wall: true}), sock)
}

// proxyOf is the proxy of a run as the gateway sets it up for the run behind a wall,
// with a tool serving pathHost; and what it records.
func proxyOf(t *testing.T, r *run.Run, sock string) (*proxy.Proxy, func() proxy.Decision) {
	t.Helper()
	pol := r.Policy()
	var mu sync.Mutex
	var last proxy.Decision
	px, err := proxy.New(pol.Policy.Egress.Mode, pol.Policy.Egress.Allow, pol.Policy.Egress.Deny, func(d proxy.Decision) {
		mu.Lock()
		defer mu.Unlock()
		last = d
	})
	if err != nil {
		t.Fatal(err)
	}
	if sides := r.NodePaths(); len(sides) > 0 {
		px.NodePaths(sides...)
	}
	ca, err := proxy.NewCA(runID)
	if err != nil {
		t.Fatal(err)
	}
	px.Terminate(ca, nil, pol.Policy.Egress.Paths, []proxy.Tool{{Name: "host", Hosts: []string{pathHost}, Socket: sock}})
	return px, func() proxy.Decision {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

// TestUnderHoldsEachSidesPathsApart pins the path rules of a policy put under a
// ceiling, in each of the four combinations of modes: each side's rules hold apart,
// the entry of each that holds the host deciding, so a request to a host either side
// lists must match an entry of each side that lists it. A miss is denied under enforce
// and passed under observe, recorded with no rule either way; a path both sides match
// passes with the narrowest entry as its rule; and an empty list on either side holds
// the host to no path.
func TestUnderHoldsEachSidesPathsApart(t *testing.T) {
	sock := serving(t)
	mk := func(mode string, allow []string, paths map[string][]string) *run.Policy {
		return &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: mode, Allow: allow, Paths: paths}}
	}
	type request struct {
		path, rule string
		both       bool
	}
	scenarios := []struct {
		name                   string
		ceilingPaths, ownPaths map[string][]string
		requests               []request
	}{
		{"overlapping keys", map[string][]string{"*.example": {"/v1/*"}}, map[string][]string{pathHost: {"/v2/*"}}, []request{
			{"/v1/x", "", false},
			{"/v2/x", "", false},
		}},
		{"one key, the ceiling narrower", map[string][]string{pathHost: {"/v1/repos/*"}}, map[string][]string{pathHost: {"/v1/*"}}, []request{
			{"/v1/repos/x", "/v1/repos/*", true},
			{"/v1/other", "", false},
		}},
		{"the run narrower under a wildcard", map[string][]string{"*.example": {"/v1/*"}}, map[string][]string{pathHost: {"/v1/repos/*"}}, []request{
			{"/v1/repos/x", "/v1/repos/*", true},
			{"/v1/other", "", false},
		}},
		{"the ceiling's empty list", map[string][]string{pathHost: {}}, map[string][]string{pathHost: {"/v1/*"}}, []request{
			{"/v1/x", "", false},
			{"/", "", false},
		}},
		{"the run's empty list", map[string][]string{"*.example": {"/v1/*"}}, map[string][]string{pathHost: {}}, []request{
			{"/v1/x", "", false},
			{"/", "", false},
		}},
		{"the ceiling's side alone", map[string][]string{"*.example": {"/v1/*"}}, nil, []request{
			{"/v1/x", "/v1/*", true},
			{"/v2/x", "", false},
		}},
		{"the run's side alone", nil, map[string][]string{pathHost: {"/v2/*"}}, []request{
			{"/v2/x", "/v2/*", true},
			{"/v1/x", "", false},
		}},
	}
	for _, modes := range [][2]string{{"observe", "observe"}, {"observe", "enforce"}, {"enforce", "observe"}, {"enforce", "enforce"}} {
		for _, s := range scenarios {
			ceiling := mk(modes[0], []string{"*.example"}, s.ceilingPaths)
			p := mk(modes[1], []string{pathHost}, s.ownPaths)
			under := p.Under(ceiling)
			enforced := modes[0] == "enforce" || modes[1] == "enforce"
			if got := under.Egress.Mode == "enforce"; got != enforced {
				t.Fatalf("ceiling %s, run %s: mode %s", modes[0], modes[1], under.Egress.Mode)
			}
			px, last := underProxy(t, under, sock)
			for range 50 {
				for _, req := range s.requests {
					w := httptest.NewRecorder()
					px.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://"+pathHost+req.path, nil))
					d := last()
					wantCode := http.StatusOK
					if !req.both && enforced {
						wantCode = http.StatusForbidden
					}
					if w.Code != wantCode || d.Path != req.path || d.PathRule != req.rule || d.Allowed != (wantCode == http.StatusOK) {
						t.Fatalf("ceiling %s, run %s, %s: %s answered %d, recorded %+v; want %d with the rule %q",
							modes[0], modes[1], s.name, req.path, w.Code, d, wantCode, req.rule)
					}
				}
			}
		}
	}
}

// first is the first path of a host's entry, empty when there is none.
func first(paths map[string][]string, host string) string {
	if len(paths[host]) == 0 {
		return ""
	}
	return paths[host][0]
}

// TestUnderKeepsTheCeilingsPathsBesideThePolicys pins where the sides go: the run's
// policy holds its paths, and the ceiling's are beside it, without a server as with
// one, whatever the modes; a ceiling with no paths adds no side; and a run without a
// wall whose ceiling has paths is refused, as one whose policy has them is.
func TestUnderKeepsTheCeilingsPathsBesideThePolicys(t *testing.T) {
	ceilingPaths := map[string][]string{"*.example": {"/v1/*"}}
	ownPaths := map[string][]string{pathHost: {"/v2/*"}}
	for _, modes := range [][2]string{{"observe", "observe"}, {"observe", "enforce"}, {"enforce", "observe"}, {"enforce", "enforce"}} {
		ceiling := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: modes[0], Allow: []string{"*.example"}, Paths: ceilingPaths}}
		p := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: modes[1], Allow: []string{pathHost}, Paths: ownPaths}}
		under := p.Under(ceiling)
		if len(under.Egress.Paths) != 1 || first(under.Egress.Paths, pathHost) != "/v2/*" {
			t.Errorf("ceiling %s, run %s: the policy's paths %v", modes[0], modes[1], under.Egress.Paths)
		}
		r := open(t, run.Config{RunID: runID, Node: under, Wall: true})
		if sides := r.NodePaths(); len(sides) != 1 || first(sides[0], "*.example") != "/v1/*" || !r.NeedsCA() {
			t.Errorf("ceiling %s, run %s: beside %v, authority %v", modes[0], modes[1], sides, r.NeedsCA())
		}
		fetched := served(`{"version":1,"egress":{"mode":"observe"}}`, digest('1'))
		r = open(t, run.Config{RunID: runID, Node: under, Wall: true, Fetched: fetched})
		if sides := r.NodePaths(); len(sides) != 2 || first(sides[0], pathHost) != "/v2/*" || first(sides[1], "*.example") != "/v1/*" {
			t.Errorf("ceiling %s, run %s, with a server: beside %v", modes[0], modes[1], sides)
		}
		bare := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: modes[1], Allow: []string{pathHost}}}
		_, err := run.Decide(run.Config{RunID: runID, Node: bare.Under(ceiling)})
		if err == nil || !strings.Contains(err.Error(), "run it with a wall") {
			t.Errorf("ceiling %s, run %s: the ceiling's paths without a wall: %v", modes[0], modes[1], err)
		}
		var nw *refusal.NeedsWall
		if !errors.As(err, &nw) || len(nw.Names) != 1 || nw.Names[0] != "paths" {
			t.Errorf("ceiling %s, run %s: refused as %v", modes[0], modes[1], nw)
		}
		plain := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: modes[0], Allow: []string{"*.example"}}}
		r = open(t, run.Config{RunID: runID, Node: p.Under(plain), Wall: true})
		if sides := r.NodePaths(); sides != nil {
			t.Errorf("ceiling %s, run %s: a ceiling with no paths put %v beside", modes[0], modes[1], sides)
		}
	}
	p := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: string(policy.Enforce), Allow: []string{pathHost}, Paths: ownPaths}}
	if got := p.Under(&run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: string(policy.Observe)}}); got != p {
		t.Errorf("a ceiling with nothing to add changed the policy: %+v", got)
	}
}

// TestARunHoldsItsCopyOfTheCeilingsPaths pins that a run holds the path rules a
// ceiling puts beside its policy as they are when it starts: a change to the ceiling's
// maps after the start, a path of a host replaced, a path appended to a host's and a
// host added, leaves the run's sides, the proxy's rules and the sides the record lists
// as they were, with a server and without.
func TestARunHoldsItsCopyOfTheCeilingsPaths(t *testing.T) {
	sock := serving(t)
	want := []map[string][]string{{pathHost: {"/v1/*", "/v3/*"}}}
	for _, fetched := range []*run.Fetched{nil, served(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, digest('1'))} {
		paths := map[string][]string{pathHost: {"/v1/*", "/v3/*"}}
		ceiling := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"*.example"}, Paths: paths}}
		under := (&run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{pathHost}}}).Under(ceiling)
		r := open(t, run.Config{RunID: runID, Node: under, Wall: true, Fetched: fetched})
		px, _ := proxyOf(t, r, sock)
		paths[pathHost][0] = "/v2/*"
		paths[pathHost] = append(paths[pathHost], "/v4/*")
		paths["b.example"] = []string{"/x/*"}
		if got := r.NodePaths(); !reflect.DeepEqual(got, want) {
			t.Errorf("server %v: the run's sides %v, want %v", fetched != nil, got, want)
		}
		if got := r.Beside(); !reflect.DeepEqual(got, want) {
			t.Errorf("server %v: the sides the record lists %v, want %v", fetched != nil, got, want)
		}
		for path, code := range map[string]int{"/v1/x": http.StatusOK, "/v3/x": http.StatusOK, "/v2/x": http.StatusForbidden, "/v4/x": http.StatusForbidden} {
			w := httptest.NewRecorder()
			px.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://"+pathHost+path, nil))
			if w.Code != code {
				t.Errorf("server %v: %s answered %d, want %d", fetched != nil, path, w.Code, code)
			}
		}
	}
}

// badCeilingPaths are path rules the schema refuses: a host with a trailing dot, a bare
// wildcard, a host in capitals beside the same host in lower case, a path not from the
// root.
var badCeilingPaths = map[string]map[string][]string{
	"a trailing dot":  {"api.example.": {"/v1/*"}},
	"a bare wildcard": {"*": {"/v1/*"}},
	"capitals":        {"API.EXAMPLE": {"/v1/*"}, pathHost: {}},
	"a relative path": {pathHost: {"v1"}},
}

// TestUnderChecksTheCeilingsPaths pins that the path rules a ceiling puts beside a
// policy are checked against the schema as the policy is, in each combination of
// modes: a side the schema refuses is a policy error and no run, with a wall or without.
func TestUnderChecksTheCeilingsPaths(t *testing.T) {
	for _, modes := range [][2]string{{"observe", "observe"}, {"observe", "enforce"}, {"enforce", "observe"}, {"enforce", "enforce"}} {
		for name, paths := range badCeilingPaths {
			ceiling := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: modes[0], Allow: []string{"*.example"}, Paths: paths}}
			p := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: modes[1], Allow: []string{pathHost}, Paths: map[string][]string{pathHost: {"/v1/*"}}}}
			under := p.Under(ceiling)
			if err := run.CheckBeside(under); err == nil {
				t.Errorf("ceiling %s, run %s, %s: checked", modes[0], modes[1], name)
			}
			for _, wall := range []bool{true, false} {
				_, err := run.Decide(run.Config{RunID: runID, Node: under, Wall: wall})
				var pe *policy.Error
				if !errors.As(err, &pe) {
					t.Errorf("ceiling %s, run %s, %s, wall %v: %v, want a policy error", modes[0], modes[1], name, wall, err)
				}
			}
		}
	}
	good := (&run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{pathHost}}}).Under(
		&run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe", Paths: map[string][]string{"*.example": {"/v1/*"}, pathHost: {}}}})
	if err := run.CheckBeside(good); err != nil {
		t.Errorf("rules the schema takes: %v", err)
	}
}
