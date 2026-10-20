package run_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/policy"
)

// TestAnAllowFirstEntryCoversACredentialAndAToolUnderEnforce pins the host checks of
// a run under enforce: a credential's host and a tool's host that allow_first lists,
// with no allow entry over them, are covered at the start and at a reload.
func TestAnAllowFirstEntryCoversACredentialAndAToolUnderEnforce(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "a-token")
	cfg := modelConfig()
	cfg.Node.Egress.Allow, cfg.Node.Egress.AllowFirst = []string{"git.example.com"}, []string{"api.model.example"}
	open(t, cfg)

	cfg = toolConfig()
	cfg.Node.Egress.Allow, cfg.Node.Egress.AllowFirst = nil, []string{toolHost}
	open(t, cfg)

	cfg = toolConfig()
	cfg.Node, cfg.Server, cfg.Fetched = nil, true, served(`{"version":1,"egress":{"mode":"enforce","allow":["`+toolHost+`"]},"tools":[{"name":"files","argument":"acme/shop"}]}`, digest('1'))
	r := open(t, cfg)
	d, err := reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow_first":["`+toolHost+`"]},"tools":[{"name":"files","argument":"acme/shop"}]}`, digest('2')))
	if err != nil {
		t.Fatalf("a reload whose allow_first lists the tool's host: %v", err)
	}
	if !slices.Equal(d.Policy.Policy.Egress.AllowFirst, []string{toolHost}) {
		t.Errorf("the reload's allow_first %q", d.Policy.Policy.Egress.AllowFirst)
	}
	d.Discard()
}

// TestTheNodesPolicyKeepsItsSideOverAServersAllowFirst pins a server's allow_first under
// the node's policy: the node's deny still denies an entry, the node's enforce keeps
// only an entry its allow covers, and an entry the node allows lifts the server's deny.
func TestTheNodesPolicyKeepsItsSideOverAServersAllowFirst(t *testing.T) {
	server := `{"version":1,"egress":{"mode":"observe","allow_first":["api.example","b.example"],"deny":["*.example"]}}`
	for _, c := range []struct {
		name string
		node *run.Policy
		want []string
	}{
		{"a node's deny", &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe", Deny: []string{"api.example"}}}, []string{"b.example"}},
		{"a node's enforce", &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"b.example"}}}, []string{"b.example"}},
		{"a node that observes", &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}}, []string{"api.example", "b.example"}},
	} {
		r := open(t, run.Config{RunID: runID, Node: c.node, Fetched: served(server, digest('1'))})
		e := r.Policy().Policy.Egress
		if !slices.Equal(e.AllowFirst, c.want) {
			t.Errorf("%s: allow_first %q, want %q", c.name, e.AllowFirst, c.want)
		}
		if e.Allows("api.example") != slices.Contains(c.want, "api.example") || !e.Allows("b.example") || e.Allows("c.example") {
			t.Errorf("%s: api.example %v, b.example %v, c.example %v", c.name, e.Allows("api.example"), e.Allows("b.example"), e.Allows("c.example"))
		}
	}
}

// TestASessionsNarrowingKeepsTheAllowFirstItAllows pins a session's narrowing of a
// policy with allow_first: an entry the narrowing's deny covers, or its allow does not,
// is dropped; one it allows stays.
func TestASessionsNarrowingKeepsTheAllowFirstItAllows(t *testing.T) {
	pol, err := policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"observe","allow_first":["api.example","b.example"],"deny":["*.example"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		n    *run.Narrowing
		want []string
	}{
		{&run.Narrowing{Deny: []string{"api.example"}}, []string{"b.example"}},
		{&run.Narrowing{Deny: []string{"*.example"}}, nil},
		{&run.Narrowing{Allow: []string{"b.example"}}, []string{"b.example"}},
		{&run.Narrowing{Deny: []string{"tracker.test"}}, []string{"api.example", "b.example"}},
	} {
		if got := run.Narrow(pol, c.n).Policy.Egress.AllowFirst; !slices.Equal(got, c.want) {
			t.Errorf("%+v: allow_first %q, want %q", *c.n, got, c.want)
		}
	}
}

// TestUnderKeepsEachSidesAllowFirst pins a policy's allow_first under a ceiling: each
// side's entries the other side allows, the ceiling's first, an entry lifting the deny
// and allow of the side that lists it alone.
func TestUnderKeepsEachSidesAllowFirst(t *testing.T) {
	mk := func(mode string, first, allow, deny []string) *run.Policy {
		return &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: mode, AllowFirst: first, Allow: allow, Deny: deny}}
	}
	for _, c := range []struct {
		name       string
		p, ceiling *run.Policy
		want       []string
	}{
		{"an observing ceiling without a deny", mk("observe", []string{"api.example"}, nil, []string{"*.example"}), mk("observe", nil, nil, nil), []string{"api.example"}},
		{"a ceiling's deny", mk("observe", []string{"api.example", "b.example"}, nil, []string{"*.example"}), mk("observe", nil, nil, []string{"api.example"}), []string{"b.example"}},
		{"a ceiling that enforces", mk("observe", []string{"api.example", "b.example"}, nil, nil), mk("enforce", nil, []string{"b.example"}, nil), []string{"b.example"}},
		{"a ceiling's entry the policy allows", mk("enforce", nil, []string{"*.example"}, nil), mk("enforce", []string{"api.example", "other.test"}, nil, []string{"*.example"}), []string{"api.example"}},
		{"a ceiling's entry under the policy's deny", mk("observe", nil, nil, []string{"api.example"}), mk("observe", []string{"api.example"}, nil, []string{"*.example"}), nil},
	} {
		got := c.p.Under(c.ceiling)
		if !slices.Equal(got.Egress.AllowFirst, c.want) {
			t.Errorf("%s: allow_first %q, want %q", c.name, got.Egress.AllowFirst, c.want)
		}
	}
	p, err := run.ReadPolicy("run.yaml", []byte("version: 1\negress:\n  mode: enforce\n  allow_first: [api.example]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.Egress.AllowFirst, " ") != "api.example" {
		t.Errorf("allow_first read as %v", p.Egress.AllowFirst)
	}
}

// TestAGuardNameOpensForAnAllowFirstEntry pins that a node's allow entry that names a
// host is a guard name when the run's policy lists the host in allow_first alone.
func TestAGuardNameOpensForAnAllowFirstEntry(t *testing.T) {
	node, err := policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"enforce","allow":["nas","other.example"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"enforce","allow_first":["nas"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := run.GuardNames(node, pol, nil); !slices.Equal(got, []string{"nas"}) {
		t.Errorf("guard names %q, want [nas]", got)
	}
}
