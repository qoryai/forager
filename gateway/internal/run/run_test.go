package run_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// The tests of this file feed the inputs the session's tests feed session.Run, and pin
// what this package computes of them: the session test each is ported from is named
// above it.

const (
	runID    = "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f"
	runURL   = "https://apiary.example/v1/run-configuration"
	toolHost = "files.tools.internal"
)

func digest(c byte) string { return "sha256=" + strings.Repeat(string(c), 64) }

// served is a run configuration whose security_policy is the policy document given.
func served(securityPolicy string, d string) *run.Fetched {
	return &run.Fetched{URL: runURL, Digest: d, Document: &server.RunConfiguration{Version: 1, SecurityPolicy: json.RawMessage(securityPolicy)}}
}

// document is a run configuration document as given.
func document(t *testing.T, doc string, d string) *run.Fetched {
	t.Helper()
	var rc server.RunConfiguration
	if err := json.Unmarshal([]byte(doc), &rc); err != nil {
		t.Fatal(err)
	}
	return &run.Fetched{URL: runURL, Digest: d, Document: &rc}
}

// reports collects what a run reports.
type reports struct {
	mu   sync.Mutex
	said []string
}

func (r *reports) report(l string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.said = append(r.said, l)
}

func (r *reports) reported(text string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.ContainsFunc(r.said, func(l string) bool { return strings.Contains(l, text) })
}

// reload reads a run configuration and decides it, as the session's reload does.
func reload(t *testing.T, r *run.Run, f *run.Fetched) (*run.Decision, error) {
	t.Helper()
	next, err := r.Read(*f)
	if err != nil {
		return nil, err
	}
	return r.Reload(context.Background(), next)
}

// open opens a run, failing the test when it does not.
func open(t *testing.T, cfg run.Config) *run.Run {
	t.Helper()
	r, err := run.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func refusalOf(err error) (string, []string) {
	var r *accesskey.Refusal
	if !errors.As(err, &r) {
		return "", nil
	}
	return r.Code, r.Names
}

// From session_test.go TestNoPolicyObservesAndNoServerNeedsNoPing and
// TestRunEnforcesRecordsAndExitsWithTheRuntimesStatus: no policy is none, mode
// observe, with no digest; the node's own is the run's, source config, with its digest.
func TestNoPolicyObservesAndTheNodesIsTheRuns(t *testing.T) {
	r := open(t, run.Config{RunID: runID})
	if p := r.Policy(); p.Source != "none" || p.Policy.Egress.Mode != policy.Observe || r.Digest() != "" || r.NeedsCA() || r.NodePaths() != nil {
		t.Errorf("no policy: %+v, digest %q", p, r.Digest())
	}
	node := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1"}}}
	r = open(t, run.Config{RunID: runID, Node: node})
	b, _ := json.Marshal(node)
	want, err := policy.Read("policy", b)
	if err != nil {
		t.Fatal(err)
	}
	if p := r.Policy(); p.Source != "config" || r.Digest() != want.Digest || p.Canonical != want.Canonical || fmt.Sprint(p.Policy.Egress.Allow) != "[127.0.0.1]" {
		t.Errorf("the node's policy: %+v, digest %q", p, r.Digest())
	}
	if _, err := run.Decide(run.Config{Node: &run.Policy{Version: 2, Egress: run.PolicyEgress{Mode: "observe"}}}); err == nil {
		t.Error("a policy the schema refuses was decided")
	}
}

// From session_test.go TestRunConfigurationIsThePolicyAndReloadsOnTheDigest: the run
// configuration's policy is the run's, over the node's own, with the source fetched
// and both digests; another one in force is put in force with its own digest.
func TestRunConfigurationIsThePolicyAndReloadsOnTheDigest(t *testing.T) {
	first, second := digest('1'), digest('2')
	labels := map[string]string{"forge": "example-forge", "issue": "77", "repository": "example-namespace/project"}
	r := open(t, run.Config{
		RunID: runID, Server: true, Labels: labels,
		Node:    &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}},
		Fetched: served(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, first),
	})
	at := r.Policy()
	if at.Source != "fetched" || at.Policy.Egress.Mode != policy.Enforce || fmt.Sprint(at.Policy.Egress.Allow) != "[127.0.0.1]" || at.RunConfiguration != first || at.URL != runURL || r.Digest() == "" {
		t.Errorf("the first policy %+v", at)
	}
	if !maps.Equal(r.Labels(), labels) || r.RunConfiguration() != first {
		t.Errorf("labels %v, run configuration %q", r.Labels(), r.RunConfiguration())
	}
	d, err := reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":[]}}`, second))
	if err != nil {
		t.Fatal(err)
	}
	if d.Unchanged || d.Policy.Source != "fetched" || fmt.Sprint(d.Policy.Policy.Egress.Allow) != "[]" || d.Policy.RunConfiguration != second || d.Policy.Digest == at.Digest {
		t.Errorf("the reload's decision %+v", d.Policy)
	}
	if r.Policy() != at {
		t.Error("a decision was put in force before it was committed")
	}
	r.Commit(d)
	if r.Policy() != d.Policy || r.RunConfiguration() != second || r.Digest() != d.Policy.Digest {
		t.Errorf("after the commit %+v", r.Policy())
	}
}

// From variables_test.go TestTheNodesPolicyNarrowsTheServers: the hosts both allow,
// the node's policy by its digest beside, and a run configuration without a policy
// leaves the node's in force with the run configuration's URL and digest beside it.
func TestTheNodesPolicyNarrowsTheServers(t *testing.T) {
	node := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"127.0.0.1"}}}
	r := open(t, run.Config{RunID: runID, Node: node, Fetched: served(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1","localhost"]}}`, digest('1'))})
	p := r.Policy()
	if p.Source != "fetched" || fmt.Sprint(p.Policy.Egress.Allow) != "[127.0.0.1]" || p.RunConfiguration != digest('1') || p.Node == nil || !regexp.MustCompile(`^sha256=[0-9a-f]{64}$`).MatchString(p.Node.Digest) {
		t.Errorf("narrowed %+v", p)
	}

	r = open(t, run.Config{RunID: runID, Node: node, Fetched: document(t, `{"version":1,"variables":{"NODE_ENV":{"value":"test"}}}`, digest('1'))})
	p = r.Policy()
	if p.Source != "config" || fmt.Sprint(p.Policy.Egress.Allow) != "[127.0.0.1]" || p.RunConfiguration != digest('1') || p.URL != runURL || p.Node != nil {
		t.Errorf("without a server's policy %+v", p)
	}
	if !maps.Equal(r.Variables(), map[string]string{"NODE_ENV": "test"}) {
		t.Errorf("the server's variables %v", r.Variables())
	}
}

// From variables_test.go TestANarrowingThatRefusesIsNoRun: a tool the server selects
// that the node's policy does not list is tool_unknown, a server's image other than
// the node's is image_unknown, and a security_policy the schema refuses is
// run_configuration_invalid. The session test's third case, a variable the schema
// refuses, is the server client's to refuse, before this package reads the document.
func TestANarrowingThatRefusesIsNoRun(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		node      *run.Policy
		code      string
	}{
		{"a tool", `{"version":1,"security_policy":{"version":1,"egress":{"mode":"observe"},"tools":[{"name":"files"}]}}`,
			&run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}, Tools: []run.PolicyTool{}}, "tool_unknown"},
		{"an image", `{"version":1,"security_policy":{"version":1,"egress":{"mode":"observe"},"image":"with-docker"}}`,
			&run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}, Image: "base"}, "image_unknown"},
		{"a policy", `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.example:443"]}}}`, nil, "run_configuration_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run.Open(context.Background(), run.Config{
				RunID: runID, Node: tc.node, Wall: true, Fetched: document(t, tc.doc, digest('1')),
				Tools: []run.Tool{{Name: "files", Command: []string{"/bin/true"}, Serves: []string{"files.internal"}}},
			})
			if code, _ := refusalOf(err); code != tc.code {
				t.Fatalf("%v, want %s", err, tc.code)
			}
			if !strings.Contains(err.Error(), "run configuration "+runURL) {
				t.Errorf("the error does not name the run configuration: %v", err)
			}
			if !run.Settled(err) {
				t.Errorf("%v is not settled", err)
			}
		})
	}
	// A server's credential the node's policy does not list is refused without a code,
	// so a reload asks for it again on the next answer, as today.
	_, err := run.Decide(run.Config{
		Node: &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}, Credentials: []run.PolicyCredential{}}, Wall: true,
		Fetched: served(`{"version":1,"egress":{"mode":"observe"},"credentials":[{"name":"model"}]}`, digest('1')),
	})
	if err == nil || !strings.Contains(err.Error(), "which the node's policy does not list") || run.Settled(err) {
		t.Errorf("a credential the node does not list: %v, settled %v", err, run.Settled(err))
	}
}

// From session.go's reload (reload.go pass): which failed fetches are asked for again.
func TestSettledIsWhatTheServerAnsweredAndForagerRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"a document error", &server.DocumentError{}, true},
		{"a policy error", &policy.Error{Name: "run-configuration", Err: errors.New("no")}, true},
		{"a refusal Forager decides", fmt.Errorf("wrapped: %w", &accesskey.Refusal{Code: "tool_unknown"}), true},
		{"a server's refusal", &accesskey.Refusal{Code: "rate_limited", Status: 429}, false},
		{"a network error", errors.New("connection refused"), false},
	} {
		if got := run.Settled(c.err); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// From session_test.go TestAReloadIsAsStrictAsAStart: an unwalled run with a server
// has the run's authority from the start; a reload that brings path rules, which need
// a wall, fails, and the policy in force stays, though the run has an authority; a
// reload that selects a credential puts it in force; and a run configuration that is
// the one in force is not put in force again.
func TestAReloadIsAsStrictAsAStart(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	var said reports
	r := open(t, run.Config{RunID: runID, Server: true, Report: said.report, Fetched: served(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, digest('1')),
		Credentials: []run.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.example"}, Scheme: "bearer"}}})
	if !r.NeedsCA() {
		t.Fatal("an unwalled run with a server has no authority")
	}

	paths := `{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1","api.example"],"paths":{"127.0.0.1":["/ok/*"]}}}`
	_, err := reload(t, r, served(paths, digest('2')))
	var nw *refusal.NeedsWall
	if !errors.As(err, &nw) || !slices.Equal(nw.Names, []string{"paths"}) || !strings.Contains(err.Error(), "run it with a wall") ||
		!strings.Contains(err.Error(), "run configuration "+runURL+": ") || !strings.HasSuffix(err.Error(), "; the policy in force stays") {
		t.Errorf("path rules without a wall: %v", err)
	}
	if r.RunConfiguration() != digest('1') || fmt.Sprint(r.Policy().Policy.Egress.Allow) != "[127.0.0.1]" {
		t.Errorf("the policy in force after a failed reload %+v", r.Policy())
	}

	creds := `{"version":1,"egress":{"mode":"enforce","allow":["api.example"]},"credentials":[{"name":"model"}]}`
	d, err := reload(t, r, served(creds, digest('3')))
	if err != nil {
		t.Fatal(err)
	}
	if !d.CredentialsChanged || len(d.Uses) != 1 || d.Uses[0].Name != "model" || d.Policy.RunConfiguration != digest('3') {
		t.Errorf("a credential without a wall: changed %v, uses %v", d.CredentialsChanged, d.Uses)
	}
	r.Commit(d)

	// The document in force, under its own digest: nothing is put in force.
	d, err = reload(t, r, served(creds, digest('3')))
	if err != nil || !d.Unchanged {
		t.Errorf("the run configuration in force: %+v, %v", d, err)
	}
	if len(said.said) != 0 {
		t.Errorf("the user was told %v", said.said)
	}
}

// toolConfig is session/tool_test.go's toolSpec: a walled run whose policy selects a
// tool with an argument and path rules for its host.
func toolConfig() run.Config {
	return run.Config{
		RunID: runID, Wall: true,
		Node: &run.Policy{Version: 1,
			Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{toolHost}, Paths: map[string][]string{toolHost: {"/media/acme/shop/*"}}},
			Tools:  []run.PolicyTool{{Name: "files", Argument: "acme/shop"}}},
		Tools: []run.Tool{{Name: "files", Command: []string{"/bin/sh", "-c", "exit 0"}, Argument: `[a-z]+/[a-z]+`, Serves: []string{toolHost}, Placeholders: []string{"FILES_KEY"}}},
	}
}

// From tool_test.go TestARunWhoseToolsCannotHoldDoesNotStart: no wall, a tool nobody
// defined, an argument the machine does not provide for, a host a credential is for
// as well, a value the run passes for a placeholder, and a tool that does not listen.
func TestARunWhoseToolsCannotHoldDoesNotStart(t *testing.T) {
	t.Setenv("QORY_TEST_FILES_TOKEN", "a-token")
	r := open(t, toolConfig())
	if !r.NeedsCA() || !slices.Equal(r.ToolPlaceholders(), []string{"FILES_KEY"}) || len(r.Chosen()) != 1 || r.Chosen()[0].Argument != "acme/shop" {
		t.Errorf("the tool's run: authority %v, placeholders %v, chosen %+v", r.NeedsCA(), r.ToolPlaceholders(), r.Chosen())
	}
	for name, c := range map[string]struct {
		change func(*run.Config)
		want   string
		code   string
	}{
		"no wall":                      {func(c *run.Config) { c.Wall = false }, "run it with a wall", ""},
		"a tool nobody defined":        {func(c *run.Config) { c.Tools = nil }, "does not define", "tool_unknown"},
		"an argument not provided for": {func(c *run.Config) { c.Node.Tools[0].Argument = "acme/shop/x" }, "not one the machine provides for", ""},
		"a host a credential is for": {func(c *run.Config) {
			c.Credentials = []run.Credential{{Name: "files-token", Env: "QORY_TEST_FILES_TOKEN", Hosts: []string{toolHost}, Scheme: "bearer"}}
			c.Node.Credentials = []run.PolicyCredential{{Name: "files-token"}}
		}, "both claim", ""},
		"a value for the placeholder": {func(c *run.Config) { c.Passes = func(name string) bool { return name == "FILES_KEY" } }, "placeholder of a tool", "placeholder_conflict"},
	} {
		cfg := toolConfig()
		c.change(&cfg)
		_, err := run.Open(context.Background(), cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
		if code, _ := refusalOf(err); code != c.code {
			t.Errorf("%s: the code %q, want %q", name, code, c.code)
		}
	}
	cfg := toolConfig()
	cfg.Tools[0].Command = []string{"/bin/sh", "-c", "echo no key for the store >&2; exit 4"}
	r = open(t, cfg)
	if set, err := r.StartTools(context.Background()); err == nil || !strings.Contains(err.Error(), "no key for the store") {
		if set != nil {
			set.Close()
		}
		t.Errorf("a tool that does not listen: %v", err)
	}
}

// From tool_test.go TestAReloadKeepsTheRunsTools: a run configuration that selects
// other tools fails the reload, and one that selects the same tools takes effect.
func TestAReloadKeepsTheRunsTools(t *testing.T) {
	withTools := `{"version":1,"egress":{"mode":"enforce","allow":["` + toolHost + `"%s]},"tools":[{"name":"files","argument":"acme/shop"}]}`
	cfg := toolConfig()
	cfg.Node, cfg.Server, cfg.Fetched = nil, true, served(fmt.Sprintf(withTools, ""), digest('1'))
	r := open(t, cfg)

	if _, err := reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["`+toolHost+`"]}}`, digest('2'))); err == nil || !strings.Contains(err.Error(), "other tools than the run started with") {
		t.Errorf("other tools: %v", err)
	}
	d, err := reload(t, r, served(fmt.Sprintf(withTools, `,"api.model.example"`), digest('3')))
	if err != nil {
		t.Fatal(err)
	}
	r.Commit(d)
	if r.RunConfiguration() != digest('3') || len(r.Chosen()) != 1 {
		t.Errorf("the reload with the same tools: %q, %+v", r.RunConfiguration(), r.Chosen())
	}
	// A tool the reload's allow list does not cover is refused as at the start.
	if _, err := reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"tools":[{"name":"files","argument":"acme/shop"}]}`, digest('4'))); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Errorf("a tool's host outside the allow list: %v", err)
	}
}

// modelConfig is session/wall_test.go's TestCredentialsCrossAsAnAuthorityAndAPlaceholder:
// a walled run whose policy selects a credential read from a variable, with path rules.
func modelConfig() run.Config {
	return run.Config{
		RunID: runID, Wall: true,
		Credentials: []run.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_TOKEN"}}},
		Node: &run.Policy{Version: 1,
			Egress:      run.PolicyEgress{Mode: "enforce", Allow: []string{"api.model.example", "git.example.com"}, Paths: map[string][]string{"git.example.com": {"/acme/*"}}},
			Credentials: []run.PolicyCredential{{Name: "model"}}},
	}
}

// From wall_test.go TestCredentialsCrossAsAnAuthorityAndAPlaceholder: a credential
// means the run's authority and a placeholder, the gateway holds its token, and the
// runs that do not start.
func TestCredentialsCrossAsAnAuthorityAndAPlaceholder(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	r := open(t, modelConfig())
	uses := r.Uses()
	if !r.NeedsCA() || !slices.Equal(r.CredentialPlaceholders(), []string{"MODEL_TOKEN"}) || len(uses) != 1 || uses[0].Scheme != "bearer" || uses[0].Token() != "the-token-held-outside" {
		t.Errorf("authority %v, placeholders %v, uses %+v", r.NeedsCA(), r.CredentialPlaceholders(), uses)
	}
	if !slices.Equal(r.Reserved(), []string{"QORY_TEST_MODEL_TOKEN"}) {
		t.Errorf("reserved %v", r.Reserved())
	}
	for name, c := range map[string]struct {
		change func(*run.Config)
		code   string
	}{
		"no wall":                            {func(c *run.Config) { c.Wall = false }, ""},
		"a credential nobody defined":        {func(c *run.Config) { c.Credentials = nil }, ""},
		"a value passed for the placeholder": {func(c *run.Config) { c.Passes = func(name string) bool { return name == "MODEL_TOKEN" } }, "placeholder_conflict"},
	} {
		cfg := modelConfig()
		c.change(&cfg)
		_, err := run.Open(context.Background(), cfg)
		if err == nil {
			t.Errorf("%s: the run opened", name)
		}
		if code, _ := refusalOf(err); code != c.code {
			t.Errorf("%s: the code %q, want %q", name, code, c.code)
		}
	}
}

// From wall_test.go TestAReloadBehindAWallBringsCredentialsAndPaths: behind a wall a
// run with a server always has its authority, so a reload's path rules are held and
// its credentials resolved; a credential nobody defined fails the reload and the
// policy in force stays.
func TestAReloadBehindAWallBringsCredentialsAndPaths(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	r := open(t, run.Config{
		RunID: runID, Wall: true, Server: true,
		Credentials: []run.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"}},
		Fetched:     served(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}}`, digest('1')),
	})
	if !r.NeedsCA() || len(r.Uses()) != 0 {
		t.Errorf("a walled run with a server: authority %v, uses %v", r.NeedsCA(), r.Uses())
	}
	d, err := reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example","git.example.com"],"paths":{"git.example.com":["/acme/*"]}},"credentials":[{"name":"model"}]}`, digest('2')))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Uses) != 1 || d.Uses[0].Name != "model" || d.Policy.Policy.Egress.Paths == nil || !d.CredentialsChanged || d.Image != (run.Image{Ref: ""}) {
		t.Errorf("the decision %+v", d)
	}
	r.Commit(d)
	if len(r.Uses()) != 1 || r.RunConfiguration() != digest('2') {
		t.Errorf("after the commit: uses %v, %q", r.Uses(), r.RunConfiguration())
	}
	_, err = reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"credentials":[{"name":"nobody-defined"}]}`, digest('3')))
	if err == nil || !strings.Contains(err.Error(), "the policy in force stays") {
		t.Errorf("a credential nobody defined: %v", err)
	}
	if r.RunConfiguration() != digest('2') || len(r.Uses()) != 1 {
		t.Errorf("the policy in force after a failed reload: %q, uses %v", r.RunConfiguration(), r.Uses())
	}
	// A value the run passes for a placeholder a reload brings is refused as at a
	// start.
	cfg := run.Config{
		RunID: runID, Wall: true, Server: true, Passes: func(name string) bool { return name == "MODEL_TOKEN" },
		Credentials: []run.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_TOKEN"}}},
		Fetched:     served(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}}`, digest('1')),
	}
	r = open(t, cfg)
	_, err = reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"credentials":[{"name":"model"}]}`, digest('2')))
	if code, names := refusalOf(err); code != "placeholder_conflict" || !slices.Equal(names, []string{"MODEL_TOKEN"}) {
		t.Errorf("a placeholder the run passes a value for, at a reload: %v", err)
	}
}

// From wall_test.go TestPrepareIsGivenTheStandInsOfAWalledRun: the placeholders are a
// credential's and then a tool's; without a wall there are none.
func TestThePlaceholdersAreTheCredentialsThenTheTools(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	cfg := toolConfig()
	cfg.Credentials = []run.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_TOKEN"}}}
	cfg.Node.Credentials = []run.PolicyCredential{{Name: "model"}}
	cfg.Node.Egress.Allow = append(cfg.Node.Egress.Allow, "api.model.example")
	r := open(t, cfg)
	if want := []string{"MODEL_TOKEN", "FILES_KEY"}; !slices.Equal(r.Placeholders(), want) {
		t.Errorf("placeholders %v, want %v", r.Placeholders(), want)
	}
	if err := r.Conflict(func(name string) bool { return name == "FILES_KEY" }); err == nil || !strings.Contains(err.Error(), "placeholder of a tool") {
		t.Errorf("the tool's placeholder passed: %v", err)
	}
	if err := r.Conflict(func(name string) bool { return true }); err == nil || !strings.Contains(err.Error(), "placeholder of a credential") {
		t.Errorf("both placeholders passed: %v", err)
	}
	if err := r.Conflict(func(string) bool { return false }); err != nil {
		t.Errorf("no placeholder passed: %v", err)
	}
	r = open(t, run.Config{RunID: runID})
	if len(r.Placeholders()) != 0 {
		t.Errorf("placeholders without a wall %v", r.Placeholders())
	}
}

// From variables_test.go TestWhatARunPassesInIsChecked: a placeholder the run passes a
// value for, from any source the session counts, is placeholder_conflict naming it.
// The session's variable_reserved cases are its own variable resolution.
func TestWhatARunPassesInIsChecked(t *testing.T) {
	t.Setenv("MODEL_SOURCE", "the-credential-held-outside")
	_, err := run.Open(context.Background(), run.Config{
		RunID: runID, Wall: true, Passes: func(name string) bool { return name == "MODEL_TOKEN" },
		Node:        &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}, Credentials: []run.PolicyCredential{{Name: "model"}}},
		Credentials: []run.Credential{{Name: "model", Env: "MODEL_SOURCE", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_TOKEN"}}},
	})
	if code, names := refusalOf(err); code != "placeholder_conflict" || !slices.Equal(names, []string{"MODEL_TOKEN"}) {
		t.Fatalf("%v, want placeholder_conflict [MODEL_TOKEN]", err)
	}
	if strings.Contains(err.Error(), "the-credential-held-outside") {
		t.Errorf("the error quotes a value: %v", err)
	}
}

// images are image_test.go's: the machine's definitions the tests below select among.
var images = []run.Image{
	{Name: "base", Ref: "example.com/agent:1"},
	{Name: "with-docker", Ref: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true},
}

// From image_test.go TestAnImageDefinitionThatCannotBeOneIsRefused.
func TestAnImageDefinitionThatCannotBeOneIsRefused(t *testing.T) {
	if err := (run.Image{Name: "with-docker", Ref: "example.com/agent:1-docker", Runtime: "sysbox-runc", Docker: true}).Check(); err != nil {
		t.Errorf("a whole definition was refused: %v", err)
	}
	for name, img := range map[string]run.Image{
		"a name in capitals":           {Name: "Base", Ref: "example.com/agent:1"},
		"a reference as the name":      {Name: "example.com/agent:1", Ref: "example.com/agent:1"},
		"no name":                      {Ref: "example.com/agent:1"},
		"no reference":                 {Name: "base"},
		"a Docker without its runtime": {Name: "with-docker", Ref: "example.com/agent:1-docker", Docker: true},
	} {
		if err := img.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// From image_test.go TestTheImageIsTheOneThePolicySelects: the one the policy selects
// by name, the machine's default by name or by reference when it selects none; and
// without a wall none is resolved.
func TestTheImageIsTheOneThePolicySelects(t *testing.T) {
	for name, c := range map[string]struct {
		selected, def string
		want          run.Image
	}{
		"selected":               {"with-docker", "base", images[1]},
		"the default by name":    {"", "base", images[0]},
		"the default, reference": {"", "example.com/other:2", run.Image{Ref: "example.com/other:2"}},
	} {
		r := open(t, run.Config{RunID: runID, Wall: true, Images: run.Images{Default: c.def, Defined: images},
			Node: &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}, Image: c.selected}})
		if r.Image() != c.want {
			t.Errorf("%s: %+v, want %+v", name, r.Image(), c.want)
		}
	}
	if r := open(t, run.Config{RunID: runID, Images: run.Images{Default: "base", Defined: images}}); r.Image() != (run.Image{}) {
		t.Errorf("an image without a wall: %+v", r.Image())
	}
}

// From image_test.go TestARunWhoseImageCannotHoldDoesNotStart: an image selected
// without a wall, an image the machine does not define, a definition that cannot be
// one, and a name defined twice. Its last case, a default that is no image, is the
// wall's to refuse: here it resolves to an empty reference.
func TestARunWhoseImageCannotHoldDoesNotStart(t *testing.T) {
	cfg := func() run.Config {
		return run.Config{RunID: runID, Wall: true, Images: run.Images{Default: "base", Defined: slices.Clone(images)},
			Node: &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}, Image: "with-docker"}}
	}
	for name, c := range map[string]struct {
		change func(*run.Config)
		want   string
		code   string
	}{
		"no wall":                   {func(c *run.Config) { c.Wall = false }, "needs a wall", ""},
		"an image nobody defined":   {func(c *run.Config) { c.Node.Image = "nobody-defined" }, "does not define", "image_unknown"},
		"a definition that is none": {func(c *run.Config) { c.Images.Defined = []run.Image{{Name: "with-docker", Ref: "i", Docker: true}} }, "needs a runtime", ""},
		"a name defined twice":      {func(c *run.Config) { c.Images.Defined = append(c.Images.Defined, images[0]) }, "defined twice", ""},
	} {
		c2 := cfg()
		c.change(&c2)
		_, err := run.Decide(c2)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
		if code, _ := refusalOf(err); code != c.code {
			t.Errorf("%s: the code %q, want %q", name, code, c.code)
		}
	}
	c2 := cfg()
	c2.Node.Image, c2.Images.Default = "", ""
	if r := open(t, c2); r.Image() != (run.Image{}) {
		t.Errorf("a default that is no image resolved to %+v", r.Image())
	}
}

// From session.go Run: the image is resolved before the credentials are held and the
// tools chosen, and a credential's placeholder before the tools are chosen, so of two
// refusals the earlier is the one a run gets, as today.
func TestTheStartRefusesInTodaysOrder(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	cfg := toolConfig()
	cfg.Credentials = []run.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_TOKEN"}}}
	cfg.Node.Credentials = []run.PolicyCredential{{Name: "model"}}
	cfg.Node.Egress.Allow = append(cfg.Node.Egress.Allow, "api.model.example")
	// A tool nobody defined, and a credential's placeholder the run passes a value for.
	cfg.Tools = nil
	cfg.Passes = run.Passing([]string{"MODEL_TOKEN", "FILES_KEY"})
	_, err := run.Open(context.Background(), cfg)
	if code, names := refusalOf(err); code != "placeholder_conflict" || !slices.Equal(names, []string{"MODEL_TOKEN"}) {
		t.Errorf("a credential's placeholder and a tool nobody defined: %v", err)
	}
	// An image nobody defined, and a credential nobody defined.
	cfg.Credentials = nil
	cfg.Node.Image = "nobody-defined"
	_, err = run.Open(context.Background(), cfg)
	if code, _ := refusalOf(err); code != "image_unknown" {
		t.Errorf("an image and a credential nobody defined: %v", err)
	}
}

// From image_test.go TestAReloadKeepsTheRunsImage, and the image half of
// TestAReloadIsAsStrictAsAStart: a run configuration that selects another image fails
// the reload and the policy in force stays, one that selects the same takes effect;
// without a wall a reload's image is refused; and the image is compared before the
// credentials are held.
func TestAReloadKeepsTheRunsImage(t *testing.T) {
	withImage := `{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"%s]},"image":"%s"}`
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Images: run.Images{Default: "base", Defined: images},
		Fetched: served(fmt.Sprintf(withImage, "", "with-docker"), digest('1'))})
	if r.Image() != images[1] {
		t.Errorf("the run started in %+v", r.Image())
	}
	if _, err := reload(t, r, served(fmt.Sprintf(withImage, "", "base"), digest('2'))); err == nil || !strings.Contains(err.Error(), "another image than the run started in") || !strings.HasSuffix(err.Error(), "the policy in force stays") {
		t.Errorf("another image: %v", err)
	}
	if _, err := reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"image":"base","credentials":[{"name":"nobody-defined"}]}`, digest('2'))); err == nil || !strings.Contains(err.Error(), "another image than the run started in") {
		t.Errorf("another image and a credential nobody defined: %v", err)
	}
	if _, err := reload(t, r, served(fmt.Sprintf(withImage, "", "nobody-defined"), digest('2'))); err == nil || !strings.Contains(err.Error(), "does not define") {
		t.Errorf("an image nobody defined: %v", err)
	}
	d, err := reload(t, r, served(fmt.Sprintf(withImage, `,"git.example.com"`, "with-docker"), digest('3')))
	if err != nil || d.Image != images[1] || d.Policy.Policy.Image != "with-docker" {
		t.Fatalf("the same image: %+v, %v", d, err)
	}
	r.Commit(d)

	r = open(t, run.Config{RunID: runID, Server: true, Fetched: served(`{"version":1,"egress":{"mode":"observe"}}`, digest('1'))})
	if _, err := reload(t, r, served(`{"version":1,"egress":{"mode":"observe"},"image":"base"}`, digest('2'))); err == nil || !strings.Contains(err.Error(), `selects the image "base", which needs a wall`) {
		t.Errorf("a reload's image without a wall: %v", err)
	}
}

// From image_test.go TestAReloadComparesTheImageItResolvesTo: naming the machine's
// default, or no longer naming it, takes effect; another image does not.
func TestAReloadComparesTheImageItResolvesTo(t *testing.T) {
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Images: run.Images{Default: "base", Defined: images},
		Fetched: served(`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}}`, digest('1'))})
	for _, c := range []struct {
		doc  string
		d    byte
		want string
	}{
		{`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"image":"base"}`, '2', ""},
		{`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example","git.example.com"]}}`, '3', ""},
		{`{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"image":"with-docker"}`, '4', "another image than the run started in"},
	} {
		d, err := reload(t, r, served(c.doc, digest(c.d)))
		if c.want != "" {
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: %v, want %q", c.doc, err, c.want)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.doc, err)
		}
		r.Commit(d)
	}
	if r.RunConfiguration() != digest('3') || r.Policy().Policy.Image != "" {
		t.Errorf("the policy in force %q, image %q", r.RunConfiguration(), r.Policy().Policy.Image)
	}
}

// From variables.go passes: the names a run passes a value for.
func TestPassingIsTheNamesTheRunPasses(t *testing.T) {
	p := run.Passing([]string{"MODEL_TOKEN", "NODE_ENV"})
	if !p("MODEL_TOKEN") || !p("NODE_ENV") || p("FILES_KEY") || p("MODEL") || run.Passing(nil)("MODEL_TOKEN") {
		t.Error("Passing does not hold the names it was given, and only those")
	}
}

// From session.go Run: the node's path rules beside a server's policy need a wall, and
// are the proxy's beside the server's for the run.
func TestTheNodesPathsBesideAServersPolicy(t *testing.T) {
	node := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe", Paths: map[string][]string{"git.example.com": {"/acme/*"}}}}
	fetched := served(`{"version":1,"egress":{"mode":"observe"}}`, digest('1'))
	if _, err := run.Decide(run.Config{Node: node, Fetched: fetched}); err == nil || !strings.Contains(err.Error(), "run it with a wall") {
		t.Errorf("the node's paths without a wall: %v", err)
	}
	r := open(t, run.Config{RunID: runID, Node: node, Wall: true, Fetched: fetched})
	if sides := r.NodePaths(); len(sides) != 1 || !maps.EqualFunc(sides[0], node.Egress.Paths, slices.Equal) || !r.NeedsCA() {
		t.Errorf("node paths %v, authority %v", r.NodePaths(), r.NeedsCA())
	}
	// Without a server the node's policy is the run's, paths and all, and none is
	// beside it.
	r = open(t, run.Config{RunID: runID, Node: node, Wall: true})
	if r.NodePaths() != nil || r.Policy().Policy.Egress.Paths == nil || !r.NeedsCA() {
		t.Errorf("without a server: node paths %v, policy %+v", r.NodePaths(), r.Policy().Policy)
	}
}

// From env_internal_test.go TestNoProgramReceivesTheAccessKeysVariables: a tool's
// environment has neither the access key's variables nor a credential's.
func TestAToolsEnvironmentHoldsNoSecretOfForagers(t *testing.T) {
	t.Setenv(accesskey.EnvSecret, "a-secret")
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	t.Setenv("QORY_TEST_OTHER", "kept")
	r := open(t, run.Config{RunID: runID, Credentials: []run.Credential{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"}}})
	env := strings.Join(r.ToolEnv(), "\n")
	if strings.Contains(env, "a-secret") || strings.Contains(env, "the-token-held-outside") || !strings.Contains(env, "QORY_TEST_OTHER=kept") {
		t.Errorf("a tool's environment:\n%s", env)
	}
}

// From session.go egress: the event of one decision.
func TestTheEgressEventOfADecision(t *testing.T) {
	got := run.Egress(proxy.Decision{Host: "api.example", Port: 443, Method: "HTTPS", Allowed: true, Rule: "api.example", Mode: policy.Enforce, Outcome: "connected",
		RequestMethod: "GET", Path: "/a", PathRule: "/*", Credential: "model", RequestID: "r1", Status: 200})
	want := map[string]any{"host": "api.example", "port": 443, "method": "HTTPS", "decision": "allowed", "mode": "enforce", "rule": "api.example", "outcome": "connected",
		"request_method": "GET", "path": "/a", "path_rule": "/*", "credential": "model", "request_id": "r1", "status": 200}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("%v, want %v", got, want)
	}
	if got := run.Egress(proxy.Decision{Host: "x.example", Port: 443, Method: "CONNECT", Mode: policy.Observe, Outcome: "refused"}); got["decision"] != "denied" || len(got) != 7 {
		t.Errorf("a denial %v", got)
	}
}

// TestASessionsNarrowingOnlyNarrows pins the narrowing a session sends behind a
// separate gateway: under enforce when it lists allow, so a host it does not cover is
// removed, and under observe otherwise; its deny added; an observe policy put under
// enforce by its allow; the digest the narrowed policy's own; and a reload's policy
// narrowed the same way.
func TestASessionsNarrowingOnlyNarrows(t *testing.T) {
	read := func(doc string) *policy.Loaded {
		t.Helper()
		p, err := policy.Read("policy", []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	enforce := read(`{"version":1,"egress":{"mode":"enforce","allow":["*.example","git.example.org"],"deny":["bad.example"]}}`)
	for name, c := range map[string]struct {
		pol         *policy.Loaded
		n           *run.Narrowing
		mode        policy.Mode
		allow, deny []string
		source      string
	}{
		"an allow under enforce":     {enforce, &run.Narrowing{Allow: []string{"api.example", "other.test"}}, policy.Enforce, []string{"api.example"}, []string{"bad.example"}, "config"},
		"a deny alone":               {enforce, &run.Narrowing{Deny: []string{"tracker.example"}}, policy.Enforce, []string{"*.example", "git.example.org"}, []string{"bad.example", "tracker.example"}, "config"},
		"an allow under observe":     {policy.None(), &run.Narrowing{Allow: []string{"api.example"}}, policy.Enforce, []string{"api.example"}, nil, "config"},
		"a deny under observe":       {policy.None(), &run.Narrowing{Deny: []string{"tracker.example"}}, policy.Observe, []string{}, []string{"tracker.example"}, "config"},
		"an empty allow allows none": {enforce, &run.Narrowing{Allow: []string{}}, policy.Enforce, []string{}, []string{"bad.example"}, "config"},
	} {
		got := run.Narrow(c.pol, c.n)
		e := got.Policy.Egress
		if e.Mode != c.mode || !slices.Equal(e.Allow, c.allow) || !slices.Equal(e.Deny, c.deny) || got.Source != c.source {
			t.Errorf("%s: %+v %s", name, e, got.Source)
		}
		b, _ := json.Marshal(got.Policy)
		if sum := sha256.Sum256(b); got.Digest != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: the digest is not the narrowed policy's", name)
		}
	}
	if run.Narrow(enforce, nil) != enforce {
		t.Error("no narrowing changed the policy")
	}
	// The start and a reload alike.
	r, err := run.Decide(run.Config{RunID: runID, Server: true, Fetched: served(`{"version":1,"egress":{"mode":"observe"}}`, digest('a')), Narrowing: &run.Narrowing{Allow: []string{"api.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	if e := r.Policy().Policy.Egress; e.Mode != policy.Enforce || !slices.Equal(e.Allow, []string{"api.example"}) || r.Policy().Source != "fetched" || r.Policy().RunConfiguration != digest('a') {
		t.Errorf("the start: %+v %s", e, r.Policy().Source)
	}
	next, err := r.Read(*served(`{"version":1,"egress":{"mode":"enforce","allow":["api.example","git.example"]}}`, digest('b')))
	if err != nil {
		t.Fatal(err)
	}
	if e := next.Policy.Egress; !slices.Equal(e.Allow, []string{"api.example"}) {
		t.Errorf("a reload: %+v", e)
	}
	// No narrowing, no change: the node's policy as it was read.
	r, err = run.Decide(run.Config{RunID: runID, Node: &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Policy().Source != "config" {
		t.Errorf("without a narrowing: %s", r.Policy().Source)
	}
}

// TestANarrowingOpensNoneOfTheMachinesAddresses pins the guard's names under a
// session's narrowing: those of the node's policy, and only when the policy before the
// narrowing enforces. Under observe, or no policy, a narrowing's allow opens nothing;
// under enforce, a narrowed entry the node's policy does not name itself opens nothing
// either, nor does a "*." pattern; and without a narrowing the names are the node's
// allow list's.
func TestANarrowingOpensNoneOfTheMachinesAddresses(t *testing.T) {
	loaded := func(mode policy.Mode, allow ...string) *policy.Loaded {
		return &policy.Loaded{Policy: policy.Policy{Version: 1, Egress: policy.Egress{Mode: mode, Allow: allow}}, Source: "config"}
	}
	narrowing := &run.Narrowing{Allow: []string{"127.0.0.1", "api.example"}}
	for name, c := range map[string]struct {
		pol  *policy.Loaded
		n    *run.Narrowing
		want []string
	}{
		"no policy":                      {policy.None(), narrowing, nil},
		"observe":                        {loaded(policy.Observe, "127.0.0.1"), narrowing, nil},
		"enforce, a host it names":       {loaded(policy.Enforce, "127.0.0.1", "*.example"), narrowing, []string{"127.0.0.1"}},
		"enforce, a host it only covers": {loaded(policy.Enforce, "*.example"), &run.Narrowing{Allow: []string{"api.example"}}, nil},
		"no narrowing, observe":          {loaded(policy.Observe, "127.0.0.1"), nil, []string{"127.0.0.1"}},
	} {
		if got := run.GuardNames(c.pol, c.pol, c.n); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v", name, got)
		}
	}
}

// TestOnlyTheNodesPolicyOpensTheMachine pins that an entry of a server's policy never
// opens this machine's addresses: the guard's names are entries of the node's policy
// that the policy in force allows, at the start and at a reload. A guarded proxy given
// those names refuses localhost by the guard's rule where the node's policy does not
// name it, and reaches it where it does; a local policy alone opens what it names, as
// before.
func TestOnlyTheNodesPolicyOpensTheMachine(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "the local server") }))
	defer origin.Close()
	port := origin.URL[strings.LastIndex(origin.URL, ":"):]
	node := func(mode string, allow ...string) *run.Policy {
		return &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: mode, Allow: allow}}
	}
	localhost := `{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}}`
	for _, c := range []struct {
		name    string
		node    *run.Policy
		fetched *run.Fetched
		want    []string
	}{
		{"a server's localhost under a node that observes", node("observe"), served(localhost, digest('a')), nil},
		{"a server's localhost under a node that enforces it", node("enforce", "localhost"), served(localhost, digest('a')), []string{"localhost"}},
		{"a server's localhost with no node's policy", nil, served(localhost, digest('a')), nil},
		{"a server's name that resolves to this machine", nil, served(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1.nip.io"]}}`, digest('a')), nil},
		{"a local policy alone", node("enforce", "localhost", "*.example"), nil, []string{"localhost"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := open(t, run.Config{RunID: runID, Node: c.node, Server: c.fetched != nil, Fetched: c.fetched})
			if got := r.GuardNames(); !slices.Equal(got, c.want) {
				t.Errorf("the guard's names: %q, want %q", got, c.want)
			}
			e := r.Policy().Policy.Egress
			p, err := proxy.Listen("", e.Mode, e.Allow, e.Deny, func(proxy.Decision) {})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			p.Guard(r.GuardNames())
			proxyURL, _ := url.Parse(p.URL())
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
			resp, err := client.Get("http://localhost" + port + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			opened := slices.Contains(c.want, "localhost")
			if reached := resp.StatusCode == 200 && string(body) == "the local server"; reached != opened {
				t.Errorf("localhost through the guarded proxy: %d %q, want reached %v", resp.StatusCode, body, opened)
			}
			if !opened && (resp.StatusCode != 403 || !strings.Contains(string(body), "to reach the gateway's machine, list the host itself, not a *. pattern, in the allow list of the node's policy, and allow it in the run's policy; the gateway reaches its machine only for such a host, and never a link-local address")) {
				t.Errorf("localhost: %d %q, want the guard's refusal", resp.StatusCode, body)
			}
		})
	}
	// A reload takes the names from the node's policy in the same way.
	for _, c := range []struct {
		name string
		node *run.Policy
		want []string
	}{
		{"a node that observes", node("observe"), nil},
		{"a node that enforces localhost", node("enforce", "localhost", "api.example"), []string{"localhost"}},
	} {
		r := open(t, run.Config{RunID: runID, Node: c.node, Server: true, Fetched: served(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`, digest('a'))})
		d, err := reload(t, r, served(localhost, digest('b')))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !slices.Equal(d.Guard, c.want) {
			t.Errorf("%s: a reload's names %q, want %q", c.name, d.Guard, c.want)
		}
		d.Discard()
	}
}

// TestAPolicyEntryOutsideTheHostFormIsRefusedWhereverItIsRead pins that a policy whose
// entry naming a host is neither a host name nor an IPv4 address in canonical form is
// refused as one the schema refuses: as a run's policy file, as the node's policy, and
// as a server's security_policy, at the start and at a reload, run_configuration_invalid
// and settled.
func TestAPolicyEntryOutsideTheHostFormIsRefusedWhereverItIsRead(t *testing.T) {
	for _, bad := range []string{
		`{"version":1,"egress":{"mode":"observe","deny":["127.1"]}}`,
		`{"version":1,"egress":{"mode":"enforce","allow":["0x7f.0.0.1"]}}`,
		`{"version":1,"egress":{"mode":"enforce","allow":["api.example"],"paths":{"2130706433":[]}}}`,
	} {
		if _, err := run.ReadPolicy("policy.json", []byte(bad)); err == nil {
			t.Errorf("%s: read as a policy file", bad)
		}
		var node run.Policy
		if err := json.Unmarshal([]byte(bad), &node); err != nil {
			t.Fatal(err)
		}
		if _, err := run.Decide(run.Config{RunID: runID, Node: &node, Wall: true}); err == nil {
			t.Errorf("%s: a run opened on it as the node's policy", bad)
		}
		for _, r := range []*run.Run{
			open(t, run.Config{RunID: runID, Server: true}),
			open(t, run.Config{RunID: runID, Server: true, Fetched: served(`{"version":1,"egress":{"mode":"enforce","allow":["127.0.0.1"]}}`, digest('1'))}),
		} {
			_, err := r.Read(*served(bad, digest('2')))
			var refused *accesskey.Refusal
			if !errors.As(err, &refused) || refused.Code != "run_configuration_invalid" || !run.Settled(err) {
				t.Errorf("%s: %v, want run_configuration_invalid", bad, err)
			}
		}
	}
	// A ceiling's paths beside the run's policy are held to the same form.
	ceiling := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe", Paths: map[string][]string{"127.1": {"/v1/*"}}}}
	under := (&run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"api.example"}}}).Under(ceiling)
	_, err := run.Decide(run.Config{RunID: runID, Node: under, Wall: true})
	var pe *policy.Error
	if !errors.As(err, &pe) {
		t.Errorf("a ceiling's paths key 127.1: %v, want a *policy.Error", err)
	}
}

// pinned is an image a policy names by its reference pinned by digest.
const pinned = "registry.example/agents/app@sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

// TestAnImageByReferenceIsOneTheMachineAllows pins an image a policy names by its
// reference: under a prefix of images.allow it starts under the default's runtime,
// with no Docker, marked as a reference; under none it is image_not_allowed; with no
// list none is allowed; one with a tag is run_configuration_invalid; and the relay's
// image is the default's reference whatever the run's.
func TestAnImageByReferenceIsOneTheMachineAllows(t *testing.T) {
	defined := []run.Image{{Name: "base", Ref: "example.com/agent:1", Runtime: "sysbox-runc"}, images[1]}
	decide := func(image string, im run.Images) (*run.Run, error) {
		return run.Decide(run.Config{RunID: runID, Wall: true, Images: im,
			Node: &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}, Image: image}})
	}
	r, err := decide(pinned, run.Images{Default: "base", Defined: defined, Allow: []string{"registry.example/agents"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := (run.Image{Ref: pinned, Runtime: "sysbox-runc", Reference: true}); r.Image() != want || r.RelayImage() != "example.com/agent:1" {
		t.Errorf("the image %+v, the relay's %q; want %+v and the default's", r.Image(), r.RelayImage(), want)
	}
	r, err = decide(pinned, run.Images{Default: "example.com/other:2", Allow: []string{"registry.example/"}})
	if err != nil || r.Image() != (run.Image{Ref: pinned, Reference: true}) || r.RelayImage() != "example.com/other:2" {
		t.Errorf("under a default by reference: %+v, %q, %v", r.Image(), r.RelayImage(), err)
	}
	if r, err := decide("with-docker", run.Images{Default: "base", Defined: defined}); err != nil || r.RelayImage() != "example.com/agent:1" || r.Image() != images[1] {
		t.Errorf("a named image's relay: %+v, %q, %v", r.Image(), r.RelayImage(), err)
	}
	for name, c := range map[string]struct {
		image string
		im    run.Images
		code  string
		want  string
	}{
		"under no prefix":        {pinned, run.Images{Default: "base", Defined: defined, Allow: []string{"registry.example/agents-other", "registry.example:5000"}}, "image_not_allowed", "under none of the machine's allowed prefixes (images.allow)"},
		"with no list":           {pinned, run.Images{Default: "base", Defined: defined}, "image_not_allowed", "images.allow"},
		"with a tag":             {"registry.example/agents/app:1", run.Images{Default: "base", Defined: defined, Allow: []string{"registry.example/"}}, "run_configuration_invalid", "not pinned by digest"},
		"an entry of *":          {pinned, run.Images{Default: "base", Defined: defined, Allow: []string{"*"}}, "", "every image"},
		"an empty entry":         {pinned, run.Images{Default: "base", Defined: defined, Allow: []string{""}}, "", "every image"},
		"a list with no default": {pinned, run.Images{Allow: []string{"registry.example/"}}, "", "needs a default image"},
	} {
		_, err := decide(c.image, c.im)
		code, names := refusalOf(err)
		if err == nil || code != c.code || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (%q), want %q with %q", name, err, code, c.code, c.want)
		}
		if code == "image_not_allowed" && !slices.Equal(names, []string{pinned}) {
			t.Errorf("%s: the names %q", name, names)
		}
	}
}

// TestAReloadKeepsAnImageByReference pins that a run started in an image by reference
// keeps it: a reload that names the same reference takes effect, one that names the
// default, another reference or a reference outside the list does not.
func TestAReloadKeepsAnImageByReference(t *testing.T) {
	doc := `{"version":1,"egress":{"mode":"observe"},"image":"%s"}`
	other := strings.Replace(pinned, "agents/app", "agents/other", 1)
	im := run.Images{Default: "base", Defined: images, Allow: []string{"registry.example/agents/"}}
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Images: im, Fetched: served(fmt.Sprintf(doc, pinned), digest('1'))})
	if !r.Image().Reference {
		t.Fatalf("the run started in %+v", r.Image())
	}
	if d, err := reload(t, r, served(fmt.Sprintf(doc, pinned), digest('2'))); err != nil || d.Image != r.Image() {
		t.Errorf("the same reference: %+v, %v", d, err)
	}
	for _, image := range []string{"base", other, "elsewhere.example/app@sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"} {
		if _, err := reload(t, r, served(fmt.Sprintf(doc, image), digest('3'))); err == nil {
			t.Errorf("a reload to %s took effect", image)
		}
	}
}
