package gateway_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// oneRepository is the pattern of one owner/name on a forge, as a selection names it.
const oneRepository = `[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}`

// selecting is a gateway's credentials and its selection among them: github, an adapter
// that takes a repository and writes each argument it was asked for to its log, and
// model, a secret of the environment that takes none.
type selecting struct {
	creds   []gateway.Credential
	selects []gateway.Selection
	log     string
}

func newSelecting(t *testing.T) *selecting {
	t.Helper()
	t.Setenv("QORY_TEST_SELECT_MODEL", "model-value-of-the-test")
	dir := t.TempDir()
	log := filepath.Join(dir, "asked")
	adapter := shell(t, dir, "adapter", `echo "$1" >> '`+log+`'
printf '{"version":1,"token":"minted-for-%s","expires_at":"2099-01-01T00:00:00Z","apply":[{"hosts":["git.example"],"scheme":"bearer"}]}\n' "$1"
`)
	return &selecting{
		creds: []gateway.Credential{
			{Name: "github", Adapter: []string{adapter, "${argument}"}, Argument: oneRepository, Hosts: []string{"git.example"}},
			{Name: "model", Env: "QORY_TEST_SELECT_MODEL", Hosts: []string{"api.model.example"}, Scheme: "bearer"},
		},
		selects: []gateway.Selection{{Name: "github", Label: "repository", Forge: "github.com", Pattern: oneRepository}, {Name: "model"}},
		log:     log,
	}
}

// asked are the arguments the adapter was asked for, in order.
func (s *selecting) asked(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(s.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// selectedPolicy is the server's policy of these tests, which selects no credential.
const selectedPolicy = `{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]}}`

// bothSelected are the credentials of the run's applied when it has both.
var bothSelected = []any{
	map[string]any{"name": "github", "argument": "example/repo", "hosts": []any{"git.example"}, "scheme": "bearer"},
	map[string]any{"name": "model", "hosts": []any{"api.model.example"}, "scheme": "bearer"},
}

// modelSelected are the credentials of the run's applied when it has model alone.
var modelSelected = []any{map[string]any{"name": "model", "hosts": []any{"api.model.example"}, "scheme": "bearer"}}

// selectedRemote is a separate gateway with the selection, whose server serves the
// policy and gives back the labels at the attach.
func selectedRemote(t *testing.T, s *selecting, policy string, labels map[string]string, cfg gateway.Config) *remote {
	t.Helper()
	c := gatewayControl(t)
	c.serve(policy, 'a')
	c.mu.Lock()
	c.attachLabels = labels
	c.mu.Unlock()
	cfg.Credentials, cfg.Selects = s.creds, s.selects
	return startRemote(t, c, cfg)
}

// TestAWalledRunBehindASeparateGatewayGetsTheGatewaysSelection pins the selection: a
// walled run whose server selects no credential gets github, its argument the run's
// repository label, and model; the proxy sets both, and the run's applied and its
// record list them, github with the label's value as its argument. A change of the
// caller's selection after Start changes nothing.
func TestAWalledRunBehindASeparateGatewayGetsTheGatewaysSelection(t *testing.T) {
	s := newSelecting(t)
	r := selectedRemote(t, s, selectedPolicy, map[string]string{"repository": "example/repo", "forge": "github.com"}, gateway.Config{})
	s.selects[0].Label, s.selects[0].Forge = "other", "git.example"
	runID := event.NewRunID()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
	if got := members(e.a.Applied)["credentials"]; !reflect.DeepEqual(got, bothSelected) {
		t.Errorf("applied credentials %v, want %v", got, bothSelected)
	}
	want := map[string]string{"github": "minted-for-example/repo", "model": "model-value-of-the-test"}
	if got := gateway.Tokens(r.g, runID); !reflect.DeepEqual(got, want) {
		t.Errorf("the proxy sets %v, want %v", got, want)
	}
	if got := s.asked(t); !reflect.DeepEqual(got, []string{"example/repo"}) {
		t.Errorf("the adapter was asked for %v", got)
	}
	if got := e.post(t, exited(runID)); got.status != http.StatusAccepted {
		t.Fatalf("the last batch: %d %s", got.status, got.body)
	}
	eventually(t, "the run's exit at the server", func() bool {
		lines := r.c.lines(t)
		return len(lines) > 0 && lines[len(lines)-1].Type == event.RunExited
	})
	n := 0
	for _, ev := range r.record(runID) {
		if ev.Type == event.PolicyApplied {
			n++
			if !reflect.DeepEqual(ev.Data["credentials"], bothSelected) {
				t.Errorf("the record's policy_applied: %v", ev.Data)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d policy_applied in the record", n)
	}
}

// TestAnEntryTheRunsLabelsDoNotSatisfyGivesNothing pins an entry that gives no
// credential: a run without the label, a run of another forge and a run whose label
// names two repositories each get no github, the gateway's line saying why, and no
// adapter is asked; the run goes on with model.
func TestAnEntryTheRunsLabelsDoNotSatisfyGivesNothing(t *testing.T) {
	for name, c := range map[string]struct {
		labels map[string]string
		line   string
	}{
		"no label":       {map[string]string{"forge": "github.com"}, "the gateway selects github by the run's label repository, which the run does not have: it gets no github"},
		"no forge label": {map[string]string{"repository": "example/repo"}, "the gateway selects github by the run's label forge, which the run does not have: it gets no github"},
		"another forge":  {map[string]string{"repository": "example/repo", "forge": "git.example"}, "the gateway selects github for the forge github.com, and the run's forge is git.example: it gets no github"},
		"two repositories": {map[string]string{"repository": "a/b,c/d", "forge": "github.com"},
			"the run's label repository=a/b,c/d is no argument github takes: it gets no github"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSelecting(t)
			r := selectedRemote(t, s, selectedPolicy, c.labels, gateway.Config{})
			runID := event.NewRunID()
			e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
			if got := members(e.a.Applied)["credentials"]; !reflect.DeepEqual(got, modelSelected) {
				t.Errorf("applied credentials %v, want model alone", got)
			}
			if !r.reported("run " + runID + ": " + c.line) {
				t.Errorf("no line %q in %v", c.line, r.reports)
			}
			if got := s.asked(t); got != nil {
				t.Errorf("the adapter was asked for %v", got)
			}
			if got := e.post(t, exited(runID)); got.status != http.StatusAccepted {
				t.Errorf("the last batch: %d %s", got.status, got.body)
			}
		})
	}
}

// TestAServerThatSelectsACredentialKeepsItsSelection pins the server's selection: a
// run whose server selects a credential gets that one alone, and no adapter is asked.
func TestAServerThatSelectsACredentialKeepsItsSelection(t *testing.T) {
	s := newSelecting(t)
	policy := `{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]},"credentials":[{"name":"model"}]}`
	r := selectedRemote(t, s, policy, map[string]string{"repository": "example/repo", "forge": "github.com"}, gateway.Config{})
	runID := event.NewRunID()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
	if got := members(e.a.Applied)["credentials"]; !reflect.DeepEqual(got, modelSelected) {
		t.Errorf("applied credentials %v, want the server's model alone", got)
	}
	if got := s.asked(t); got != nil {
		t.Errorf("the adapter was asked for %v", got)
	}
}

// TestAnUnwalledRunBehindASeparateGatewayGetsNoSelection pins a run without a wall: it
// gets no credential, runs, and the gateway says so once. That a reload says nothing
// more is the run package's to pin.
func TestAnUnwalledRunBehindASeparateGatewayGetsNoSelection(t *testing.T) {
	s := newSelecting(t)
	r := selectedRemote(t, s, selectedPolicy, map[string]string{"repository": "example/repo", "forge": "github.com"}, gateway.Config{})
	runID := event.NewRunID()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
	if got := members(e.a.Applied)["credentials"]; got != nil {
		t.Errorf("applied credentials %v", got)
	}
	if got := e.post(t, heartbeat(runID), exited(runID)); got.status != http.StatusAccepted {
		t.Errorf("the last batch: %d %s", got.status, got.body)
	}
	line := "run " + runID + ": the gateway selects credentials for a walled run alone: this run has no wall and gets none"
	r.mu.Lock()
	n := 0
	for _, l := range r.reports {
		if l == line {
			n++
		}
	}
	r.mu.Unlock()
	if n != 1 {
		t.Errorf("the line %q %d times in %v", line, n, r.reports)
	}
	if got := s.asked(t); got != nil {
		t.Errorf("the adapter was asked for %v", got)
	}
}

// TestTheNodesPolicyNarrowsTheGatewaysSelection pins the node's credentials member: a
// selected credential it does not list is no run, as the server's would be.
func TestTheNodesPolicyNarrowsTheGatewaysSelection(t *testing.T) {
	s := newSelecting(t)
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "observe"}, Credentials: []gateway.PolicyCredential{{Name: "model"}}}
	r := selectedRemote(t, s, selectedPolicy, map[string]string{"repository": "example/repo", "forge": "github.com"}, gateway.Config{Policy: node})
	a := r.tryOpen(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{Wall: true})
	const text = "the gateway selects the credentials github, which the node's policy does not list"
	if a.status == http.StatusOK || !strings.Contains(fmt.Sprint(a.refusal()["message"]), text) {
		t.Errorf("the run request: %d %s; want a refusal saying %q", a.status, a.body, text)
	}
	if got := s.asked(t); got != nil {
		t.Errorf("the adapter was asked for %v", got)
	}
}

// TestALocalGatewayTakesNoSelection pins the local link: a gateway without an address
// has no runs a selection is for, so Start refuses one, and nothing starts.
func TestALocalGatewayTakesNoSelection(t *testing.T) {
	s := newSelecting(t)
	c := newControl(t)
	c.serve(selectedPolicy, 'a')
	_, err := gateway.Start(context.Background(), gateway.Config{Server: c.server(), Dir: t.TempDir(), Credentials: s.creds, Selects: s.selects})
	const text = "gateway: Selects is for the runs on the gateway's address, and it has no Listen"
	if err == nil || err.Error() != text {
		t.Errorf("%v; want %q", err, text)
	}
	if n := c.fetches.Load(); n != 0 {
		t.Errorf("%d requests to the run endpoint", n)
	}
}

// TestStartRefusesASelectionItCannotHold pins Start's check of each entry of Selects: a
// name that is no credential of Credentials, a name twice, a Label, a Forge or a
// Pattern for a credential that takes no argument, an entry for one that takes an
// argument without all three, and a pattern that does not compile, alone or as a
// label's value is matched, whole. Each is refused before anything starts.
func TestStartRefusesASelectionItCannotHold(t *testing.T) {
	s := newSelecting(t)
	github := gateway.Selection{Name: "github", Label: "repository", Forge: "github.com", Pattern: oneRepository}
	with := func(change func(*gateway.Selection)) gateway.Selection {
		sel := github
		change(&sel)
		return sel
	}
	for _, c := range []struct {
		sels []gateway.Selection
		text string
	}{
		{[]gateway.Selection{{Name: "nobody"}}, "gateway: Selects names nobody, which is no credential of Credentials"},
		{[]gateway.Selection{{Name: "model"}, github, {Name: "model"}}, "gateway: Selects names model twice"},
		{[]gateway.Selection{{Name: "model", Label: "repository"}}, "gateway: Selects model: model takes no argument, so Label does not apply"},
		{[]gateway.Selection{{Name: "model", Forge: "github.com"}}, "gateway: Selects model: model takes no argument, so Forge does not apply"},
		{[]gateway.Selection{{Name: "model", Pattern: oneRepository}}, "gateway: Selects model: model takes no argument, so Pattern does not apply"},
		{[]gateway.Selection{{Name: "github"}}, "gateway: Selects github: github takes an argument, so it needs Label, Forge and Pattern"},
		{[]gateway.Selection{with(func(s *gateway.Selection) { s.Label = "" })}, "gateway: Selects github: github takes an argument, so it needs Label, Forge and Pattern"},
		{[]gateway.Selection{with(func(s *gateway.Selection) { s.Forge = "" })}, "gateway: Selects github: github takes an argument, so it needs Label, Forge and Pattern"},
		{[]gateway.Selection{with(func(s *gateway.Selection) { s.Pattern = "" })}, "gateway: Selects github: github takes an argument, so it needs Label, Forge and Pattern"},
		{[]gateway.Selection{with(func(s *gateway.Selection) { s.Pattern = "(a" })},
			"gateway: Selects github: the pattern does not compile: error parsing regexp: missing closing ): `(a`"},
		// A pattern that compiles alone and not as a label's value is matched, whole.
		{[]gateway.Selection{with(func(s *gateway.Selection) { s.Pattern = `a\Q` })},
			"gateway: Selects github: the pattern does not compile: error parsing regexp: missing closing ): `^(?:a\\Q)$`"},
	} {
		c0 := gatewayControl(t)
		certFile, keyFile, _ := testCertificate(t, t.TempDir())
		g, err := gateway.Start(context.Background(), gateway.Config{
			Listen: "127.0.0.1:0", TLS: &gateway.TLS{CertFile: certFile, KeyFile: keyFile}, Server: c0.server(),
			Dir: t.TempDir(), Credentials: s.creds, Selects: c.sels,
		})
		if err == nil {
			g.Close(context.Background())
		}
		if err == nil || err.Error() != c.text {
			t.Errorf("%+v: %v; want %q", c.sels, err, c.text)
		}
		if n := c0.fetches.Load(); n != 0 {
			t.Errorf("%+v: %d requests to the run endpoint", c.sels, n)
		}
	}
}

// The phrases a gateway message prints in place of a name, or of an error's text, that
// contains qak_ or qrk_ in any case.
const (
	accessKeyNamePhrase  = "(a name that contains an access key secret)"
	runKeyNamePhrase     = "(a name that contains a run key)"
	accessKeyValuePhrase = "(a value that contains an access key secret)"
	runKeyValuePhrase    = "(a value that contains a run key)"
)

// noSecretPrefix fails the test when text contains qak_ or qrk_ in any case.
func noSecretPrefix(t *testing.T, what, text string) {
	t.Helper()
	if lower := strings.ToLower(text); strings.Contains(lower, "qak_") || strings.Contains(lower, "qrk_") {
		t.Errorf("%s: a secret's prefix in %s", what, text)
	}
}

// TestStartsSelectionRefusalPrintsAPhraseForASecret pins Start's refusals of Selects:
// a selection's name that contains qak_ or qrk_ prints the name's phrase, and a
// pattern whose error quotes it prints the value's phrase in place of the error, with
// the rest of each sentence word for word. TestStartRefusesASelectionItCannotHold pins
// the same messages for clean names and patterns.
func TestStartsSelectionRefusalPrintsAPhraseForASecret(t *testing.T) {
	s := newSelecting(t)
	for name, phrase := range map[string]string{"qak_x": accessKeyNamePhrase, "a.qrk_b": runKeyNamePhrase, "qrk_x.qak_y": accessKeyNamePhrase} {
		creds := append(slices.Clone(s.creds),
			gateway.Credential{Name: name, Env: "QORY_TEST_SELECT_MODEL", Hosts: []string{"other.model.example"}, Scheme: "bearer"},
			gateway.Credential{Name: name + "-arg", Adapter: s.creds[0].Adapter, Argument: oneRepository, Hosts: []string{"other.git.example"}})
		for _, c := range []struct {
			sels []gateway.Selection
			text string
		}{
			{[]gateway.Selection{{Name: strings.ToUpper(name)}}, "gateway: Selects names " + phrase + ", which is no credential of Credentials"},
			{[]gateway.Selection{{Name: name}, {Name: name}}, "gateway: Selects names " + phrase + " twice"},
			{[]gateway.Selection{{Name: name, Label: "repository"}}, "gateway: Selects " + phrase + ": " + phrase + " takes no argument, so Label does not apply"},
			{[]gateway.Selection{{Name: name + "-arg"}}, "gateway: Selects " + phrase + ": " + phrase + " takes an argument, so it needs Label, Forge and Pattern"},
			{[]gateway.Selection{{Name: "github", Label: "repository", Forge: "github.com", Pattern: name + "("}}, "gateway: Selects github: the pattern does not compile: " + strings.Replace(phrase, "name", "value", 1)},
			{[]gateway.Selection{{Name: "github", Label: "repository", Forge: "github.com", Pattern: strings.ToUpper(name) + `\Q`}}, "gateway: Selects github: the pattern does not compile: " + strings.Replace(phrase, "name", "value", 1)},
		} {
			c0 := gatewayControl(t)
			certFile, keyFile, _ := testCertificate(t, t.TempDir())
			g, err := gateway.Start(context.Background(), gateway.Config{
				Listen: "127.0.0.1:0", TLS: &gateway.TLS{CertFile: certFile, KeyFile: keyFile}, Server: c0.server(),
				Dir: t.TempDir(), Credentials: creds, Selects: c.sels,
			})
			if err == nil {
				g.Close(context.Background())
				t.Errorf("%+v: started", c.sels)
				continue
			}
			if err.Error() != c.text {
				t.Errorf("%+v:\n got %v\nwant %s", c.sels, err, c.text)
			}
			noSecretPrefix(t, fmt.Sprintf("%+v", c.sels), err.Error())
		}
	}
}

// TestALinksFilePrintsAPhraseForASecretInAName pins the phrases the link gives a
// credential's program directory and file by: a credential's name that contains qak_
// or qrk_ prints the name's phrase, and a clean name prints as it is.
func TestALinksFilePrintsAPhraseForASecretInAName(t *testing.T) {
	dir := t.TempDir()
	program := shell(t, dir, "adapter", "exit 1\n")
	token := filepath.Join(dir, "token")
	for name, shown := range map[string]string{"qak_x": accessKeyNamePhrase, "a.qrk_b": runKeyNamePhrase, "qrk_x.qak_y": accessKeyNamePhrase, "model": "model"} {
		h := start(t, gateway.Config{Credentials: []gateway.Credential{
			{Name: name, Adapter: []string{program}},
			{Name: name + "-file", File: token, Hosts: []string{"api.model.example"}, Scheme: "bearer"},
		}})
		fileShown := shown
		if shown == "model" {
			fileShown = "model-file"
		}
		var whats []string
		for _, f := range h.g.LocalLink().Files {
			whats = append(whats, f.What)
		}
		for _, want := range []string{"the directory of the credential " + shown + "'s program", "the file the credential " + fileShown + " is read from"} {
			if !slices.Contains(whats, want) {
				t.Errorf("%s: no %q among %q", name, want, whats)
			}
		}
		for _, w := range whats {
			noSecretPrefix(t, name, w)
		}
		h.close()
	}
}

// TestARunStartedMayCarryALabelsPhrase pins the gateway's check of the session's
// run.started labels: a value that contains qak_ or qrk_ may be the name's phrase, as
// the session sends it, or the value as it is, as a session of before sends it; any
// other value is not the run's.
func TestARunStartedMayCarryALabelsPhrase(t *testing.T) {
	labels := map[string]string{"repository": "acme/qak_x", "issue": "7"}
	h := start(t, gateway.Config{})
	for _, c := range []struct {
		sent     map[string]string
		accepted bool
	}{
		{map[string]string{"repository": accessKeyNamePhrase, "issue": "7"}, true},
		{labels, true},
		{map[string]string{"repository": runKeyNamePhrase, "issue": "7"}, false},
		{map[string]string{"repository": accessKeyNamePhrase, "issue": "8"}, false},
	} {
		a := h.open(server.LinkRunRequest{Labels: labels})
		d := h.post(started(a.RunID, c.sent))
		if c.accepted != d.Accepted() {
			t.Errorf("%v: %+v, want accepted %v", c.sent, d, c.accepted)
		}
	}
	h.close()
}
