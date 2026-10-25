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

// anArgument is the argument pattern of a credential that takes one, which Start
// refuses in Selects.
const anArgument = `[a-z]+/[a-z]+`

// selecting is a gateway's credentials and its selection among them: git, an adapter
// that takes no argument and writes a line to its log each time it is asked, and model,
// a secret of the environment.
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
	adapter := shell(t, dir, "adapter", `echo asked >> '`+log+`'
printf '{"version":1,"token":"minted-for-the-run","expires_at":"2099-01-01T00:00:00Z","apply":[{"hosts":["git.example"],"scheme":"bearer"}]}\n'
`)
	return &selecting{
		creds: []gateway.Credential{
			{Name: "git", Adapter: []string{adapter}, Hosts: []string{"git.example"}},
			{Name: "model", Env: "QORY_TEST_SELECT_MODEL", Hosts: []string{"api.model.example"}, Scheme: "bearer"},
		},
		selects: []gateway.Selection{{Name: "git"}, {Name: "model"}},
		log:     log,
	}
}

// asked are the lines the adapter wrote, one each time it was asked.
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
	map[string]any{"name": "git", "hosts": []any{"git.example"}, "scheme": "bearer"},
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
// walled run whose server selects no credential gets git and model; the proxy sets
// both, and the run's applied and its record list them. A change of the caller's
// selection after Start changes nothing.
func TestAWalledRunBehindASeparateGatewayGetsTheGatewaysSelection(t *testing.T) {
	s := newSelecting(t)
	r := selectedRemote(t, s, selectedPolicy, map[string]string{"issue": "7"}, gateway.Config{})
	s.selects[0].Name = "nobody"
	runID := event.NewRunID()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
	if got := members(e.a.Applied)["credentials"]; !reflect.DeepEqual(got, bothSelected) {
		t.Errorf("applied credentials %v, want %v", got, bothSelected)
	}
	want := map[string]string{"git": "minted-for-the-run", "model": "model-value-of-the-test"}
	if got := gateway.Tokens(r.g, runID); !reflect.DeepEqual(got, want) {
		t.Errorf("the proxy sets %v, want %v", got, want)
	}
	if got := s.asked(t); !reflect.DeepEqual(got, []string{"asked"}) {
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

// TestAServerThatSelectsACredentialKeepsItsSelection pins the server's selection: a
// run whose server selects a credential gets that one alone, and no adapter is asked.
func TestAServerThatSelectsACredentialKeepsItsSelection(t *testing.T) {
	s := newSelecting(t)
	policy := `{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]},"credentials":[{"name":"model"}]}`
	r := selectedRemote(t, s, policy, map[string]string{"issue": "7"}, gateway.Config{})
	runID := event.NewRunID()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
	if got := members(e.a.Applied)["credentials"]; !reflect.DeepEqual(got, modelSelected) {
		t.Errorf("applied credentials %v, want the server's model alone", got)
	}
	if got := s.asked(t); got != nil {
		t.Errorf("the adapter was asked for %v", got)
	}
}

// TestAnUnwalledRunBehindASeparateGatewayGetsTheSelection pins a run without a wall:
// it gets the gateway's selection as a walled run does, git and model, the proxy sets
// both, and the run answer has the run's authority. The guard applies to it, as to
// every run behind a separate gateway.
func TestAnUnwalledRunBehindASeparateGatewayGetsTheSelection(t *testing.T) {
	s := newSelecting(t)
	r := selectedRemote(t, s, selectedPolicy, map[string]string{"issue": "7"}, gateway.Config{})
	runID := event.NewRunID()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{})
	if got := members(e.a.Applied)["credentials"]; !reflect.DeepEqual(got, bothSelected) {
		t.Errorf("applied credentials %v, want %v", got, bothSelected)
	}
	want := map[string]string{"git": "minted-for-the-run", "model": "model-value-of-the-test"}
	if got := gateway.Tokens(r.g, runID); !reflect.DeepEqual(got, want) {
		t.Errorf("the proxy sets %v, want %v", got, want)
	}
	if !strings.HasPrefix(e.a.CertificateAuthority, "-----BEGIN CERTIFICATE-----") || e.a.Image != nil {
		t.Errorf("the answer: authority %q, image %+v", e.a.CertificateAuthority, e.a.Image)
	}
	if !gateway.Guarded(r.g, runID) {
		t.Error("the run's proxy is not guarded")
	}
	if got := s.asked(t); !reflect.DeepEqual(got, []string{"asked"}) {
		t.Errorf("the adapter was asked for %v", got)
	}
	if got := e.post(t, heartbeat(runID), exited(runID)); got.status != http.StatusAccepted {
		t.Errorf("the last batch: %d %s", got.status, got.body)
	}
}

// TestTheNodesPolicyNarrowsTheGatewaysSelection pins the node's credentials member: a
// selected credential it does not list is no run, as the server's would be.
func TestTheNodesPolicyNarrowsTheGatewaysSelection(t *testing.T) {
	s := newSelecting(t)
	node := &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "observe"}, Credentials: []gateway.PolicyCredential{{Name: "model"}}}
	r := selectedRemote(t, s, selectedPolicy, map[string]string{"issue": "7"}, gateway.Config{Policy: node})
	a := r.tryOpen(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{Wall: true})
	const text = "the gateway selects the credentials git, which the node's policy does not list"
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
// name that is no credential of Credentials, a name twice, and a credential that takes
// an argument. Each is refused before anything starts.
func TestStartRefusesASelectionItCannotHold(t *testing.T) {
	s := newSelecting(t)
	creds := append(slices.Clone(s.creds), gateway.Credential{Name: "scoped", Adapter: s.creds[0].Adapter, Argument: anArgument, Hosts: []string{"other.git.example"}})
	for _, c := range []struct {
		sels []gateway.Selection
		text string
	}{
		{[]gateway.Selection{{Name: "nobody"}}, "gateway: Selects names nobody, which is no credential of Credentials"},
		{[]gateway.Selection{{Name: "model"}, {Name: "git"}, {Name: "model"}}, "gateway: Selects names model twice"},
		{[]gateway.Selection{{Name: "model"}, {Name: "scoped"}}, "gateway: remove scoped from Selects: its argument comes from the run's policy"},
	} {
		c0 := gatewayControl(t)
		certFile, keyFile, _ := testCertificate(t, t.TempDir())
		g, err := gateway.Start(context.Background(), gateway.Config{
			Listen: "127.0.0.1:0", TLS: &gateway.TLS{CertFile: certFile, KeyFile: keyFile}, Server: c0.server(),
			Dir: t.TempDir(), Credentials: creds, Selects: c.sels,
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

// noSecretPrefix fails the test when text contains qak_, qrk_, qecr_, qecn_, qecp_, qecg_
// or qeci_ in any case.
func noSecretPrefix(t *testing.T, what, text string) {
	t.Helper()
	if lower := strings.ToLower(text); strings.Contains(lower, "qak_") || strings.Contains(lower, "qrk_") || strings.Contains(lower, "qecr_") || strings.Contains(lower, "qecn_") || strings.Contains(lower, "qecp_") || strings.Contains(lower, "qecg_") || strings.Contains(lower, "qeci_") {
		t.Errorf("%s: a secret's prefix in %s", what, text)
	}
}

// TestStartsSelectionRefusalPrintsAPhraseForASecret pins Start's refusals of Selects:
// a selection's name that contains qak_ or qrk_ prints the name's phrase, with the rest
// of each sentence word for word. TestStartRefusesASelectionItCannotHold pins the same
// messages for clean names.
func TestStartsSelectionRefusalPrintsAPhraseForASecret(t *testing.T) {
	s := newSelecting(t)
	for name, phrase := range map[string]string{"qak_x": accessKeyNamePhrase, "a.qrk_b": runKeyNamePhrase, "qrk_x.qak_y": accessKeyNamePhrase} {
		creds := append(slices.Clone(s.creds),
			gateway.Credential{Name: name, Env: "QORY_TEST_SELECT_MODEL", Hosts: []string{"other.model.example"}, Scheme: "bearer"},
			gateway.Credential{Name: name + "-arg", Adapter: s.creds[0].Adapter, Argument: anArgument, Hosts: []string{"other.git.example"}})
		for _, c := range []struct {
			sels []gateway.Selection
			text string
		}{
			{[]gateway.Selection{{Name: strings.ToUpper(name)}}, "gateway: Selects names " + phrase + ", which is no credential of Credentials"},
			{[]gateway.Selection{{Name: name}, {Name: name}}, "gateway: Selects names " + phrase + " twice"},
			{[]gateway.Selection{{Name: name + "-arg"}}, "gateway: remove " + phrase + " from Selects: its argument comes from the run's policy"},
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
// credential's program directory and file, and a tool's program directory, by: a
// credential's or a tool's name that contains qak_ or qrk_ prints the name's phrase,
// and a clean name prints as it is.
func TestALinksFilePrintsAPhraseForASecretInAName(t *testing.T) {
	dir := t.TempDir()
	program := shell(t, dir, "adapter", "exit 1\n")
	token := filepath.Join(dir, "token")
	// The tool's program is in a directory apart, since the link lists a directory once.
	toolProgram := shell(t, t.TempDir(), "tool", "exit 1\n")
	for name, shown := range map[string]string{"qak_x": accessKeyNamePhrase, "a.qrk_b": runKeyNamePhrase, "qrk_x.qak_y": accessKeyNamePhrase, "model": "model"} {
		h := start(t, gateway.Config{Credentials: []gateway.Credential{
			{Name: name, Adapter: []string{program}},
			{Name: name + "-file", File: token, Hosts: []string{"api.model.example"}, Scheme: "bearer"},
		}, Tools: []gateway.Tool{{Name: name, Command: []string{toolProgram}, Serves: []string{"files.tools.internal"}}}})
		fileShown := shown
		if shown == "model" {
			fileShown = "model-file"
		}
		var whats []string
		for _, f := range h.g.LocalLink().Files {
			whats = append(whats, f.What)
		}
		for _, want := range []string{"the directory of the credential " + shown + "'s program", "the file the credential " + fileShown + " is read from", "the directory of the tool " + shown + "'s program"} {
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

// TestARunStartedWithRawLabelsGoesOnPhrased pins the labels of a run.started a session
// sends as they are: the gateway accepts them, and the record and the server get each
// key and value that contains qak_ or qrk_ in any case as the name's phrase, so no
// session passes a secret through in its labels.
func TestARunStartedWithRawLabelsGoesOnPhrased(t *testing.T) {
	labels := map[string]string{"repository": "acme/qak_FAKE", "qrk_fake": "x", "issue": "7"}
	want := map[string]any{"repository": accessKeyNamePhrase, runKeyNamePhrase: "x", "issue": "7"}
	c := newControl(t)
	h := start(t, gateway.Config{Server: c.server()})
	a := h.open(server.LinkRunRequest{Labels: labels})
	if d := h.post(started(a.RunID, labels)); !d.Accepted() {
		t.Fatalf("the run.started: %+v", d)
	}
	if d := h.post(exited(a.RunID)); !d.Accepted() {
		t.Fatalf("the run.exited: %+v", d)
	}
	eventually(t, "the run's exit at the server", func() bool {
		lines := c.lines(t)
		return len(lines) > 0 && lines[len(lines)-1].Type == event.RunExited
	})
	for what, lines := range map[string][]recorded{"the record": h.record(a.RunID), "the server": c.lines(t)} {
		n := 0
		for _, l := range lines {
			if l.Type != event.RunStarted {
				continue
			}
			n++
			if !reflect.DeepEqual(l.Data["labels"], want) {
				t.Errorf("%s: labels %v, want %v", what, l.Data["labels"], want)
			}
		}
		if n != 1 {
			t.Errorf("%s: %d run.started", what, n)
		}
	}
	h.close()
}
