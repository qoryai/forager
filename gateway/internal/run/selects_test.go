package run_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/policy"
)

// selectsConfig is a walled run with a server behind a separate gateway, whose
// selection is git, an adapter, and model, a secret of the environment; the server
// serves policy.
func selectsConfig(t *testing.T, policy string) (run.Config, *reports) {
	t.Helper()
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	adapter := filepath.Join(t.TempDir(), "adapter")
	answer := `printf '{"version":1,"token":"minted-for-the-run","expires_at":"2099-01-01T00:00:00Z","apply":[{"hosts":["git.example"],"scheme":"bearer"}]}\n'` + "\n"
	if err := os.WriteFile(adapter, []byte("#!/bin/sh\n"+answer), 0o755); err != nil {
		t.Fatal(err)
	}
	said := &reports{}
	return run.Config{
		RunID: runID, Wall: true, Server: true, Report: said.report,
		Labels: map[string]string{"issue": "7"},
		Credentials: []run.Credential{
			{Name: "git", Adapter: []string{adapter}, Hosts: []string{"git.example"}},
			{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"},
		},
		Selects: []run.Selection{{Name: "git"}, {Name: "model"}},
		Fetched: served(policy, digest('1')),
	}, said
}

// tokensOf are the uses as the proxy sets them: each credential's name and its token,
// in order.
func tokensOf(uses []proxy.Credential) []string {
	out := make([]string, len(uses))
	for i, u := range uses {
		out[i] = u.Name + "=" + u.Token()
	}
	return out
}

// TestAReloadKeepsTheGatewaysSelection pins a reload: a run configuration that selects
// no credential gets the gateway's selection again, the same, so the credentials are
// unchanged; one that selects a credential gets the server's.
func TestAReloadKeepsTheGatewaysSelection(t *testing.T) {
	const none = `{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]}}`
	cfg, _ := selectsConfig(t, none)
	r := open(t, cfg)
	want := []string{"git=minted-for-the-run", "model=the-token-held-outside"}
	if got := tokensOf(r.Uses()); !slices.Equal(got, want) {
		t.Errorf("the start's uses %v, want %v", got, want)
	}
	d, err := reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example","b.example"]}}`, digest('2')))
	if err != nil {
		t.Fatal(err)
	}
	if got := tokensOf(d.Uses); d.CredentialsChanged || !slices.Equal(got, want) {
		t.Errorf("the reload: changed %v, uses %v, want %v", d.CredentialsChanged, got, want)
	}
	if got := d.Policy.Policy.Credentials; len(got) != 2 || got[0].Name != "git" || got[0].Argument != "" || got[1].Name != "model" || got[1].Argument != "" {
		t.Errorf("the reload's credentials %v", got)
	}
	r.Commit(d)
	d, err = reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]},"credentials":[{"name":"model"}]}`, digest('3')))
	if err != nil {
		t.Fatal(err)
	}
	if !d.CredentialsChanged || len(d.Uses) != 1 || d.Uses[0].Name != "model" {
		t.Errorf("a reload whose server selects model: changed %v, uses %v", d.CredentialsChanged, d.Uses)
	}
	d.Discard()
}

// TestAnUnwalledRunGetsTheSelection pins a run without a wall: it gets the gateway's
// selection at the start and at a reload, as a walled run does, has the run's
// authority, and its user is told nothing.
func TestAnUnwalledRunGetsTheSelection(t *testing.T) {
	const none = `{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]}}`
	cfg, said := selectsConfig(t, none)
	cfg.Wall = false
	r := open(t, cfg)
	want := []string{"git=minted-for-the-run", "model=the-token-held-outside"}
	if got := tokensOf(r.Uses()); !slices.Equal(got, want) || !r.NeedsCA() {
		t.Errorf("the start's uses %v, want %v; authority %v", got, want, r.NeedsCA())
	}
	d, err := reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example","b.example"]}}`, digest('2')))
	if err != nil {
		t.Fatal(err)
	}
	if got := tokensOf(d.Uses); d.CredentialsChanged || !slices.Equal(got, want) {
		t.Errorf("the reload: changed %v, uses %v, want %v", d.CredentialsChanged, got, want)
	}
	d.Discard()
	said.mu.Lock()
	defer said.mu.Unlock()
	if len(said.said) != 0 {
		t.Errorf("the user was told %v", said.said)
	}
}

// TestTheNodesCredentialsCapTheGatewaysSelection pins the node's credentials member as
// the cap of the gateway's selection, the same whether the server's run configuration
// has a security_policy that selects none or has none, the node's policy then the
// run's: a member that lists none, and one that does not list a selected credential,
// are no run, with the same refusal; no member caps nothing.
func TestTheNodesCredentialsCapTheGatewaysSelection(t *testing.T) {
	const text = "the gateway selects the credentials git, which the node's policy does not list"
	sides := map[string]*run.Fetched{
		"a server's policy that selects none": served(`{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]}}`, digest('1')),
		"no server's policy":                  document(t, `{"version":1}`, digest('1')),
	}
	for side, fetched := range sides {
		for name, c := range map[string]struct {
			credentials []run.PolicyCredential
			refused     string
			uses        []string
		}{
			"no member":             {nil, "", []string{"git", "model"}},
			"a member listing none": {[]run.PolicyCredential{}, "the gateway selects the credentials git, model, which the node's policy does not list", nil},
			"a member without git":  {[]run.PolicyCredential{{Name: "model"}}, text, nil},
		} {
			cfg, _ := selectsConfig(t, "")
			cfg.Fetched = fetched
			cfg.Node = &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"git.example", "api.model.example"}}, Credentials: c.credentials}
			r, err := run.Open(context.Background(), cfg)
			if c.refused != "" {
				if err == nil || !strings.Contains(err.Error(), c.refused) {
					t.Errorf("%s, %s: %v; want %q", side, name, err, c.refused)
				}
				if err == nil {
					r.Close()
				}
				continue
			}
			if err != nil {
				t.Errorf("%s, %s: %v", side, name, err)
				continue
			}
			var got []string
			for _, u := range r.Uses() {
				got = append(got, u.Name)
			}
			if !slices.Equal(got, c.uses) {
				t.Errorf("%s, %s: uses %v, want %v", side, name, got, c.uses)
			}
			r.Close()
		}
	}
}

// The phrases a run's message prints in place of a name, or of an error's text, that
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

// selectsNamed is selectsConfig with the git credential and its entry named name.
func selectsNamed(t *testing.T, name string) (run.Config, *reports) {
	t.Helper()
	cfg, said := selectsConfig(t, `{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]}}`)
	cfg.Credentials[0].Name, cfg.Selects[0].Name = name, name
	return cfg, said
}

// TestASelectionReportPrintsAPhraseForASecret pins the refusal of a selection the
// node's policy does not list: an entry's name that contains qak_ or qrk_ prints the
// name's phrase, with the rest of the refusal word for word; a clean name prints as it
// is.
func TestASelectionReportPrintsAPhraseForASecret(t *testing.T) {
	for name, phrase := range map[string]string{"qak_x": accessKeyNamePhrase, "a.qrk_b": runKeyNamePhrase, "qrk_x.qak_y": accessKeyNamePhrase, "git": "git"} {
		cfg, _ := selectsNamed(t, name)
		cfg.Node = &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"git.example", "api.model.example"}}, Credentials: []run.PolicyCredential{}}
		_, err := run.Open(context.Background(), cfg)
		if want := "the gateway selects the credentials " + phrase + ", model, which the node's policy does not list"; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s, the node's cap: %v, want %q", name, err, want)
		} else {
			noSecretPrefix(t, name+", the node's cap", err.Error())
		}
	}
}

// TestARunConfigurationRefusalPrintsAPhraseForASecret pins the refusal of a server's
// security_policy the schema refuses: when the schema's error contains qak_ or qrk_ in
// any case, policy.Error prints the value's phrase in place of the error's text after
// the document's name, and a clean error prints as policy.Read gives it.
func TestARunConfigurationRefusalPrintsAPhraseForASecret(t *testing.T) {
	const bad = `{"version":1,"egress":{"mode":"enforce","allow":["api.example"]},"credentials":[{"name":%q}]}`
	r := open(t, run.Config{RunID: runID, Server: true})
	for name, phrase := range map[string]string{"QAK_FAKESECRET": accessKeyValuePhrase, "qrk_X": runKeyValuePhrase, "QRK_x.QAK_y": accessKeyValuePhrase} {
		_, err := r.Read(*served(fmt.Sprintf(bad, name), digest('2')))
		code, _ := refusalOf(err)
		if want := "run configuration " + runURL + ": policy run-configuration: " + phrase + ": run_configuration_invalid"; code != "run_configuration_invalid" || err.Error() != want {
			t.Errorf("%s:\n got %v\nwant %s", name, err, want)
		} else {
			noSecretPrefix(t, name, err.Error())
		}
	}
	doc := fmt.Sprintf(bad, "Not-A-Name")
	_, read := policy.Read("run-configuration", []byte(doc))
	if read == nil {
		t.Fatal("policy.Read accepted the clean document")
	}
	_, err := r.Read(*served(doc, digest('2')))
	if want := "run configuration " + runURL + ": " + read.Error() + ": run_configuration_invalid"; err == nil || err.Error() != want {
		t.Errorf("a clean refusal:\n got %v\nwant %s", err, want)
	}
}

// TestAPlaceholderConflictPrintsAPhraseForASecret pins a placeholder_conflict of a
// credential's placeholder and of a tool's: a placeholder that contains qak_ or qrk_ in
// any case prints the name's phrase in the refusal's detail and its names, so the
// refusal's text holds neither prefix, and a clean one prints as it is.
func TestAPlaceholderConflictPrintsAPhraseForASecret(t *testing.T) {
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	for name, phrase := range map[string]string{"QAK_TOKEN": accessKeyNamePhrase, "qrk_token": runKeyNamePhrase, "QRK_X_QAK_Y": accessKeyNamePhrase, "MODEL_TOKEN": "MODEL_TOKEN"} {
		for of, c := range map[string]struct {
			cfg    func() run.Config
			detail string
		}{
			"a credential": {func() run.Config {
				cfg := modelConfig()
				cfg.Credentials[0].Placeholders = []string{name}
				return cfg
			}, " is a placeholder of a credential the gateway holds outside the enclosure, and the session passes a value for it inside"},
			"a tool": {func() run.Config {
				cfg := toolConfig()
				cfg.Tools[0].Placeholders = []string{name}
				return cfg
			}, " is a placeholder of a tool the gateway starts outside the enclosure, and the session passes a value for it inside"},
		} {
			cfg := c.cfg()
			cfg.Passes = func(n string) bool { return n == name }
			_, err := run.Open(context.Background(), cfg)
			var r *accesskey.Refusal
			if !errors.As(err, &r) || r.Code != "placeholder_conflict" {
				t.Fatalf("%s, %s: %v, want placeholder_conflict", of, name, err)
			}
			if want := phrase + c.detail + ": placeholder_conflict: " + phrase; err.Error() != want {
				t.Errorf("%s, %s:\n got %s\nwant %s", of, name, err, want)
			}
			noSecretPrefix(t, of+", "+name, err.Error())
			if !slices.Equal(r.Names, []string{phrase}) {
				t.Errorf("%s, %s: the names %q", of, name, r.Names)
			}
		}
	}
}

// TestTheEgressEventSendsAPhraseForASecretInAName pins run.egress's credential and
// tool: a name that contains qak_ or qrk_ in any case is sent as the name's phrase, the
// event validates against its schema, and a clean name is sent as it is.
func TestTheEgressEventSendsAPhraseForASecretInAName(t *testing.T) {
	schema, err := contracts.Compile("events/run.egress.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"qak_x": accessKeyNamePhrase, "a.qrk_b": runKeyNamePhrase, "qrk_x.qak_y": accessKeyNamePhrase, "model": "model"} {
		for _, d := range []proxy.Decision{
			{Host: "api.example", Port: 443, Method: "HTTPS", Allowed: true, Rule: "api.example", Mode: "enforce", Outcome: "connected", RequestMethod: "GET", Path: "/a", PathRule: "/*", Credential: name},
			{Host: "files.tools.internal", Port: 443, Method: "HTTPS", Allowed: true, Rule: "files.tools.internal", Mode: "enforce", Outcome: "connected", RequestMethod: "GET", Path: "/a", PathRule: "/*", Tool: name},
		} {
			data := run.Egress(d)
			field := "credential"
			if d.Tool != "" {
				field = "tool"
			}
			if data[field] != want {
				t.Errorf("%s: %s %v, want %s", name, field, data[field], want)
			}
			b, _ := json.Marshal(data)
			var doc any
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Errorf("%s, %s: the event does not validate: %v", name, field, err)
			}
		}
	}
}

// TestAnImageMessagePrintsAPhraseForASecret pins the messages that print an image: an
// image_unknown refusal's detail and names, a reload whose image moved, and an image
// that needs a wall. An image that contains qak_ or qrk_ in any case prints the name's
// phrase in its place, and a clean image prints as it is.
func TestAnImageMessagePrintsAPhraseForASecret(t *testing.T) {
	const sum = "@sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	withImage := func(image string) string {
		return fmt.Sprintf(`{"version":1,"egress":{"mode":"observe"},"image":%q}`, image)
	}
	for image, phrase := range map[string]string{
		"registry.example/agents/qak_x" + sum: accessKeyNamePhrase, "registry.example/agents/qrk_x" + sum: runKeyNamePhrase,
		"registry.example/agents/qrk_x.qak_y" + sum: accessKeyNamePhrase, pinned: pinned,
	} {
		other := "registry.example/agents/other" + sum
		_, err := run.Decide(run.Config{RunID: runID, Wall: true, Images: allowing, Fetched: named(image, withImage(other), digest('1'))})
		code, names := refusalOf(err)
		if want := "the run configuration names the image " + phrase + ", and the server's policy the image " + other; code != "image_unknown" || !slices.Equal(names, []string{phrase}) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (%q, %q), want image_unknown with %q", image, err, code, names, want)
		} else {
			noSecretPrefix(t, image, err.Error())
		}
		_, err = run.Decide(run.Config{RunID: runID, Wall: true, Images: allowing, Fetched: named(other, withImage(image), digest('1'))})
		if want := "the run configuration names the image " + other + ", and the server's policy the image " + phrase; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s, the server's policy: %v, want %q", image, err, want)
		}

		r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Images: allowing, Fetched: named(image, "", digest('1'))})
		_, err = reload(t, r, named(other, "", digest('2')))
		if want := "the run configuration names the image " + other + ", and the run started in " + phrase; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s, a reload: %v, want %q", image, err, want)
		}
		r = open(t, run.Config{RunID: runID, Wall: true, Server: true, Images: allowing, Fetched: named(other, "", digest('1'))})
		_, err = reload(t, r, named(image, "", digest('2')))
		if want := "the run configuration names the image " + phrase + ", and the run started in " + other; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s, a reload to it: %v, want %q", image, err, want)
		} else {
			noSecretPrefix(t, image+", a reload to it", err.Error())
		}
	}
	for image, phrase := range map[string]string{"qak_base": accessKeyNamePhrase, "a.qrk_b": runKeyNamePhrase, "base": `"base"`} {
		r := open(t, run.Config{RunID: runID, Server: true, Fetched: served(`{"version":1,"egress":{"mode":"observe"}}`, digest('1'))})
		_, err := reload(t, r, served(withImage(image), digest('2')))
		if want := "selects the image " + phrase + ", which needs a wall"; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s, no wall: %v, want %q", image, err, want)
		} else {
			noSecretPrefix(t, image+", no wall", err.Error())
		}
	}
}

// TestAnImageTheMachineRefusesPrintsAPhraseForASecret pins image_unknown for a name the
// machine does not define and image_not_allowed for a reference under none of its
// prefixes: an image that contains qak_ or qrk_ in any case is the name's phrase in the
// detail and the names, and a clean image is as it is.
func TestAnImageTheMachineRefusesPrintsAPhraseForASecret(t *testing.T) {
	const sum = "@sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	for _, c := range []struct{ image, code, names, detail string }{
		{"qak_nobody", "image_unknown", accessKeyNamePhrase, "the policy selects the image " + accessKeyNamePhrase + ", which this machine does not define"},
		{"nobody", "image_unknown", "nobody", `the policy selects the image "nobody", which this machine does not define`},
		{"registry.other/qrk_x" + sum, "image_not_allowed", runKeyNamePhrase, "the image " + runKeyNamePhrase + " is under none of the machine's allowed prefixes (images.allow)"},
		{"registry.other/x" + sum, "image_not_allowed", "registry.other/x" + sum, "the image registry.other/x" + sum + " is under none of the machine's allowed prefixes (images.allow)"},
	} {
		node := &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "observe"}, Image: c.image}
		_, err := run.Decide(run.Config{RunID: runID, Wall: true, Images: allowing, Node: node})
		code, names := refusalOf(err)
		if code != c.code || !slices.Equal(names, []string{c.names}) || !strings.Contains(err.Error(), c.detail) {
			t.Errorf("%s: %v (%q, %q), want %s with %q", c.image, err, code, names, c.code, c.detail)
			continue
		}
		noSecretPrefix(t, c.image, err.Error())
	}
}

// TestTheEgressEventSendsAPhraseForASecretInAValue pins run.egress's host, path, path
// rule and request method, which come from the run's request or the policy: a value
// that contains qak_ or qrk_ in any case is sent as the value's phrase, the event
// validates against its schema, and a clean value is sent as it is.
func TestTheEgressEventSendsAPhraseForASecretInAValue(t *testing.T) {
	schema, err := contracts.Compile("events/run.egress.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	d := proxy.Decision{Host: "api.qak_x.example", Port: 443, Method: "HTTPS", Allowed: false, Rule: "", Mode: "enforce", Outcome: "refused",
		RequestMethod: "QRK_GET", Path: "/a/qrk_b", PathRule: "/a/QAK_*"}
	data := run.Egress(d)
	want := map[string]any{"host": accessKeyValuePhrase, "request_method": runKeyValuePhrase, "path": runKeyValuePhrase, "path_rule": accessKeyValuePhrase}
	for k, v := range want {
		if data[k] != v {
			t.Errorf("%s %v, want %s", k, data[k], v)
		}
	}
	b, _ := json.Marshal(data)
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the event does not validate: %v", err)
	}
	clean := run.Egress(proxy.Decision{Host: "api.example", Port: 443, Method: "HTTPS", Mode: "enforce", Outcome: "refused", RequestMethod: "GET", Path: "/a", PathRule: "/a/*"})
	if clean["host"] != "api.example" || clean["path"] != "/a" || clean["path_rule"] != "/a/*" || clean["request_method"] != "GET" {
		t.Errorf("a clean decision %v", clean)
	}
}
