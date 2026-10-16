package run_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/run"
)

// selectsConfig is a walled run with a server behind a separate gateway, whose
// selection is github, an adapter that takes the run's repository, and model, which
// takes none; the server serves policy.
func selectsConfig(t *testing.T, policy string) (run.Config, *reports) {
	t.Helper()
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token-held-outside")
	adapter := filepath.Join(t.TempDir(), "adapter")
	answer := `printf '{"version":1,"token":"minted-for-%s","expires_at":"2099-01-01T00:00:00Z","apply":[{"hosts":["git.example"],"scheme":"bearer"}]}\n' "$1"` + "\n"
	if err := os.WriteFile(adapter, []byte("#!/bin/sh\n"+answer), 0o755); err != nil {
		t.Fatal(err)
	}
	const repository = `[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}`
	said := &reports{}
	return run.Config{
		RunID: runID, Wall: true, Server: true, Report: said.report,
		Labels: map[string]string{"repository": "example/repo", "forge": "github.com"},
		Credentials: []run.Credential{
			{Name: "github", Adapter: []string{adapter, "${argument}"}, Argument: repository, Hosts: []string{"git.example"}},
			{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"},
		},
		Selects: []run.Selection{{Name: "github", Label: "repository", Forge: "github.com", Pattern: repository}, {Name: "model"}},
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
	want := []string{"github=minted-for-example/repo", "model=the-token-held-outside"}
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
	if got := d.Policy.Policy.Credentials; len(got) != 2 || got[0].Name != "github" || got[0].Argument != "example/repo" || got[1].Name != "model" || got[1].Argument != "" {
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

// TestAnUnwalledRunIsToldOnce pins a run without a wall: it gets none of the gateway's
// selection, at the start or at a reload, and its user is told once.
func TestAnUnwalledRunIsToldOnce(t *testing.T) {
	cfg, said := selectsConfig(t, `{"version":1,"egress":{"mode":"enforce","allow":["git.example"]}}`)
	cfg.Wall = false
	r := open(t, cfg)
	if len(r.Uses()) != 0 || len(r.Policy().Policy.Credentials) != 0 {
		t.Errorf("uses %v, credentials %v", r.Uses(), r.Policy().Policy.Credentials)
	}
	d, err := reload(t, r, served(`{"version":1,"egress":{"mode":"enforce","allow":["git.example","b.example"]}}`, digest('2')))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Uses) != 0 {
		t.Errorf("the reload's uses %v", d.Uses)
	}
	line := "run " + runID + ": the gateway selects credentials for a walled run alone: this run has no wall and gets none"
	said.mu.Lock()
	n := 0
	for _, l := range said.said {
		if l == line {
			n++
		}
	}
	said.mu.Unlock()
	if n != 1 {
		t.Errorf("the line %d times in %v", n, said.said)
	}
}

// TestAnEntryMatchesTheWholeValue pins the pattern to the label's whole value: a value
// that holds one repository and more gives no credential of the entry, and its user is
// told.
func TestAnEntryMatchesTheWholeValue(t *testing.T) {
	for _, value := range []string{"a/b,c/d", "a/b c/d", " a/b", "a/b\n"} {
		cfg, said := selectsConfig(t, `{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]}}`)
		cfg.Labels["repository"] = value
		r := open(t, cfg)
		if uses := r.Uses(); len(uses) != 1 || uses[0].Name != "model" {
			t.Errorf("%q: uses %v", value, uses)
		}
		shown := strings.ReplaceAll(value, "\n", " ")
		if !said.reported("run " + runID + ": the run's label repository=" + shown + " is no argument github takes: it gets no github") {
			t.Errorf("%q: reported %v", value, said.said)
		}
		if strings.Contains(strings.Join(said.said, "\n"), "minted") {
			t.Errorf("%q: a report holds a token", value)
		}
	}
}

// TestALabelsValueIsPrintedWithoutItsControlCharacters pins the lines that print a
// label's value: a newline and an escape in it come out as spaces, so the value can
// neither start a line of its own nor reach the reader's terminal as an escape.
func TestALabelsValueIsPrintedWithoutItsControlCharacters(t *testing.T) {
	for name, c := range map[string]struct {
		label, value, line string
	}{
		"the repository": {"repository", "a/b\nrun x: forged\x1b[2J", "the run's label repository=a/b run x: forged [2J is no argument github takes: it gets no github"},
		"the forge":      {"forge", "git.example\nrun x: forged\x1b[2J", "the gateway selects github for the forge github.com, and the run's forge is git.example run x: forged [2J: it gets no github"},
	} {
		cfg, said := selectsConfig(t, `{"version":1,"egress":{"mode":"enforce","allow":["git.example","api.model.example"]}}`)
		cfg.Labels[c.label] = c.value
		open(t, cfg)
		if !said.reported("run " + runID + ": " + c.line) {
			t.Errorf("%s: reported %q", name, said.said)
		}
		for _, l := range said.said {
			if strings.ContainsAny(l, "\n\x1b") {
				t.Errorf("%s: a line holds a control character: %q", name, l)
			}
		}
	}
}

// TestTheNodesCredentialsCapTheGatewaysSelection pins the node's credentials member as
// the cap of the gateway's selection, the same whether the server's run configuration
// has a security_policy that selects none or has none, the node's policy then the
// run's: a member that lists none, and one that does not list a selected credential,
// are no run, with the same refusal; no member caps nothing.
func TestTheNodesCredentialsCapTheGatewaysSelection(t *testing.T) {
	const text = "the gateway selects the credentials github, which the node's policy does not list"
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
			"no member":               {nil, "", []string{"github", "model"}},
			"a member listing none":   {[]run.PolicyCredential{}, "the gateway selects the credentials github, model, which the node's policy does not list", nil},
			"a member without github": {[]run.PolicyCredential{{Name: "model"}}, text, nil},
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
