package run_test

import (
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
		if !said.reported("run " + runID + ": the run's label repository=" + value + " is no argument github takes: it gets no github") {
			t.Errorf("%q: reported %v", value, said.said)
		}
		if strings.Contains(strings.Join(said.said, "\n"), "minted") {
			t.Errorf("%q: a report holds a token", value)
		}
	}
}
