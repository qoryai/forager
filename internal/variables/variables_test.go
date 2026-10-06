package variables_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/runner/internal/refusal"
	"github.com/qoryai/runner/internal/variables"
)

// claude is what the Claude Code descriptor declares and denies, as a run passes it.
var claude = variables.Run{
	RuntimeDenies: []string{"ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR"},
	Runtime:       []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"},
}

func resolve(t *testing.T, r variables.Run) variables.Resolved {
	t.Helper()
	got, err := variables.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func want(t *testing.T, what string, got, want []string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got == nil || !slices.Equal(got, want) {
		t.Errorf("%s: %q, want %q", what, got, want)
	}
}

// TestAnUnwalledRunIgnoresTheServerByDefault pins an unwalled run with
// variables.unwalled unset or ignore: every server variable is left out and reported
// as unwalled, the deny list aside, and the node's own variables are the run's, a name
// the server also sends included.
func TestAnUnwalledRunIgnoresTheServerByDefault(t *testing.T) {
	for _, mode := range []string{"", variables.Ignore} {
		r := claude
		r.Unwalled = mode
		r.Server = map[string]string{"NODE_ENV": "test", "PATH": "/srv/bin", "APP_REGION": "eu-west-1"}
		r.Node = []string{"NODE_ENV=development", "EDITOR=vi"}
		got := resolve(t, r)
		want(t, "unwalled", got.Unwalled, []string{"APP_REGION", "NODE_ENV", "PATH"})
		want(t, "names", got.Names, []string{"EDITOR", "NODE_ENV"})
		want(t, "env", got.Env, []string{"EDITOR=vi", "NODE_ENV=development"})
		want(t, "denied", got.Denied, nil)
		want(t, "node_ignored", got.NodeIgnored, nil)
	}
}

// TestAnUnwalledRunThatAcceptsAppliesTheDenyList pins variables.unwalled: accept: the
// server's variables apply as in a walled run, the deny list first.
func TestAnUnwalledRunThatAcceptsAppliesTheDenyList(t *testing.T) {
	r := claude
	r.Unwalled = variables.Accept
	r.Server = map[string]string{"NODE_ENV": "test", "https_proxy": "http://elsewhere:3128", "ANTHROPIC_BASE_URL": "https://elsewhere.example"}
	got := resolve(t, r)
	want(t, "names", got.Names, []string{"NODE_ENV"})
	want(t, "denied", got.Denied, []string{"ANTHROPIC_BASE_URL", "https_proxy"})
	want(t, "unwalled", got.Unwalled, nil)
}

// TestAWalledRunLeavesOutWhatIsDeniedOrSetOtherwise pins every reason a walled run
// leaves a server variable out, each reported in denied: the built-in names and
// patterns in any case, the runtime's denies, the node's own entries, a name the
// runtime declares or reserves, a placeholder, a variable a machine value is read from,
// and a name the runner sets. Every other server variable applies.
func TestAWalledRunLeavesOutWhatIsDeniedOrSetOtherwise(t *testing.T) {
	r := claude
	r.Walled = true
	r.Deny = []string{"LEGACY_TOKEN", "ACME_*_KEY"}
	r.Placeholders = []string{"GITHUB_TOKEN"}
	r.Machine = []string{"SENTRY_AUTH_SOURCE"}
	r.Runner = []string{"CLAUDE_SETTINGS_HINT", "SSL_CERT_FILE"}
	r.Server = map[string]string{
		"PATH": "x", "no_proxy": "x", "Http_Proxy": "x", "QORY_ACCESS_KEY_SECRET": "x", "qory_anything": "x",
		"SSL_CERT_DIR": "x", "DOCKER_HOST": "x", "DOCKER_CONFIG": "x",
		"anthropic_base_url": "x", "CLAUDE_CONFIG_DIR": "x",
		"legacy_token": "x", "ACME_SIGNING_KEY": "x", "ACME__KEY": "x",
		"ANTHROPIC_API_KEY": "x", "ANTHROPIC_AUTH_TOKEN": "x",
		"GITHUB_TOKEN": "x", "SENTRY_AUTH_SOURCE": "x", "CLAUDE_SETTINGS_HINT": "x",
		"NODE_ENV": "test", "ACME_KEY_ID": "kept", "PATHS": "kept",
	}
	got := resolve(t, r)
	want(t, "names", got.Names, []string{"ACME_KEY_ID", "NODE_ENV", "PATHS"})
	want(t, "env", got.Env, []string{"ACME_KEY_ID=kept", "NODE_ENV=test", "PATHS=kept"})
	want(t, "denied", got.Denied, []string{
		"ACME_SIGNING_KEY", "ACME__KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CONFIG_DIR",
		"CLAUDE_SETTINGS_HINT", "DOCKER_CONFIG", "DOCKER_HOST", "GITHUB_TOKEN", "Http_Proxy", "PATH",
		"QORY_ACCESS_KEY_SECRET", "SENTRY_AUTH_SOURCE", "SSL_CERT_DIR", "anthropic_base_url",
		"legacy_token", "no_proxy", "qory_anything",
	})
	want(t, "unwalled", got.Unwalled, nil)
}

// TestTheServerLeadsTheNodeAddsNames pins the node's variables beside a server's: a
// node variable for a name the run applies the server's value of is left out and
// reported as node_ignored; a node variable for a name whose server value the run
// leaves out, denied or never sent, applies; names compare exactly; and without a
// server the node's variables are the run's, a later one replacing an earlier one.
func TestTheServerLeadsTheNodeAddsNames(t *testing.T) {
	r := claude
	r.Walled = true
	r.Server = map[string]string{"NODE_ENV": "test", "PATH": "/srv/bin", "Region": "eu"}
	r.Node = []string{"NODE_ENV=development", "PATH=/usr/bin:/bin", "REGION=us", "LOG_LEVEL=debug"}
	got := resolve(t, r)
	want(t, "names", got.Names, []string{"LOG_LEVEL", "NODE_ENV", "PATH", "REGION", "Region"})
	want(t, "env", got.Env, []string{"LOG_LEVEL=debug", "NODE_ENV=test", "PATH=/usr/bin:/bin", "REGION=us", "Region=eu"})
	want(t, "denied", got.Denied, []string{"PATH"})
	want(t, "node_ignored", got.NodeIgnored, []string{"NODE_ENV"})

	r.Server = nil
	r.Node = []string{"A=1", "B=2", "A=3"}
	got = resolve(t, r)
	want(t, "env without a server", got.Env, []string{"A=3", "B=2"})
	want(t, "node_ignored without a server", got.NodeIgnored, nil)
}

// TestDenyEntries pins the grammar of the node's deny entries and the matching rule: a
// whole name, regardless of case, * matching any run of characters, the empty one
// included, anywhere in the entry.
func TestDenyEntries(t *testing.T) {
	for _, bad := range []string{"", "*", "**", "A-B", "A B", "A=B", strings.Repeat("A", 129)} {
		if err := variables.CheckDeny([]string{bad}); err == nil {
			t.Errorf("the entry %q was accepted", bad)
		}
		if _, err := variables.Resolve(variables.Run{Deny: []string{bad}}); err == nil {
			t.Errorf("a run with the entry %q resolved", bad)
		}
	}
	if err := variables.CheckDeny([]string{"A", "*_KEY", "A*B*C", strings.Repeat("A", 128), "_*"}); err != nil {
		t.Error(err)
	}
	d, err := variables.List([]string{"*_KEY", "A*B*C", "EXACT", "PRE*"})
	if err != nil {
		t.Fatal(err)
	}
	for name, denied := range map[string]bool{
		"API_KEY": true, "_KEY": true, "api_key": true, "KEY": false, "API_KEYS": false,
		"ABC": true, "AxxBxxC": true, "aBc": true, "AC": false, "ABCD": false, "XABC": false,
		"EXACT": true, "exact": true, "EXACTLY": false, "PRE": true, "PREFIX": true, "XPRE": false,
		"HTTP_PROXY": true, "no_proxy": true, "QORY_X": true, "PATH": true, "Path": true, "NODE_ENV": false,
	} {
		if d.Matches(name) != denied {
			t.Errorf("%s: matched %v, want %v", name, !denied, denied)
		}
	}
	if _, err := variables.Resolve(variables.Run{Unwalled: "sometimes"}); err == nil {
		t.Error("variables.unwalled: sometimes was accepted")
	}
}

// TestTheBuiltinListIsTheContracts pins that the list is denied-variables.json.
func TestTheBuiltinListIsTheContracts(t *testing.T) {
	b, err := variables.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != 1 || !slices.Contains(b.Names, "PATH") || !slices.Contains(b.Patterns, "QORY_*") || !slices.Contains(b.Patterns, "*_PROXY") {
		t.Errorf("read %+v", b)
	}
}

// TestCheckRefusesWhatStaysOutside pins the refusals of a run's own environment, with
// their codes and names and never a value: behind a wall, a QORY_ variable other than
// the two the runner sets, in any case, and a variable a machine value is read from,
// are variable_reserved; in any run, a value for a placeholder is
// placeholder_conflict. Without a wall the first pass, and a variable the runtime
// reads its credential from passes either way.
func TestCheckRefusesWhatStaysOutside(t *testing.T) {
	placeholders, machine := []string{"GITHUB_TOKEN"}, []string{"SENTRY_AUTH_SOURCE"}
	secret := "a-value-no-error-quotes"
	for _, tc := range []struct {
		env    []string
		walled bool
		code   string
		names  []string
	}{
		{[]string{"QORY_ACCESS_KEY_SECRET=" + secret, "QORY_SERVER_SECRET=" + secret}, true, refusal.VariableReserved, []string{"QORY_ACCESS_KEY_SECRET", "QORY_SERVER_SECRET"}},
		{[]string{"qory_lower=" + secret}, true, refusal.VariableReserved, []string{"qory_lower"}},
		{[]string{"SENTRY_AUTH_SOURCE=" + secret}, true, refusal.VariableReserved, []string{"SENTRY_AUTH_SOURCE"}},
		{[]string{"ANTHROPIC_API_KEY=" + secret, "CLAUDE_CODE_OAUTH_TOKEN=" + secret}, true, "", nil},
		{[]string{"GITHUB_TOKEN=" + secret}, true, refusal.PlaceholderConflict, []string{"GITHUB_TOKEN"}},
		{[]string{"GITHUB_TOKEN=" + secret}, false, refusal.PlaceholderConflict, []string{"GITHUB_TOKEN"}},
		{[]string{"QORY_RUN_ID=x", "QORY_RUN_SOCKET=x", "NODE_ENV=test"}, true, "", nil},
		{[]string{"QORY_SERVER_SECRET=" + secret, "ANTHROPIC_API_KEY=" + secret, "SENTRY_AUTH_SOURCE=" + secret}, false, "", nil},
	} {
		err := variables.Check(tc.env, tc.walled, placeholders, machine)
		if tc.code == "" {
			if err != nil {
				t.Errorf("%q, walled %v: %v", tc.env, tc.walled, err)
			}
			continue
		}
		var r *refusal.Error
		if !errors.As(err, &r) || r.Code != tc.code || !slices.Equal(r.Names, tc.names) {
			t.Errorf("%q, walled %v: %#v, want %s %q", tc.env, tc.walled, err, tc.code, tc.names)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error quotes a value: %v", err)
		}
	}
}
