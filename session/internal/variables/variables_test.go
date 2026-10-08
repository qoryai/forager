package variables_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/refusal"
	"github.com/qoryai/runner/session/internal/variables"
)

// claude is what the Claude Code descriptor declares and denies, as a run passes it.
var claude = variables.Inputs{
	RuntimeDenies: []string{"ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR"},
	Runtime:       []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"},
}

func resolve(t *testing.T, in variables.Inputs) variables.Resolved {
	t.Helper()
	got, err := variables.Resolve(in)
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

// record is the record of a resolution, one line per name: the name, the source that
// won after <- when one did, and each loss as source:why.
func record(applied []variables.Entry) []string {
	out := []string{}
	for _, e := range applied {
		line := e.Name
		if e.From != "" {
			line += "<-" + e.From
		}
		for _, l := range e.Lost {
			line += " " + l.From + ":" + l.Why
		}
		out = append(out, line)
	}
	return out
}

// TestTheHighestRungWins pins the order of the sources, name by name, the highest
// first: the fixed names, the server's, the run's, the machine's, the harness's
// defaults, the inherited environment. Each pair that can collide is here, the losing
// value is out of Env and in the record with overridden, a fixed name wins over every
// other source with fixed, and within one source a later value replaces an earlier
// one.
func TestTheHighestRungWins(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     variables.Inputs
		env    []string
		record []string
	}{
		{"apiary over run", variables.Inputs{Server: map[string]string{"LOG_LEVEL": "info"}, Run: []string{"LOG_LEVEL=debug"}},
			[]string{"LOG_LEVEL=info"}, []string{"LOG_LEVEL<-apiary run:overridden"}},
		{"run over machine", variables.Inputs{Run: []string{"BUILD_NUMBER=7"}, Machine: []string{"BUILD_NUMBER=1"}},
			[]string{"BUILD_NUMBER=7"}, []string{"BUILD_NUMBER<-run machine:overridden"}},
		{"machine over harness", variables.Inputs{Machine: []string{"HARNESS_PROFILE=ci"}, Defaults: []string{"HARNESS_PROFILE=nextjs"}},
			[]string{"HARNESS_PROFILE=ci"}, []string{"HARNESS_PROFILE<-machine harness:overridden"}},
		{"harness over shell", variables.Inputs{Defaults: []string{"HARNESS_PROFILE=nextjs"}, Shell: []string{"HARNESS_PROFILE=python", "HOME=/home/dev"}},
			[]string{"HARNESS_PROFILE=nextjs"}, []string{"HARNESS_PROFILE<-harness shell:overridden"}},
		{"apiary over harness", variables.Inputs{Server: map[string]string{"HARNESS_PROFILE": "python"}, Defaults: []string{"HARNESS_PROFILE=nextjs"}},
			[]string{"HARNESS_PROFILE=python"}, []string{"HARNESS_PROFILE<-apiary harness:overridden"}},
		{"apiary over shell", variables.Inputs{Server: map[string]string{"NODE_ENV": "test"}, Shell: []string{"NODE_ENV=development"}},
			[]string{"NODE_ENV=test"}, []string{"NODE_ENV<-apiary shell:overridden"}},
		{"every source on one name", variables.Inputs{
			Server: map[string]string{"LOG_LEVEL": "info"}, Run: []string{"LOG_LEVEL=debug"}, Machine: []string{"LOG_LEVEL=warn"},
			Defaults: []string{"LOG_LEVEL=error"}, Shell: []string{"LOG_LEVEL=trace"},
		}, []string{"LOG_LEVEL=info"}, []string{"LOG_LEVEL<-apiary run:overridden machine:overridden harness:overridden shell:overridden"}},
		{"fixed over each", variables.Inputs{
			Fixed:  []string{"CODEX_HOME=/run/home"},
			Server: map[string]string{"CODEX_HOME": "a"}, Run: []string{"CODEX_HOME=b"}, Machine: []string{"CODEX_HOME=c"},
			Defaults: []string{"CODEX_HOME=d"}, Shell: []string{"CODEX_HOME=e"},
		}, nil, []string{"CODEX_HOME<-fixed apiary:fixed run:fixed machine:fixed harness:fixed shell:fixed"}},
		{"the runner's names and a placeholder are fixed", variables.Inputs{
			Own: []string{"CLAUDE_SETTINGS_HINT"}, Placeholders: []string{"GITHUB_TOKEN"},
			Server: map[string]string{"CLAUDE_SETTINGS_HINT": "x", "GITHUB_TOKEN": "x"}, Machine: []string{"CLAUDE_SETTINGS_HINT=y"},
		}, nil, []string{"CLAUDE_SETTINGS_HINT<-fixed apiary:fixed machine:fixed", "GITHUB_TOKEN<-fixed apiary:fixed"}},
		{"a later value of one source replaces an earlier", variables.Inputs{Run: []string{"A=1", "B=2", "A=3"}, Machine: []string{"C=1", "C=2"}},
			[]string{"A=3", "B=2", "C=2"}, []string{"A<-run", "B<-run", "C<-machine"}},
		{"names compare exactly", variables.Inputs{Server: map[string]string{"Region": "eu"}, Run: []string{"REGION=us"}},
			[]string{"REGION=us", "Region=eu"}, []string{"REGION<-run", "Region<-apiary"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.Walled = true
			got := resolve(t, tc.in)
			want(t, "env", got.Env, tc.env)
			want(t, "record", record(got.Applied), tc.record)
		})
	}
}

// TestTheDenyListCoversEverySourceBelowTheFixedNames pins the deny list over the
// server's, the run's, the machine's and the harness's defaults alike: the built-in
// names and patterns in any case, the runtime's denies and the node's own entries. A
// denied value is left out and in the record with denied, and the inherited
// environment's value, which no entry matches against, then applies.
func TestTheDenyListCoversEverySourceBelowTheFixedNames(t *testing.T) {
	in := claude
	in.Walled = true
	in.Deny = []string{"LEGACY_SETTING", "ACME_*_KEY"}
	in.Server = map[string]string{"PATH": "/srv", "no_proxy": "x", "QORY_ANYTHING": "x", "ANTHROPIC_BASE_URL": "x", "legacy_setting": "x", "ACME_SIGNING_KEY": "x", "NODE_ENV": "test"}
	in.Run = []string{"PATH=/run", "DOCKER_HOST=x", "CLAUDE_CONFIG_DIR=x", "ACME__KEY=x", "PATHS=kept"}
	in.Machine = []string{"PATH=/machine", "SSL_CERT_DIR=x", "anthropic_base_url=x", "LEGACY_SETTING=x"}
	in.Defaults = []string{"PATH=/harness", "Http_Proxy=x", "CLAUDE_CONFIG_DIR=x", "ACME_SIGNING_KEY=x"}
	in.Shell = []string{"PATH=/usr/bin:/bin"}
	got := resolve(t, in)
	want(t, "env", got.Env, []string{"NODE_ENV=test", "PATHS=kept"})
	want(t, "record", record(got.Applied), []string{
		"ACME_SIGNING_KEY apiary:denied harness:denied",
		"ACME__KEY run:denied",
		"ANTHROPIC_BASE_URL apiary:denied",
		"CLAUDE_CONFIG_DIR run:denied harness:denied",
		"DOCKER_HOST run:denied",
		"Http_Proxy harness:denied",
		"LEGACY_SETTING machine:denied",
		"NODE_ENV<-apiary",
		"PATH<-shell apiary:denied run:denied machine:denied harness:denied",
		"PATHS<-run",
		"QORY_ANYTHING apiary:denied",
		"SSL_CERT_DIR machine:denied",
		"anthropic_base_url machine:denied",
		"legacy_setting apiary:denied",
		"no_proxy apiary:denied",
	})
}

// TestTheHarnesssComputedValuesTakeTheBuiltinListAlone pins the deny list on the
// values the harness computes: an entry of denied-variables.json leaves one out, and
// the record lists it as a fixed value denied; the runtime's denies and the node's own
// entries leave it in, and it then wins over every other source of its name.
func TestTheHarnesssComputedValuesTakeTheBuiltinListAlone(t *testing.T) {
	in := claude
	in.Walled = true
	in.Deny = []string{"LEGACY_SETTING"}
	in.Fixed = []string{"DOCKER_HOST=unix:///run/home/docker.sock", "NODE_EXTRA_CA_CERTS=/run/home/ca.pem", "CLAUDE_CONFIG_DIR=/run/home/.claude", "LEGACY_SETTING=/run/home/legacy", "CODEX_HOME=/run/home"}
	in.Server = map[string]string{"LEGACY_SETTING": "x"}
	in.Run = []string{"DOCKER_HOST=x"}
	got := resolve(t, in)
	want(t, "fixed", got.Fixed, []string{"CLAUDE_CONFIG_DIR=/run/home/.claude", "LEGACY_SETTING=/run/home/legacy", "CODEX_HOME=/run/home"})
	want(t, "env", got.Env, nil)
	want(t, "record", record(got.Applied), []string{
		"DOCKER_HOST fixed:denied run:denied",
		"LEGACY_SETTING<-fixed apiary:denied",
		"NODE_EXTRA_CA_CERTS fixed:denied",
	})
}

// TestAnUnwalledRun pins variables.unwalled: under ignore, the default, every server
// variable is left out with unwalled and the run's own value, --env, applies; under
// accept, the server's apply as in a walled run, the deny list first, and win over the
// run's.
func TestAnUnwalledRun(t *testing.T) {
	for _, mode := range []string{"", variables.Ignore} {
		in := claude
		in.Unwalled = mode
		in.Server = map[string]string{"NODE_ENV": "test", "PATH": "/srv/bin", "LOG_LEVEL": "info"}
		in.Run = []string{"LOG_LEVEL=debug"}
		in.Shell = []string{"NODE_ENV=development", "EDITOR=vi"}
		got := resolve(t, in)
		want(t, "env under "+mode, got.Env, []string{"LOG_LEVEL=debug"})
		want(t, "record under "+mode, record(got.Applied), []string{"LOG_LEVEL<-run apiary:unwalled", "NODE_ENV<-shell apiary:unwalled", "PATH apiary:unwalled"})
	}
	in := claude
	in.Unwalled = variables.Accept
	in.Server = map[string]string{"NODE_ENV": "test", "https_proxy": "http://elsewhere:3128", "ANTHROPIC_BASE_URL": "https://elsewhere.example", "LOG_LEVEL": "info"}
	in.Run = []string{"LOG_LEVEL=debug"}
	got := resolve(t, in)
	want(t, "env under accept", got.Env, []string{"LOG_LEVEL=info", "NODE_ENV=test"})
	want(t, "record under accept", record(got.Applied), []string{"ANTHROPIC_BASE_URL apiary:denied", "LOG_LEVEL<-apiary run:overridden", "NODE_ENV<-apiary", "https_proxy apiary:denied"})
}

// TestWhichNamesTheRecordLists pins the names in the record: every name the server,
// the run, the machine or the harness's defaults set; a fixed name only when it won
// over one of those; a name of the inherited environment only when one of those set
// it too; a variable the runtime declares, which behind a wall goes in empty when
// nothing applies, only when a source set it, with no source that won.
func TestWhichNamesTheRecordLists(t *testing.T) {
	in := claude
	in.Walled = true
	in.Own = []string{"QORY_RUN_ID", "HTTPS_PROXY", "CLAUDE_SETTINGS_HINT"}
	in.Fixed = []string{"CODEX_HOME=/run/home"}
	in.Shell = []string{"HOME=/home/dev", "HTTPS_PROXY=http://elsewhere:3128", "CODEX_HOME=/home/dev/.codex", "EDITOR=vi"}
	in.Server = map[string]string{"ANTHROPIC_API_KEY": "x", "EDITOR": "nano"}
	in.Defaults = []string{"CLAUDE_CODE_OAUTH_TOKEN=a-fake-credential"}
	got := resolve(t, in)
	want(t, "record", record(got.Applied), []string{"ANTHROPIC_API_KEY apiary:denied", "CLAUDE_CODE_OAUTH_TOKEN<-harness", "EDITOR<-apiary shell:overridden"})
	want(t, "env", got.Env, []string{"CLAUDE_CODE_OAUTH_TOKEN=a-fake-credential", "EDITOR=nano"})
}

// TestTheServersValueOfWhatStaysOutsideIsLeftOut pins the server's values the run
// leaves out besides the deny list: a variable the runtime declares or reserves and
// one a value of the machine's is read from, denied, while the node's value of either
// applies; a node value of a declared name passes, and only the server's is left out.
func TestTheServersValueOfWhatStaysOutsideIsLeftOut(t *testing.T) {
	in := claude
	in.Unwalled = variables.Accept
	in.ReadFrom = []string{"SENTRY_AUTH_SOURCE"}
	in.Server = map[string]string{"ANTHROPIC_AUTH_TOKEN": "x", "SENTRY_AUTH_SOURCE": "x"}
	in.Run = []string{"ANTHROPIC_AUTH_TOKEN=a-fake-credential"}
	in.Shell = []string{"SENTRY_AUTH_SOURCE=the-machine-value"}
	got := resolve(t, in)
	want(t, "env", got.Env, []string{"ANTHROPIC_AUTH_TOKEN=a-fake-credential"})
	want(t, "record", record(got.Applied), []string{"ANTHROPIC_AUTH_TOKEN<-run apiary:denied", "SENTRY_AUTH_SOURCE<-shell apiary:denied"})
}

// TestRefusalsComeFirst pins that Resolve refuses before it resolves, over every value
// the node passes: behind a wall a QORY_ name from the run, the machine, the harness's
// defaults or its computed values is variable_reserved, not denied, and so is a
// variable a machine value is read from; in any run a placeholder's name from any of
// them is placeholder_conflict. Without a wall a QORY_ name of the run's is denied.
func TestRefusalsComeFirst(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     variables.Inputs
		code   string
		refuse []string
	}{
		{"--env", variables.Inputs{Walled: true, Run: []string{"QORY_X=1"}}, refusal.VariableReserved, []string{"QORY_X"}},
		{"wall.env", variables.Inputs{Walled: true, Machine: []string{"QORY_X=1"}}, refusal.VariableReserved, []string{"QORY_X"}},
		{"a default", variables.Inputs{Walled: true, Defaults: []string{"QORY_HARNESS_HOME=/h"}}, refusal.VariableReserved, []string{"QORY_HARNESS_HOME"}},
		{"a computed value", variables.Inputs{Walled: true, Fixed: []string{"QORY_HARNESS_HOME=/h"}}, refusal.VariableReserved, []string{"QORY_HARNESS_HOME"}},
		{"what a machine value is read from", variables.Inputs{Walled: true, ReadFrom: []string{"MODEL_SOURCE"}, Machine: []string{"MODEL_SOURCE=x"}}, refusal.VariableReserved, []string{"MODEL_SOURCE"}},
		{"a placeholder from --env", variables.Inputs{Placeholders: []string{"GITHUB_TOKEN"}, Run: []string{"GITHUB_TOKEN=x"}}, refusal.PlaceholderConflict, []string{"GITHUB_TOKEN"}},
		{"a placeholder from wall.env", variables.Inputs{Walled: true, Placeholders: []string{"GITHUB_TOKEN"}, Machine: []string{"GITHUB_TOKEN=x"}}, refusal.PlaceholderConflict, []string{"GITHUB_TOKEN"}},
		{"a placeholder from a default", variables.Inputs{Walled: true, Placeholders: []string{"GITHUB_TOKEN"}, Defaults: []string{"GITHUB_TOKEN=x"}}, refusal.PlaceholderConflict, []string{"GITHUB_TOKEN"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := variables.Resolve(tc.in)
			var r *accesskey.Refusal
			if !errors.As(err, &r) || r.Code != tc.code || !slices.Equal(r.Names, tc.refuse) {
				t.Errorf("%v, want %s %q", err, tc.code, tc.refuse)
			}
		})
	}
	got := resolve(t, variables.Inputs{Run: []string{"QORY_HARNESS_HOME=/h", "QORY_X=1"}})
	want(t, "unwalled", record(got.Applied), []string{"QORY_HARNESS_HOME run:denied", "QORY_X run:denied"})
}

// TestDenyEntries pins the grammar of the node's deny entries and the matching rule: a
// whole name, regardless of case, * matching any run of characters, the empty one
// included, anywhere in the entry.
func TestDenyEntries(t *testing.T) {
	for _, bad := range []string{"", "*", "**", "A-B", "A B", "A=B", strings.Repeat("A", 129)} {
		if err := variables.CheckDeny([]string{bad}); err == nil {
			t.Errorf("the entry %q was accepted", bad)
		}
		if _, err := variables.Resolve(variables.Inputs{Deny: []string{bad}}); err == nil {
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
	if _, err := variables.Resolve(variables.Inputs{Unwalled: "sometimes"}); err == nil {
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
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != tc.code || !slices.Equal(r.Names, tc.names) {
			t.Errorf("%q, walled %v: %#v, want %s %q", tc.env, tc.walled, err, tc.code, tc.names)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error quotes a value: %v", err)
		}
	}
}
