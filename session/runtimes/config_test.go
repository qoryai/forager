package runtimes_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
)

// TestTOMLValueEscapesQuotesAndControlCharacters pins the TOML writer: a string is a
// basic string on one line, with a quote, a backslash and every control character
// escaped, the short escapes where TOML has one and \uXXXX otherwise; a bool and an
// integer are bare; a string that is not UTF-8, and a value of another type, are
// errors.
func TestTOMLValueEscapesQuotesAndControlCharacters(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		{"qory", `"qory"`},
		{"", `""`},
		{`say "hi"`, `"say \"hi\""`},
		{`C:\path\`, `"C:\\path\\"`},
		{"a\nb\rc\td\be\ff", `"a\nb\rc\td\be\ff"`},
		{"nul\x00 esc\x1b del\x7f", `"nul\u0000 esc\u001B del\u007F"`},
		{"https://api.model.example/v1?a=b&c=\"d\"", `"https://api.model.example/v1?a=b&c=\"d\""`},
		{"ünïcode ✓", `"ünïcode ✓"`},
		{"\u2028 stays", "\"\u2028 stays\""},
		{true, "true"},
		{false, "false"},
		{int64(-9007199254740991), "-9007199254740991"},
		{42, "42"},
	} {
		got, err := runtimes.TOMLValue(c.in)
		if err != nil || got != c.want {
			t.Errorf("TOMLValue(%q) = %s, %v; want %s", c.in, got, err, c.want)
		}
		if strings.ContainsAny(got, "\r\n\x00") {
			t.Errorf("TOMLValue(%q) = %q has a line break or a NUL", c.in, got)
		}
	}
	for _, bad := range []any{"\xff\xfe", 1.5, nil, []string{"a"}} {
		if got, err := runtimes.TOMLValue(bad); err == nil {
			t.Errorf("TOMLValue(%#v) = %s; want an error", bad, got)
		}
	}
}

// TestConfigArgsPassesEachSettingAsAPairSortedByKey pins the arguments of a config:
// the flag and key=value for each fixed setting and each setting the session sets,
// sorted by key, none for a config without settings, and an error for a setting that
// is fixed too or has a value TOML has no form for.
func TestConfigArgsPassesEachSettingAsAPairSortedByKey(t *testing.T) {
	c := runtimes.Config{Flag: "--config", Fixed: map[string]any{"z.on": true, "a.name": "it's \"x\"", "m.n": int64(3)}}
	got, err := runtimes.ConfigArgs(c, map[string]any{"p.url": "https://e.example/v1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--config", `a.name="it's \"x\""`, "--config", "m.n=3", "--config", `p.url="https://e.example/v1"`, "--config", "z.on=true"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ConfigArgs = %q; want %q", got, want)
	}
	if got, err := runtimes.ConfigArgs(runtimes.Config{Flag: "-c"}, nil); err != nil || got != nil {
		t.Errorf("no settings: %q, %v; want none", got, err)
	}
	if _, err := runtimes.ConfigArgs(c, map[string]any{"m.n": "x"}); err == nil || !strings.Contains(err.Error(), "m.n") {
		t.Errorf("a setting that is fixed too: %v", err)
	}
	if _, err := runtimes.ConfigArgs(c, map[string]any{"p.url": "\xff"}); err == nil || !strings.HasPrefix(err.Error(), "give the setting p.url a string in UTF-8") {
		t.Errorf("a value that is not UTF-8: %v", err)
	}
}

// TestADescriptorSaysHowItTakesSettingsThroughTheOptionalInterface pins that a
// descriptor's config reaches the session through [runtimes.Configs], as a copy, and
// that a descriptor without it reports none.
func TestADescriptorSaysHowItTakesSettingsThroughTheOptionalInterface(t *testing.T) {
	rt, err := runtimes.Described("other-agent.yaml", []byte(other), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := rt.(runtimes.Configs).Config(); ok || c.Flag != "" {
		t.Errorf("a descriptor without config: %+v, %v", c, ok)
	}
	rt, err = runtimes.Described("other-agent.yaml", []byte(other+"config: {flag: --config, fixed: {a.b: on, n: 2}}\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := rt.(runtimes.Configs).Config()
	if !ok || c.Flag != "--config" || !reflect.DeepEqual(c.Fixed, map[string]any{"a.b": "on", "n": int64(2)}) {
		t.Fatalf("config %+v, %v", c, ok)
	}
	c.Fixed["a.b"] = "changed"
	if again, _ := rt.(runtimes.Configs).Config(); again.Fixed["a.b"] != "on" {
		t.Error("a change to the returned config reached the descriptor")
	}
}

// TestALaunchMayNotSetASettingTheSessionPasses pins the check of config.flag: an
// argument pair that sets a fixed key or the endpoint's setting, as "flag k=v" or
// "flag=k=v", with spaces around the key, under a key, or over one, is refused with an
// error that starts with the fix and contains no value; other pairs, a flag after --,
// and a runtime without config pass.
func TestALaunchMayNotSetASettingTheSessionPasses(t *testing.T) {
	const value = "value-not-shown"
	doc := "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n" +
		"model:\n  formats: [openai-responses]\n  model: {flag: --model}\n  endpoint: {setting: providers.qory.base_url}\n" +
		"  keys: [{format: openai-responses, auth: {scheme: bearer}, variable: AMP_KEY}]\n" +
		"config: {flag: --set, fixed: {provider: qory, providers.qory.name: qory, search: off}}\n"
	rt, err := runtimes.Described("amp.yaml", []byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := rt.(runtimes.ArgsChecker)
	if !ok {
		t.Fatal("a described runtime is no ArgsChecker")
	}
	for _, args := range [][]string{
		{"run", "--set", "provider=" + value},
		{"run", "--set=provider=" + value},
		{"--set", " search =" + value},
		{"--set", "providers.qory.base_url=" + value},
		{"--set", "providers.qory.name.x=" + value},
		{"--set", "providers.qory={name=\"" + value + "\"}"},
		{"--set", "providers=" + value},
	} {
		err := c.CheckArgs(args)
		if err == nil || !strings.HasPrefix(err.Error(), "remove the --set pair") || strings.Contains(err.Error(), value) {
			t.Errorf("%q: %v; want a refusal that starts with the fix and contains no value", args, err)
		}
	}
	for _, args := range [][]string{
		nil,
		{"run", "--set", "model=x", "--set=effort=high", "--model", "provider"},
		{"run", "--set", "provider_extra=x", "--set", "providers.other.name=x"},
		{"run", "--", "--set", "provider=x"},
		{"run", "--set"},
	} {
		if err := c.CheckArgs(args); err != nil {
			t.Errorf("%q: %v; want no refusal", args, err)
		}
	}
	plain, err := runtimes.Described("other-agent.yaml", []byte(other), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.(runtimes.ArgsChecker).CheckArgs([]string{"--config", "model_provider=x", "--set", "provider=x"}); err != nil {
		t.Errorf("a runtime without config: %v; want no refusal", err)
	}
}
