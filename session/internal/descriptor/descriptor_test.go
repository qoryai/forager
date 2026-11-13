package descriptor_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/session/internal/descriptor"
)

// TestAnExpressionIsRefused pins that a descriptor matches and copies and never
// computes: the schema refuses a document that tries.
func TestAnExpressionIsRefused(t *testing.T) {
	bad, _ := fs.ReadFile(contracts.FS, "fixtures/invalid/descriptor-expression.yaml")
	if _, err := descriptor.Parse("descriptor.yaml", bad); err == nil {
		t.Error("a descriptor with an expression was accepted")
	}
}

// TestMatchIsEqualityOrPresenceOnly pins the match grammar: equality on strings,
// numbers and booleans across YAML and JSON decodings, presence with {present: true},
// nested paths, and no match on a missing path.
func TestMatchIsEqualityOrPresenceOnly(t *testing.T) {
	d := &descriptor.Descriptor{Rules: []descriptor.Rule{
		{Source: "output", Match: map[string]any{"type": "result", "num_turns": 1, "ok": true, "meta.kind": map[string]any{"present": true}}, Type: "dev.qory.runtime.result", Data: map[string]string{"n": "num_turns", "k": "meta.kind", "missing": "nope"}},
	}}
	rec := func(js string) descriptor.Record {
		var m map[string]any
		if err := json.Unmarshal([]byte(js), &m); err != nil {
			t.Fatal(err)
		}
		return descriptor.Record{Source: "output", Record: m}
	}
	events := d.Map(rec(`{"type":"result","num_turns":1,"ok":true,"meta":{"kind":"x"}}`))
	if len(events) != 1 || events[0].Type != "dev.qory.runtime.result" || events[0].Data["n"] != 1.0 || events[0].Data["k"] != "x" {
		t.Fatalf("Map = %+v", events)
	}
	if _, hasMissing := events[0].Data["missing"]; hasMissing {
		t.Error("a missing path produced a field")
	}
	for _, js := range []string{
		`{"type":"result","num_turns":2,"ok":true,"meta":{"kind":"x"}}`,
		`{"type":"result","num_turns":1,"ok":false,"meta":{"kind":"x"}}`,
		`{"type":"result","num_turns":1,"ok":true,"meta":{}}`,
		`{"type":"result","num_turns":"1","ok":true,"meta":{"kind":"x"}}`,
	} {
		if events := d.Map(rec(js)); events != nil {
			t.Errorf("%s matched", js)
		}
	}
	if events := d.Map(descriptor.Record{Source: "hooks", Record: map[string]any{"type": "result"}}); events != nil {
		t.Error("a rule matched a record of another source")
	}
}

// TestClaudeDeclaresItsModelCredential pins that the secrets of the contract's Claude
// Code descriptor decode: no declaration, since its model keys are in model.keys, no
// one_of group, no reserved variable, and the denied and credential file lists.
func TestClaudeDeclaresItsModelCredential(t *testing.T) {
	b, err := fs.ReadFile(contracts.FS, "runtimes/claude/descriptor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := descriptor.Parse("descriptor.yaml", b)
	if err != nil {
		t.Fatal(err)
	}
	s := d.Secrets
	if d.Title != "Claude Code" || s == nil || len(s.Declares) != 0 {
		t.Fatalf("title %q, secrets %+v", d.Title, s)
	}
	if len(s.OneOf) != 0 {
		t.Errorf("one_of = %+v; want none", s.OneOf)
	}
	if len(s.Reserves) != 0 ||
		!reflect.DeepEqual(s.CredentialFiles, []string{"~/.claude/.credentials.json"}) ||
		len(s.Denies) != 23 || s.Denies[0] != "ANTHROPIC_BASE_URL" {
		t.Errorf("reserves %v, credential_files %v, denies %v", s.Reserves, s.CredentialFiles, s.Denies)
	}
}

// TestClaudeRequiresNoModelKey pins that the Claude Code descriptor has no one_of
// group and that its entry in runtimes.json has one_of, empty. The descriptor requires
// neither key, because a server's model key reaches the run only as a sealed
// credential that the run configuration names, and otherwise the run's model key is a
// credential the machine defines.
func TestClaudeRequiresNoModelKey(t *testing.T) {
	b, err := fs.ReadFile(contracts.FS, "runtimes/claude/descriptor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := descriptor.Parse("descriptor.yaml", b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Secrets == nil {
		t.Fatal("the claude descriptor has no secrets")
	}
	if len(d.Secrets.OneOf) != 0 {
		t.Errorf("the claude descriptor has one_of %+v; want none", d.Secrets.OneOf)
	}
	j, err := fs.ReadFile(contracts.FS, descriptor.RuntimesFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runtimes []struct {
			Name  string            `json:"name"`
			OneOf []json.RawMessage `json:"one_of"`
		} `json:"runtimes"`
	}
	if err := json.Unmarshal(j, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range doc.Runtimes {
		if r.Name != "claude" {
			continue
		}
		found = true
		if r.OneOf == nil {
			t.Error("runtimes.json has no one_of list for the claude runtime; want []")
		} else if len(r.OneOf) != 0 {
			t.Errorf("runtimes.json has %d one_of groups for the claude runtime; want []", len(r.OneOf))
		}
	}
	if !found {
		t.Error("runtimes.json has no claude runtime")
	}
}

// TestClaudeDescribesWhereItsModelGoes pins the model section of the contract's Claude
// Code descriptor as it decodes: Anthropic's Messages format, the model id as --model,
// the run's effort as --effort with low to max, an agent's effort in the agent file's
// effort frontmatter with low to max, the endpoint in ANTHROPIC_BASE_URL, the API key
// in ANTHROPIC_API_KEY as x-api-key, the API key as a bearer in ANTHROPIC_AUTH_TOKEN and
// the OAuth token as a bearer with oauth in CLAUDE_CODE_OAUTH_TOKEN, and the 12
// variables that would override the model or effort in overrides.
func TestClaudeDescribesWhereItsModelGoes(t *testing.T) {
	b, err := fs.ReadFile(contracts.FS, "runtimes/claude/descriptor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := descriptor.Parse("descriptor.yaml", b)
	if err != nil {
		t.Fatal(err)
	}
	efforts := []string{"low", "medium", "high", "xhigh", "max"}
	want := &descriptor.Model{
		Formats: []string{"anthropic-messages"},
		Model:   descriptor.Place{Flag: "--model"},
		Effort: &descriptor.Effort{
			Run:   descriptor.ValuedPlace{Place: descriptor.Place{Flag: "--effort"}, Values: efforts},
			Agent: &descriptor.AgentPlace{Frontmatter: "effort", Values: efforts},
		},
		Endpoint: descriptor.Endpoint{Variable: "ANTHROPIC_BASE_URL"},
		Keys: []descriptor.Key{
			{Format: "anthropic-messages", Auth: descriptor.Auth{Scheme: "header", Header: "x-api-key"}, Variable: "ANTHROPIC_API_KEY"},
			{Format: "anthropic-messages", Auth: descriptor.Auth{Scheme: "bearer"}, Variable: "ANTHROPIC_AUTH_TOKEN"},
			{Format: "anthropic-messages", Auth: descriptor.Auth{Scheme: "bearer", OAuth: true}, Variable: "CLAUDE_CODE_OAUTH_TOKEN"},
		},
		Overrides: []string{
			"ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
			"ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_DEFAULT_FABLE_MODEL", "ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL",
			"CLAUDE_CODE_SUBAGENT_MODEL_FORCE", "CLAUDE_CODE_WORKFLOW_SUBAGENT_MODEL", "CLAUDE_CODE_AUTO_MODE_MODEL",
			"CLAUDE_CODE_EFFORT_LEVEL", "CLAUDE_CODE_SUBAGENT_EFFORT", "CLAUDE_CODE_EXTRA_BODY",
		},
	}
	if !reflect.DeepEqual(d.Model, want) {
		t.Errorf("model = %+v; want %+v", d.Model, want)
	}
}

// TestModelDecodesFromYAMLAndJSON pins that a model section decodes the same from either
// reader, each kind of place among them, and that a descriptor without one has none.
func TestModelDecodesFromYAMLAndJSON(t *testing.T) {
	yamlDoc, err := fs.ReadFile(contracts.FS, "fixtures/descriptor/model.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fromYAML, err := descriptor.Parse("model.yaml", yamlDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := contracts.Document("fixtures/descriptor/model.yaml")
	if err != nil {
		t.Fatal(err)
	}
	jsonDoc, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := descriptor.Parse("model.json", jsonDoc)
	if err != nil {
		t.Fatal(err)
	}
	want := &descriptor.Model{
		Formats: []string{"openai-responses", "openai-chat"},
		Model:   descriptor.Place{Setting: "agent.model"},
		Effort: &descriptor.Effort{
			Run:   descriptor.ValuedPlace{Place: descriptor.Place{Variable: "AMP_EFFORT"}, Values: []string{"low", "medium", "high"}},
			Agent: &descriptor.AgentPlace{Frontmatter: "reasoning-effort", Values: []string{"low", "high"}},
		},
		Endpoint: descriptor.Endpoint{Variable: "AMP_BASE_URL"},
		Keys: []descriptor.Key{
			{Format: "openai-responses", Auth: descriptor.Auth{Scheme: "bearer"}, Variable: "AMP_API_KEY"},
			{Format: "openai-responses", Auth: descriptor.Auth{Scheme: "bearer", OAuth: true}, Variable: "AMP_OAUTH_TOKEN"},
			{Format: "openai-chat", Auth: descriptor.Auth{Scheme: "header", Header: "api-key"}, Variable: "AMP_API_KEY"},
		},
		Overrides: []string{"AMP_MODEL", "AMP_EFFORT_LEVEL"},
	}
	for name, d := range map[string]*descriptor.Descriptor{"yaml": fromYAML, "json": fromJSON} {
		if !reflect.DeepEqual(d.Model, want) {
			t.Errorf("%s: model = %+v; want %+v", name, d.Model, want)
		}
	}
	noEffort, err := fs.ReadFile(contracts.FS, "fixtures/descriptor/model-no-effort.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := descriptor.Parse("model-no-effort.yaml", noEffort)
	if err != nil || d.Model == nil || d.Model.Effort != nil || d.Model.Overrides != nil {
		t.Errorf("a model section without effort or overrides: %+v %v", d, err)
	}
	const none = "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n"
	if d, err := descriptor.Parse("amp.yaml", []byte(none)); err != nil || d.Model != nil {
		t.Errorf("a descriptor without a model section: %+v %v", d, err)
	}
}

// TestModelIsChecked pins what the schema holds a model section to, each fixture under
// fixtures/invalid named descriptor-model-* being refused by Parse.
func TestModelIsChecked(t *testing.T) {
	entries, err := fs.ReadDir(contracts.FS, "fixtures/invalid")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "descriptor-model-") {
			continue
		}
		n++
		b, err := fs.ReadFile(contracts.FS, "fixtures/invalid/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := descriptor.Parse(e.Name(), b); err == nil {
			t.Errorf("%s was accepted", e.Name())
		}
	}
	if n < 8 {
		t.Errorf("%d invalid model fixtures; want one per rule: an unknown format, two places, "+
			"empty values, no formats, an extra member, and overrides empty, with a duplicate or with a non-name", n)
	}
}

// TestModelKeysAreChecked pins what Parse holds a model section's keys to beyond the
// schema, each refusal starting with its fix: no key, nor a declared secret, read from
// HOME, LD_PRELOAD, NODE_OPTIONS or BASH_ENV in any case; each key's format one of
// formats; each pair of format and auth once; no key in a variable of denies,
// overrides or the endpoint; and a key in a declared variable with the declaration's
// auth.
func TestModelKeysAreChecked(t *testing.T) {
	const head = "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n"
	const model = "model:\n  formats: [openai-chat]\n  model: {flag: --model}\n  endpoint: {variable: AMP_BASE_URL}\n  overrides: [AMP_MODEL]\n"
	ok := head + "secrets:\n  denies: [AMP_URL]\n  declares: [{id: key, title: Key, name: AMP_API_KEY, hosts: [api.example.com], auth: {scheme: bearer}}]\n" +
		model + "  keys: [{format: openai-chat, auth: {scheme: bearer}, variable: AMP_API_KEY}, {format: openai-chat, auth: {scheme: bearer, oauth: true}, variable: AMP_OAUTH}]\n"
	if _, err := descriptor.Parse("amp.yaml", []byte(ok)); err != nil {
		t.Errorf("a descriptor with keys: %v", err)
	}
	for _, tc := range []struct{ what, doc, want string }{
		{"a key in home, lower case", head + model + "  keys: [{format: openai-chat, auth: {scheme: bearer}, variable: home}]\n",
			"amp.yaml: model.keys: read the key from another variable than home: a key may not be read from HOME, LD_PRELOAD, NODE_OPTIONS or BASH_ENV"},
		{"a declared secret in node_options", head + "secrets:\n  declares: [{id: key, title: Key, name: node_options, hosts: [api.example.com], auth: {scheme: bearer}}]\n",
			"amp.yaml: secrets.declares: read the secret key from another variable than node_options: a secret may not be read from HOME, LD_PRELOAD, NODE_OPTIONS or BASH_ENV"},
		{"a format outside formats", head + model + "  keys: [{format: gemini, auth: {scheme: bearer}, variable: AMP_KEY}]\n",
			"amp.yaml: model.keys: add gemini to model.formats, or remove its keys: model.formats lists only openai-chat"},
		{"a pair twice", head + model + "  keys: [{format: openai-chat, auth: {scheme: header, header: x-key}, variable: AMP_KEY}, {format: openai-chat, auth: {scheme: header, header: X-Key}, variable: AMP_OTHER}]\n",
			"amp.yaml: model.keys: list openai-chat with the header X-Key once: two keys have it"},
		{"a key in denies", head + "secrets:\n  denies: [AMP_URL]\n" + model + "  keys: [{format: openai-chat, auth: {scheme: bearer}, variable: AMP_URL}]\n",
			"amp.yaml: model.keys: read the key from a variable outside denies, overrides and the endpoint: AMP_URL is in denies"},
		{"a key in overrides", head + model + "  keys: [{format: openai-chat, auth: {scheme: bearer}, variable: AMP_MODEL}]\n",
			"amp.yaml: model.keys: read the key from a variable outside denies, overrides and the endpoint: AMP_MODEL is in overrides"},
		{"a key in the endpoint", head + model + "  keys: [{format: openai-chat, auth: {scheme: bearer}, variable: AMP_BASE_URL}]\n",
			"amp.yaml: model.keys: read the key from a variable outside denies, overrides and the endpoint: AMP_BASE_URL is the endpoint"},
		{"another auth than the declaration's", head + "secrets:\n  declares: [{id: key, title: Key, name: AMP_API_KEY, hosts: [api.example.com], auth: {scheme: bearer}}]\n" +
			model + "  keys: [{format: openai-chat, auth: {scheme: header, header: x-key}, variable: AMP_API_KEY}]\n",
			"amp.yaml: model.keys: give AMP_API_KEY the auth of its secrets.declares entry: the two differ"},
	} {
		_, err := descriptor.Parse("amp.yaml", []byte(tc.doc))
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s: %v; want %q", tc.what, err, tc.want)
		}
	}
}

// TestFixedIsChecked pins what a descriptor's fixed variables are held to: the
// schema's bounds, each fixture under fixtures/invalid named descriptor-fixed-* being
// refused; and beyond it, each refusal starting with its fix, no name the built-in
// deny list matches, in any case, and no name the descriptor lists elsewhere. A
// descriptor with fixed variables decodes them, and runtimes.json lists them.
func TestFixedIsChecked(t *testing.T) {
	const head = "version: 1\nruntime: amp\ntitle: Amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n"
	const rest = "secrets:\n  denies: [AMP_URL]\n  declares: [{id: key, title: Key, name: AMP_SECRET, hosts: [api.example.com], auth: {scheme: bearer}}]\n  reserves: [AMP_OTHER]\n" +
		"model:\n  formats: [openai-chat]\n  model: {flag: --model}\n  endpoint: {variable: AMP_BASE_URL}\n  overrides: [AMP_MODEL]\n" +
		"  keys: [{format: openai-chat, auth: {scheme: bearer}, variable: AMP_API_KEY}]\n"
	ok := head + rest + "fixed: {AMP_QUIET: \"1\", AMP_EMPTY: \"\"}\n"
	d, err := descriptor.Parse("amp.yaml", []byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"AMP_QUIET": "1", "AMP_EMPTY": ""}; !reflect.DeepEqual(d.Fixed, want) {
		t.Errorf("fixed = %v; want %v", d.Fixed, want)
	}
	rendered, err := descriptor.Runtimes(fstest.MapFS{"runtimes/amp/descriptor.yaml": {Data: []byte(ok)}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), `"fixed": {
        "AMP_EMPTY": "",
        "AMP_QUIET": "1"
      }`) {
		t.Errorf("runtimes.json does not list the fixed variables by name:\n%s", rendered)
	}
	for _, tc := range []struct{ what, fixed, want string }{
		{"a name of the deny list", "{PATH: /bin}", "amp.yaml: fixed: remove PATH: denied-variables.json lists it, and a descriptor sets no such variable"},
		{"a pattern of the deny list, lower case", "{https_proxy: x}", "amp.yaml: fixed: remove https_proxy: denied-variables.json lists it, and a descriptor sets no such variable"},
		{"a denied name", "{AMP_URL: x}", "amp.yaml: fixed: remove AMP_URL from fixed or from secrets.denies: a variable that fixed sets is in no other list of the descriptor"},
		{"a declared secret", "{AMP_SECRET: x}", "amp.yaml: fixed: remove AMP_SECRET from fixed or from secrets.declares: a variable that fixed sets is in no other list of the descriptor"},
		{"a reserved name", "{AMP_OTHER: x}", "amp.yaml: fixed: remove AMP_OTHER from fixed or from secrets.reserves: a variable that fixed sets is in no other list of the descriptor"},
		{"a key, lower case", "{amp_api_key: x}", "amp.yaml: fixed: remove amp_api_key from fixed or from model.keys: a variable that fixed sets is in no other list of the descriptor"},
		{"the endpoint", "{AMP_BASE_URL: x}", "amp.yaml: fixed: remove AMP_BASE_URL from fixed or from model.endpoint: a variable that fixed sets is in no other list of the descriptor"},
		{"an override", "{AMP_MODEL: x}", "amp.yaml: fixed: remove AMP_MODEL from fixed or from model.overrides: a variable that fixed sets is in no other list of the descriptor"},
	} {
		_, err := descriptor.Parse("amp.yaml", []byte(head+rest+"fixed: "+tc.fixed+"\n"))
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s: %v; want %q", tc.what, err, tc.want)
		}
	}
	entries, err := fs.ReadDir(contracts.FS, "fixtures/invalid")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "descriptor-fixed-") {
			continue
		}
		n++
		b, err := fs.ReadFile(contracts.FS, "fixtures/invalid/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := descriptor.Parse(e.Name(), b); err == nil {
			t.Errorf("%s was accepted", e.Name())
		}
	}
	if n < 4 {
		t.Errorf("%d invalid fixed fixtures; want one per bound: empty, a name that is no name, a line feed and a number", n)
	}
}

// TestSecretsAreChecked pins what a descriptor's secrets are held to, by the schema and
// beyond it: exact hosts, a scheme of the closed set with its header, no secret of its
// own in a declaration's auth, and groups of declared ids, each in one group at most.
// A descriptor without secrets stays valid, and runtimes.json writes a basic
// declaration's username beside its scheme.
func TestSecretsAreChecked(t *testing.T) {
	const head = "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n"
	const key = "  - {id: key, title: Key, name: AMP_KEY, hosts: [api.example.com], auth: {scheme: bearer}}\n"
	if _, err := descriptor.Parse("amp.yaml", []byte(head)); err != nil {
		t.Errorf("a descriptor without secrets: %v", err)
	}
	ok := head + "title: Amp\nsecrets:\n declares:\n" + key +
		"  - {id: alt, title: Alt, name: AMP_ALT, hosts: [api.example.com], paths: [/v2/*], auth: {scheme: header, header: x-key}}\n" +
		"  - {id: git, title: Git, name: AMP_GIT, hosts: [git.example.com], auth: {scheme: basic, username: bot}}\n" +
		" one_of: [{id: model, of: [key, alt]}]\n reserves: [AMP_OTHER]\n denies: [AMP_URL]\n credential_files: [~/.amp/key, /etc/amp/key]\n"
	if _, err := descriptor.Parse("amp.yaml", []byte(ok)); err != nil {
		t.Errorf("a descriptor with secrets: %v", err)
	}
	rendered, err := descriptor.Runtimes(fstest.MapFS{"runtimes/amp/descriptor.yaml": {Data: []byte(ok)}})
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Runtimes []struct {
			Declares []struct {
				ID   string         `json:"id"`
				Auth map[string]any `json:"auth"`
			} `json:"declares"`
		} `json:"runtimes"`
	}
	if err := json.Unmarshal(rendered, &file); err != nil || len(file.Runtimes) != 1 || len(file.Runtimes[0].Declares) != 3 {
		t.Fatalf("runtimes.json of the descriptor with secrets: %v\n%s", err, rendered)
	}
	if auth := file.Runtimes[0].Declares[2].Auth; !reflect.DeepEqual(auth, map[string]any{"scheme": "basic", "username": "bot"}) {
		t.Errorf("runtimes.json writes the basic declaration's auth as %v; want its scheme and username", auth)
	}
	for name, secrets := range map[string]string{
		"a wildcard host":            " declares:\n  - {id: key, title: Key, name: AMP_KEY, hosts: ['*.example.com'], auth: {scheme: bearer}}\n",
		"an IP literal":              " declares:\n  - {id: key, title: Key, name: AMP_KEY, hosts: [192.0.2.1], auth: {scheme: bearer}}\n",
		"a header scheme, no header": " declares:\n  - {id: key, title: Key, name: AMP_KEY, hosts: [api.example.com], auth: {scheme: header}}\n",
		"a scheme outside the set":   " declares:\n  - {id: key, title: Key, name: AMP_KEY, hosts: [api.example.com], auth: {scheme: digest}}\n",
		"an unknown auth member":     " declares:\n  - {id: key, title: Key, name: AMP_KEY, hosts: [api.example.com], auth: {scheme: bearer, secret: key}}\n",
		"an unknown basic member":    " declares:\n  - {id: key, title: Key, name: AMP_KEY, hosts: [api.example.com], auth: {scheme: basic, username_secret: key}}\n",
		"no hosts":                   " declares:\n  - {id: key, title: Key, name: AMP_KEY, auth: {scheme: bearer}}\n",
		"a relative credential file": " credential_files: [.amp/key]\n",
		"an id declared twice":       " declares:\n" + key + key,
		"an undeclared id":           " declares:\n" + key + " one_of: [{id: model, of: [key, other]}]\n",
		"an id in two groups":        " declares:\n" + key + " one_of: [{id: a, of: [key]}, {id: b, of: [key]}]\n",
		"a group defined twice": " declares:\n" + key + "  - {id: alt, title: Alt, name: AMP_ALT, hosts: [api.example.com], auth: {scheme: bearer}}\n" +
			" one_of: [{id: a, of: [key]}, {id: a, of: [alt]}]\n",
		"a key_form": " declares:\n  - {id: key, title: Key, name: AMP_KEY, hosts: [api.example.com], auth: {scheme: bearer}, key_form: api_key}\n",
	} {
		if _, err := descriptor.Parse("amp.yaml", []byte(head+"secrets:\n"+secrets)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestRuntimesJSONHasModelOnlyWhenDescribed pins that runtimes.json writes a runtime's
// model section as the descriptor has it, and has no model key for a runtime whose
// descriptor has none.
func TestRuntimesJSONHasModelOnlyWhenDescribed(t *testing.T) {
	const head = "version: 1\nruntime: amp\ntitle: Amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n"
	for name, c := range map[string]struct {
		doc  string
		want map[string]any
	}{
		"a descriptor without a model section": {head, nil},
		"a descriptor with one": {head + "model:\n formats: [gemini]\n model: {flag: --model}\n endpoint: {variable: AMP_URL}\n",
			map[string]any{"formats": []any{"gemini"}, "model": map[string]any{"flag": "--model"}, "endpoint": map[string]any{"variable": "AMP_URL"}}},
		"a descriptor with overrides": {head + "model:\n formats: [gemini]\n model: {flag: --model}\n endpoint: {variable: AMP_URL}\n overrides: [AMP_MODEL]\n",
			map[string]any{"formats": []any{"gemini"}, "model": map[string]any{"flag": "--model"}, "endpoint": map[string]any{"variable": "AMP_URL"}, "overrides": []any{"AMP_MODEL"}}},
	} {
		b, err := descriptor.Runtimes(fstest.MapFS{"runtimes/amp/descriptor.yaml": {Data: []byte(c.doc)}})
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Runtimes []map[string]any `json:"runtimes"`
		}
		if err := json.Unmarshal(b, &f); err != nil || len(f.Runtimes) != 1 {
			t.Fatalf("%s: %v\n%s", name, err, b)
		}
		got, has := f.Runtimes[0]["model"]
		switch {
		case c.want == nil && has:
			t.Errorf("%s: runtimes.json has model %v; want no model key", name, got)
		case c.want != nil && !reflect.DeepEqual(got, c.want):
			t.Errorf("%s: runtimes.json has model %v; want %v", name, got, c.want)
		}
	}
}

// TestRuntimesJSONListsTheConfigKeys pins config in runtimes.json: the Codex entry has
// the flag --config and the 13 keys of its config.fixed in the descriptor's order,
// without their values, and Claude Code's entry, whose descriptor has no config, has
// no config member. A descriptor's key order reaches the file whether it is YAML or
// JSON.
func TestRuntimesJSONListsTheConfigKeys(t *testing.T) {
	b, err := fs.ReadFile(contracts.FS, descriptor.RuntimesFile)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Runtimes []map[string]any `json:"runtimes"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"flag": "--config", "fixed": []any{
		"model_provider", "model_providers.qory.name", "model_providers.qory.wire_api", "model_providers.qory.env_key",
		"features.plugins", "features.apps", "analytics.enabled", "feedback.enabled", "check_for_update_on_startup",
		"otel.exporter", "otel.trace_exporter", "otel.metrics_exporter", "web_search",
	}}
	seen := 0
	for _, rt := range f.Runtimes {
		switch rt["name"] {
		case "codex":
			seen++
			if !reflect.DeepEqual(rt["config"], want) {
				t.Errorf("codex config is %v; want %v", rt["config"], want)
			}
		case "claude":
			seen++
			if c, ok := rt["config"]; ok {
				t.Errorf("claude has config %v; want no config member", c)
			}
		}
	}
	if seen != 2 {
		t.Errorf("runtimes.json has %d of codex and claude; want both", seen)
	}
	for name, doc := range map[string]string{
		"amp.yaml": "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
			"config: {flag: --set, fixed: {z.last: 1, a.first: true, m.mid: x}}\n" +
			"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n",
		"amp.json": `{"version": 1, "runtime": "amp", "runtime_version": "1", "sources": {"output": {"format": "jsonl"}},
			"config": {"flag": "--set", "fixed": {"z.last": 1, "a.first": true, "m.mid": "x"}},
			"rules": [{"source": "output", "match": {"type": "end"}, "type": "dev.qory.runtime.ended", "data": {"reason": "why"}}]}`,
	} {
		d, err := descriptor.Parse(name, []byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := d.Config.Keys; !reflect.DeepEqual(got, []string{"z.last", "a.first", "m.mid"}) {
			t.Errorf("%s: keys %q; want the document's order", name, got)
		}
	}
}

// TestRuntimesJSONIsGenerated pins that runtimes.json is exactly what the descriptors
// the contract ships render to, so the file a server vendors cannot drift from them.
func TestRuntimesJSONIsGenerated(t *testing.T) {
	got, err := descriptor.Runtimes(contracts.FS)
	if err != nil {
		t.Fatal(err)
	}
	want, err := fs.ReadFile(contracts.FS, descriptor.RuntimesFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("contracts/forager/v1/%s differs from the descriptors; run go generate ./contracts\n%s",
			descriptor.RuntimesFile, got)
	}
}

// TestEgressHostsAreListed pins that a descriptor's egress_hosts decode and that
// runtimes.json lists them in the descriptor's order, as [] for a descriptor with none,
// and what the schema accepts: 1 to 16 exact DNS names, each once. A declaration's
// hosts are not in the list.
func TestEgressHostsAreListed(t *testing.T) {
	const head = "version: 1\nruntime: amp\ntitle: Amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n" +
		"secrets:\n  declares: [{id: key, title: Key, name: AMP_SECRET, hosts: [secret.example.com], auth: {scheme: bearer}}]\n"
	listed := func(doc string) string {
		t.Helper()
		rendered, err := descriptor.Runtimes(fstest.MapFS{"runtimes/amp/descriptor.yaml": {Data: []byte(doc)}})
		if err != nil {
			t.Fatal(err)
		}
		var file struct {
			Runtimes []struct {
				EgressHosts json.RawMessage `json:"egress_hosts"`
			} `json:"runtimes"`
		}
		if err := json.Unmarshal(rendered, &file); err != nil || len(file.Runtimes) != 1 {
			t.Fatalf("runtimes.json: %v\n%s", err, rendered)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, file.Runtimes[0].EgressHosts); err != nil {
			t.Fatal(err)
		}
		return compact.String()
	}
	if got, want := listed(head), `[]`; got != want {
		t.Errorf("egress_hosts of a descriptor with none = %s; want %s", got, want)
	}
	two := head + "egress_hosts: [b.example.com, a.example.com]\n"
	if got, want := listed(two), `["b.example.com","a.example.com"]`; got != want {
		t.Errorf("egress_hosts = %s; want %s", got, want)
	}
	d, err := descriptor.Parse("amp.yaml", []byte(two))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"b.example.com", "a.example.com"}; !reflect.DeepEqual(d.EgressHosts, want) {
		t.Errorf("EgressHosts = %v; want %v", d.EgressHosts, want)
	}
	hosts := func(n int) string {
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("h%d.example.com", i)
		}
		return "[" + strings.Join(names, ", ") + "]"
	}
	if _, err := descriptor.Parse("amp.yaml", []byte(head+"egress_hosts: "+hosts(16)+"\n")); err != nil {
		t.Errorf("16 hosts: %v", err)
	}
	for name, list := range map[string]string{
		"an empty list":   "[]",
		"17 hosts":        hosts(17),
		"a host twice":    "[a.example.com, a.example.com]",
		"a wildcard host": "['*.example.com']",
		"an IP literal":   "[192.0.2.1]",
		"upper case":      "[API.example.com]",
		"a port":          "['api.example.com:443']",
		"a single label":  "[localhost]",
		"a trailing dot":  "[api.example.com.]",
	} {
		if _, err := descriptor.Parse("amp.yaml", []byte(head+"egress_hosts: "+list+"\n")); err == nil {
			t.Errorf("%s: passed; want a schema failure", name)
		}
	}
}

// TestRuntimesJSONShape pins the members of runtimes.json a server reads: version and
// runtimes; per runtime its name, title, reserves, denies, credential_files, declares,
// one_of, fixed and egress_hosts, every one present, fixed an object of strings; per declaration id, title, name, hosts, auth with its
// scheme, the header of a header scheme and the username of a basic scheme, and paths
// when it has some; per group id, required and of; model when the descriptor has
// one, with formats, model, endpoint with exactly one of its variable and its setting,
// keys whose auth has no account_header or account_claim, and optionally effort, with run
// and optionally agent, each place being exactly one of flag, setting and variable, and
// optionally overrides; and resume when the descriptor has one, with its prefix and its
// path alone. The claude runtime has a model with overrides, its resume's prefix and path, and its fixed
// sets CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC and
// CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL to 1 and CLAUDE_CODE_MAX_RETRIES
// to 15, and nothing else, and its egress_hosts is api.anthropic.com alone. Every built-in descriptor is one runtime, in
// name order.
func TestRuntimesJSONShape(t *testing.T) {
	b, err := fs.ReadFile(contracts.FS, descriptor.RuntimesFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Error("runtimes.json does not end in a newline")
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	members := func(where string, v any, required []string, optional ...string) map[string]any {
		t.Helper()
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s is not an object", where)
		}
		allowed := map[string]bool{}
		for _, k := range required {
			allowed[k] = true
			if _, ok := m[k]; !ok {
				t.Errorf("%s has no %s", where, k)
			}
		}
		for _, k := range optional {
			allowed[k] = true
		}
		for k := range m {
			if !allowed[k] {
				t.Errorf("%s has %s, which the file does not define", where, k)
			}
		}
		return m
	}
	strs := func(where string, v any) []string {
		t.Helper()
		l, ok := v.([]any)
		if !ok {
			t.Fatalf("%s is not a list", where)
		}
		out := []string{}
		for _, e := range l {
			s, ok := e.(string)
			if !ok || s == "" {
				t.Errorf("%s holds %v; want a string", where, e)
			}
			out = append(out, s)
		}
		return out
	}
	// place checks a place: exactly one of flag, setting and variable, and the other
	// members named.
	place := func(v any, other ...string) map[string]any {
		t.Helper()
		m := members("place", v, other, "flag", "setting", "variable")
		kinds := 0
		for _, k := range []string{"flag", "setting", "variable"} {
			if _, ok := m[k]; ok {
				kinds++
			}
		}
		if kinds != 1 {
			t.Errorf("place %v has %d of flag, setting and variable; want one", m, kinds)
		}
		return m
	}
	members("runtimes.json", doc, []string{"version", "runtimes"})
	if doc["version"] != 1.0 {
		t.Errorf("version %v; want 1", doc["version"])
	}
	entries, err := fs.ReadDir(contracts.FS, "runtimes")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []fs.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}
	runtimes, _ := doc["runtimes"].([]any)
	if len(runtimes) != len(dirs) {
		t.Fatalf("%d runtimes for %d descriptors", len(runtimes), len(dirs))
	}
	for i, r := range runtimes {
		rt := members("runtime", r, []string{"name", "title", "reserves", "denies", "credential_files", "declares", "one_of", "fixed", "egress_hosts"}, "model", "config", "resume")
		if rs, ok := rt["resume"]; ok {
			resume := members("resume", rs, []string{"prefix", "path"})
			prefix, _ := resume["prefix"].(string)
			path, _ := resume["path"].(string)
			lead := strings.HasPrefix(prefix, "~/") || strings.HasPrefix(prefix, "/") || strings.HasPrefix(prefix, "${")
			if !lead || !strings.HasSuffix(prefix, "/") || !strings.HasPrefix(path, prefix) {
				t.Errorf("resume of %v is %v; want a prefix under ~/, /, or ${<home_var>}/ ending in / that the path starts with", rt["name"], resume)
			}
		}
		if want := map[string]any{"prefix": "~/.claude/projects/", "path": "~/.claude/projects/{cwd_slug}/{session_id}.jsonl"}; rt["name"] == "claude" && !reflect.DeepEqual(rt["resume"], want) {
			t.Errorf("the claude runtime's resume is %v; want %v", rt["resume"], want)
		}
		if want := map[string]any{"prefix": "${CODEX_HOME}/sessions/", "path": "${CODEX_HOME}/sessions/*/*/*/rollout-*-{session_id}.jsonl"}; rt["name"] == "codex" && !reflect.DeepEqual(rt["resume"], want) {
			t.Errorf("the codex runtime's resume is %v; want %v", rt["resume"], want)
		}
		if rt["name"] != dirs[i].Name() || rt["title"] == "" {
			t.Errorf("runtime %d is %v, %v; want %s and a title", i, rt["name"], rt["title"], dirs[i].Name())
		}
		fixed, ok := rt["fixed"].(map[string]any)
		if !ok {
			t.Errorf("fixed of %v is not an object", rt["name"])
		}
		for name, v := range fixed {
			if _, ok := v.(string); !ok {
				t.Errorf("fixed %s of %v is %v; want a string", name, rt["name"], v)
			}
		}
		if want := map[string]any{"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1", "CLAUDE_CODE_MAX_RETRIES": "15"}; rt["name"] == "claude" && !reflect.DeepEqual(fixed, want) {
			t.Errorf("the claude runtime's fixed is %v; want %v", fixed, want)
		}
		for _, k := range []string{"reserves", "denies", "credential_files"} {
			strs(k, rt[k])
		}
		hosts := strs("egress_hosts", rt["egress_hosts"])
		if want := []string{"api.anthropic.com"}; rt["name"] == "claude" && !reflect.DeepEqual(hosts, want) {
			t.Errorf("the claude runtime's egress_hosts is %v; want %v", hosts, want)
		}
		declares, _ := rt["declares"].([]any)
		for _, d := range declares {
			dc := members("declaration", d, []string{"id", "title", "name", "hosts", "auth"}, "paths")
			strs("hosts", dc["hosts"])
			if p, ok := dc["paths"]; ok {
				strs("paths", p)
			}
			auth := members("auth", dc["auth"], []string{"scheme"}, "header", "username")
			if _, ok := auth["header"]; ok != (auth["scheme"] == "header") {
				t.Errorf("auth %v: a header scheme has a header and no other does", auth)
			}
			if _, ok := auth["username"]; ok != (auth["scheme"] == "basic") {
				t.Errorf("auth %v: a basic scheme has a username and no other does", auth)
			}
		}
		groups, _ := rt["one_of"].([]any)
		for _, g := range groups {
			gr := members("group", g, []string{"id", "required", "of"})
			if _, ok := gr["required"].(bool); !ok {
				t.Errorf("group %v: required is not a boolean", gr["id"])
			}
			strs("of", gr["of"])
		}
		if m, ok := rt["model"]; ok {
			model := members("model", m, []string{"formats", "model", "endpoint"}, "effort", "keys", "overrides")
			strs("formats", model["formats"])
			keys, _ := model["keys"].([]any)
			for _, k := range keys {
				key := members("key", k, []string{"format", "auth", "variable"})
				// A descriptor's auth has no account_header or account_claim: only an
				// API credential of a run configuration has them.
				members("auth", key["auth"], []string{"scheme"}, "header", "username", "oauth")
			}
			if len(keys) == 0 && rt["name"] == "claude" {
				t.Error("the claude runtime's model has no keys")
			}
			if o, ok := model["overrides"]; ok {
				strs("overrides", o)
			} else if rt["name"] == "claude" {
				t.Error("the claude runtime's model has no overrides")
			}
			place(model["model"])
			endpoint := members("endpoint", model["endpoint"], nil, "variable", "setting")
			if _, v := endpoint["variable"]; v == (endpoint["setting"] != nil) {
				t.Errorf("endpoint %v has %d of variable and setting; want one", endpoint, len(endpoint))
			}
			if e, ok := model["effort"]; ok {
				effort := members("effort", e, []string{"run"}, "agent")
				strs("values", place(effort["run"], "values")["values"])
				if a, ok := effort["agent"]; ok {
					strs("values", members("agent", a, []string{"frontmatter", "values"})["values"])
				}
			}
		} else if rt["name"] == "claude" {
			t.Error("the claude runtime has no model")
		}
	}
}

// TestResumeDecodes pins that a descriptor's resume decodes with its members, path_from
// and after optional, that the built-in Claude Code descriptor has the contract's, and
// what Parse returns an error for beyond the schema: a path that does not start with the
// prefix, and a .. segment. runtimes.json lists the prefix and the path alone
// (TestRuntimesJSONShape).
func TestResumeDecodes(t *testing.T) {
	const head = "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n"
	resume := func(path, prefix string) string {
		return head + "resume:\n  path_from: transcript_path\n  path: " + path + "\n  prefix: " + prefix + "\n  args: [--resume, '{session_id}']\n"
	}
	d, err := descriptor.Parse("amp.yaml", []byte(resume("~/.amp/s/{cwd_slug}/{session_id}.jsonl", "~/.amp/s/")))
	if err != nil {
		t.Fatal(err)
	}
	want := &descriptor.Resume{PathFrom: "transcript_path", Path: "~/.amp/s/{cwd_slug}/{session_id}.jsonl", Prefix: "~/.amp/s/", Args: []string{"--resume", "{session_id}"}}
	if !reflect.DeepEqual(d.Resume, want) {
		t.Errorf("Resume = %+v; want %+v", d.Resume, want)
	}
	if d, err := descriptor.Parse("amp.yaml", []byte(head)); err != nil || d.Resume != nil {
		t.Errorf("a descriptor with no resume: %+v, %v; want nil", d.Resume, err)
	}
	starred := head + "resume:\n  path: ~/.amp/s/*/*/run-*-{session_id}.jsonl\n  prefix: ~/.amp/s/\n  args: [resume, '{session_id}']\n  after: exec\n"
	d, err = descriptor.Parse("amp.yaml", []byte(starred))
	if err != nil {
		t.Fatal(err)
	}
	want = &descriptor.Resume{Path: "~/.amp/s/*/*/run-*-{session_id}.jsonl", Prefix: "~/.amp/s/", Args: []string{"resume", "{session_id}"}, After: "exec"}
	if !reflect.DeepEqual(d.Resume, want) {
		t.Errorf("a resume with * and after, without path_from = %+v; want %+v", d.Resume, want)
	}
	// An absolute prefix and path, a home at a fixed place, decode as they are.
	d, err = descriptor.Parse("amp.yaml", []byte(resume("/var/lib/amp/s/{session_id}.jsonl", "/var/lib/amp/s/")))
	if err != nil {
		t.Fatal(err)
	}
	if d.Resume == nil || d.Resume.Prefix != "/var/lib/amp/s/" || d.Resume.Path != "/var/lib/amp/s/{session_id}.jsonl" {
		t.Errorf("an absolute resume = %+v", d.Resume)
	}
	b, err := fs.ReadFile(contracts.FS, "runtimes/claude/descriptor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	claude, err := descriptor.Parse("descriptor.yaml", b)
	if err != nil {
		t.Fatal(err)
	}
	if want := (&descriptor.Resume{PathFrom: "transcript_path", Path: "~/.claude/projects/{cwd_slug}/{session_id}.jsonl", Prefix: "~/.claude/projects/", Args: []string{"--resume", "{session_id}"}}); !reflect.DeepEqual(claude.Resume, want) {
		t.Errorf("the claude descriptor's resume = %+v; want %+v", claude.Resume, want)
	}
	for name, doc := range map[string]string{
		"a path outside the prefix":              resume("~/.amp/other/{session_id}.jsonl", "~/.amp/s/"),
		"a .. in the path":                       resume("~/.amp/s/../{session_id}.jsonl", "~/.amp/s/"),
		"a .. in the prefix":                     resume("~/.amp/../s/{session_id}.jsonl", "~/.amp/../s/"),
		"a path in the home, an absolute prefix": resume("~/.amp/s/{session_id}.jsonl", "/var/lib/amp/s/"),
		"an absolute path, a prefix in the home": resume("/var/lib/amp/s/{session_id}.jsonl", "~/.amp/s/"),
		"a .. in an absolute prefix":             resume("/var/lib/../s/{session_id}.jsonl", "/var/lib/../s/"),
	} {
		if _, err := descriptor.Parse("amp.yaml", []byte(doc)); err == nil || !strings.HasPrefix(err.Error(), "amp.yaml: resume: ") {
			t.Errorf("%s: %v; want an error that starts with the fix", name, err)
		}
	}
	// The schema holds a prefix to ~/ or /: a relative one, or / alone, is no descriptor.
	for _, prefix := range []string{".amp/s/", "/"} {
		if _, err := descriptor.Parse("amp.yaml", []byte(resume(prefix+"{session_id}.jsonl", prefix))); err == nil {
			t.Errorf("the prefix %q was accepted", prefix)
		}
	}
}

// TestAResumeHomeVariableDecodes pins resume.home_var: a prefix and a path that start
// with ${<home_var>}/ decode as they are, the home itself as the prefix included. The
// schema refuses a variable without home_var, a home_var whose prefix or path starts
// with ~/ or /, and a $ anywhere but in that ${<home_var>}/; Parse returns an error that
// starts with the fix for a prefix or path that starts with another variable.
func TestAResumeHomeVariableDecodes(t *testing.T) {
	const head = "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n"
	resume := func(homeVar, path, prefix string) string {
		doc := head + "resume:\n  path: '" + path + "'\n  prefix: '" + prefix + "'\n  args: [resume, '{session_id}']\n"
		if homeVar != "" {
			doc += "  home_var: " + homeVar + "\n"
		}
		return doc
	}
	for _, c := range []struct{ path, prefix string }{
		{"${AMP_HOME}/s/*/rollout-*-{session_id}.jsonl", "${AMP_HOME}/s/"},
		{"${AMP_HOME}/{session_id}.jsonl", "${AMP_HOME}/"},
	} {
		d, err := descriptor.Parse("amp.yaml", []byte(resume("AMP_HOME", c.path, c.prefix)))
		if err != nil {
			t.Fatalf("%s: %v", c.prefix, err)
		}
		want := &descriptor.Resume{HomeVar: "AMP_HOME", Path: c.path, Prefix: c.prefix, Args: []string{"resume", "{session_id}"}}
		if !reflect.DeepEqual(d.Resume, want) {
			t.Errorf("Resume = %+v; want %+v", d.Resume, want)
		}
	}
	for name, doc := range map[string]string{
		"a variable without home_var":        resume("", "${AMP_HOME}/s/{session_id}.jsonl", "${AMP_HOME}/s/"),
		"home_var with a prefix in the home": resume("AMP_HOME", "~/.amp/s/{session_id}.jsonl", "~/.amp/s/"),
		"home_var with an absolute prefix":   resume("AMP_HOME", "/var/lib/amp/s/{session_id}.jsonl", "/var/lib/amp/s/"),
		"a second variable in the path":      resume("AMP_HOME", "${AMP_HOME}/s/${OTHER}/{session_id}.jsonl", "${AMP_HOME}/s/"),
		"a $ in the prefix":                  resume("AMP_HOME", "${AMP_HOME}/s$x/{session_id}.jsonl", "${AMP_HOME}/s$x/"),
		"a variable in an absolute prefix":   resume("", "/var/${AMP_HOME}/{session_id}.jsonl", "/var/${AMP_HOME}/"),
		"a variable without braces":          resume("AMP_HOME", "$AMP_HOME/s/{session_id}.jsonl", "$AMP_HOME/s/"),
		"a variable with no / after it":      resume("AMP_HOME", "${AMP_HOME}s/{session_id}.jsonl", "${AMP_HOME}s/"),
	} {
		if _, err := descriptor.Parse("amp.yaml", []byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The schema cannot compare the variable with home_var: Parse does.
	for name, doc := range map[string]string{
		"another variable":             resume("AMP_HOME", "${OTHER}/s/{session_id}.jsonl", "${OTHER}/s/"),
		"another variable in the path": resume("AMP_HOME", "${OTHER}/s/{session_id}.jsonl", "${AMP_HOME}/s/"),
	} {
		_, err := descriptor.Parse("amp.yaml", []byte(doc))
		if err == nil || !strings.HasPrefix(err.Error(), "amp.yaml: resume: start ") || !strings.Contains(err.Error(), "${AMP_HOME}/") {
			t.Errorf("%s: %v; want an error that starts with the fix and contains ${AMP_HOME}/", name, err)
		}
	}
}

// TestConfigDecodes pins that a descriptor's config decodes, with each fixed value a
// string, a bool or an int64 from YAML and from JSON alike, that an endpoint may be a
// setting, and what Parse returns an error for beyond the schema: a fixed key that is a
// setting of the model section, and a fixed key or a model setting that is a dotted
// prefix of another.
func TestConfigDecodes(t *testing.T) {
	b, err := fs.ReadFile(contracts.FS, "fixtures/descriptor/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := descriptor.Parse("config.yaml", b)
	if err != nil {
		t.Fatal(err)
	}
	want := &descriptor.Config{Flag: "--config", Fixed: map[string]any{
		"model_provider": "qory", "model_providers.qory.name": "qory", "model_providers.qory.wire_api": "responses",
		"features.plugins": false, "stream_max_retries": int64(5),
	}, Keys: []string{"model_provider", "model_providers.qory.name", "model_providers.qory.wire_api", "features.plugins", "stream_max_retries"}}
	if !reflect.DeepEqual(d.Config, want) {
		t.Errorf("Config = %#v; want %#v", d.Config, want)
	}
	if d.Model == nil || d.Model.Endpoint != (descriptor.Endpoint{Setting: "model_providers.qory.base_url"}) {
		t.Errorf("Model.Endpoint = %+v; want the setting model_providers.qory.base_url", d.Model)
	}
	j, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON, err := descriptor.Parse("config.json", j)
	if err != nil {
		t.Fatal(err)
	}
	// encoding/json writes a map's keys sorted, so the JSON document has them in that
	// order.
	want.Keys = slices.Sorted(maps.Keys(want.Fixed))
	if !reflect.DeepEqual(fromJSON.Config, want) {
		t.Errorf("Config from JSON = %#v; want %#v", fromJSON.Config, want)
	}
	const head = "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n" +
		"model:\n  formats: [openai-responses]\n  model: {setting: model}\n  endpoint: {setting: providers.qory.base_url}\n"
	for name, fixed := range map[string]string{
		"the model's setting":      "{model: x}",
		"the endpoint's setting":   "{providers.qory.base_url: x}",
		"a table of the endpoint":  "{providers.qory: x}",
		"a key inside the model's": "{model.name: x}",
		"a key inside another":     "{a.b: x, a.b.c: y}",
		"a key that holds another": "{a.b.c: x, a.b: y}",
	} {
		_, err := descriptor.Parse("amp.yaml", []byte(head+"config: {flag: --config, fixed: "+fixed+"}\n"))
		if err == nil || !strings.HasPrefix(err.Error(), "amp.yaml: config.fixed: remove ") {
			t.Errorf("%s: %v; want an error that starts with the fix", name, err)
		}
	}
	if _, err := descriptor.Parse("amp.yaml", []byte(head+"config: {flag: --config, fixed: {providers.qory.name: qory, a.b: 1}}\n")); err != nil {
		t.Errorf("fixed keys beside the model's settings: %v", err)
	}
	// Against a model setting, the fix is the fixed key alone: the model setting stays.
	for fixed, want := range map[string]string{
		"{providers.qory: x}": "amp.yaml: config.fixed: remove providers.qory: a TOML key has a value or a table of keys, not both, and providers.qory.base_url is a setting of the model section",
		"{model.name: x}":     "amp.yaml: config.fixed: remove model.name: a TOML key has a value or a table of keys, not both, and model is a setting of the model section",
	} {
		_, err := descriptor.Parse("amp.yaml", []byte(head+"config: {flag: --config, fixed: "+fixed+"}\n"))
		if err == nil || err.Error() != want {
			t.Errorf("%s: %v; want %s", fixed, err, want)
		}
	}
	// The model section's settings are distinct, and none lies inside another, with or
	// without config.
	const settings = "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n" +
		"model:\n  formats: [openai-responses]\n  model: {setting: %s}\n  endpoint: {setting: %s}\n"
	for _, c := range []struct{ model, endpoint string }{{"a", "a.b"}, {"a.b", "a"}, {"a", "a"}} {
		for _, config := range []string{"", "config: {flag: --config}\n"} {
			doc := fmt.Sprintf(settings, c.model, c.endpoint) + config
			if _, err := descriptor.Parse("amp.yaml", []byte(doc)); err == nil || !strings.HasPrefix(err.Error(), "amp.yaml: model: place the values of ") {
				t.Errorf("model %s, endpoint %s, %q: %v; want an error that starts with the fix", c.model, c.endpoint, config, err)
			}
		}
	}
	if _, err := descriptor.Parse("amp.yaml", []byte(fmt.Sprintf(settings, "a", "ab.c"))); err != nil {
		t.Errorf("model a, endpoint ab.c: %v", err)
	}
}

// fieldsDoc is a descriptor whose start gets source from set, and whose turn lines,
// which contain no session id, take it from the session's start.
const fieldsDoc = `version: 1
runtime: example
runtime_version: "1.0.0"
sources:
  output: {format: jsonl}
rules:
  - source: output
    match: {type: start}
    type: dev.qory.runtime.started
    data: {session_id: id}
    set: {source: startup}
  - source: output
    match: {type: done}
    type: dev.qory.runtime.turn_finished
    from_started: [session_id]
  - source: output
    match: {type: failed}
    type: dev.qory.runtime.turn_failed
    data: {message: error.message}
    set: {error: unknown}
    from_started: [session_id]
`

// TestARuleSetsFieldsAndListsWhatTheStartGives pins set and from_started: a field of
// set has the descriptor's value whatever the record contains, a rule's from_started
// reaches its event for the session to fill, and a rule may have no data.
func TestARuleSetsFieldsAndListsWhatTheStartGives(t *testing.T) {
	d, err := descriptor.Parse("example.yaml", []byte(fieldsDoc))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		record map[string]any
		want   descriptor.Event
	}{
		{map[string]any{"type": "start", "id": "s1", "source": "other"},
			descriptor.Event{Type: "dev.qory.runtime.started", Data: map[string]any{"session_id": "s1", "source": "startup"}}},
		{map[string]any{"type": "done"},
			descriptor.Event{Type: "dev.qory.runtime.turn_finished", Data: map[string]any{}, FromStarted: []string{"session_id"}}},
		{map[string]any{"type": "failed", "error": map[string]any{"message": "boom"}},
			descriptor.Event{Type: "dev.qory.runtime.turn_failed", Data: map[string]any{"message": "boom", "error": "unknown"}, FromStarted: []string{"session_id"}}},
	} {
		got := d.Map(descriptor.Record{Source: "output", Record: c.record})
		if len(got) != 1 || !reflect.DeepEqual(got[0], c.want) {
			t.Errorf("%v: %+v; want %+v", c.record, got, c.want)
		}
	}
	got := d.Map(descriptor.Record{Source: "output", Record: map[string]any{"type": "done"}})
	got[0].FromStarted[0] = "changed"
	if again := d.Map(descriptor.Record{Source: "output", Record: map[string]any{"type": "done"}}); again[0].FromStarted[0] != "session_id" {
		t.Error("a change to an event's FromStarted reached the rule")
	}
}

// TestAFieldComesFromOneMember pins that a field in two of data, set and from_started
// is refused, and that the schema refuses from_started on a hook rule and on a rule of
// dev.qory.runtime.started, a field other than session_id in it, set of a field the
// session sets or to an object, and a rule with none of the three.
func TestAFieldComesFromOneMember(t *testing.T) {
	for name, rule := range map[string]string{
		"data and set":          "    data: {message: error.message}\n    set: {message: x}\n",
		"data and from_started": "    data: {session_id: id}\n    from_started: [session_id]\n",
		"set and from_started":  "    set: {session_id: s}\n    from_started: [session_id]\n",
	} {
		doc := fieldsDoc + "  - source: output\n    match: {type: other}\n    type: dev.qory.runtime.turn_failed\n" + rule
		_, err := descriptor.Parse("example.yaml", []byte(doc))
		if err == nil || !strings.Contains(err.Error(), "set the field") {
			t.Errorf("%s: %v; want a refusal", name, err)
		}
	}
	for _, name := range []string{"from-started-hooks", "from-started-started", "from-started-agent-id", "set-session", "set-object", "rule-no-fields"} {
		bad, err := fs.ReadFile(contracts.FS, "fixtures/invalid/descriptor-"+name+".yaml")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := descriptor.Parse("descriptor.yaml", bad); err == nil {
			t.Errorf("descriptor-%s was accepted", name)
		}
	}
}
