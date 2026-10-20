package descriptor_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"reflect"
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
	typ, data, ok := d.Map(rec(`{"type":"result","num_turns":1,"ok":true,"meta":{"kind":"x"}}`))
	if !ok || typ != "dev.qory.runtime.result" || data["n"] != 1.0 || data["k"] != "x" {
		t.Errorf("Map = %s %v %v", typ, data, ok)
	}
	if _, hasMissing := data["missing"]; hasMissing {
		t.Error("a missing path produced a field")
	}
	for _, js := range []string{
		`{"type":"result","num_turns":2,"ok":true,"meta":{"kind":"x"}}`,
		`{"type":"result","num_turns":1,"ok":false,"meta":{"kind":"x"}}`,
		`{"type":"result","num_turns":1,"ok":true,"meta":{}}`,
		`{"type":"result","num_turns":"1","ok":true,"meta":{"kind":"x"}}`,
	} {
		if _, _, ok := d.Map(rec(js)); ok {
			t.Errorf("%s matched", js)
		}
	}
	if _, _, ok := d.Map(descriptor.Record{Source: "hooks", Record: map[string]any{"type": "result"}}); ok {
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
			"CLAUDE_CODE_SUBAGENT_MODEL_FORCE", "CLAUDE_CODE_AUTO_MODE_MODEL", "CLAUDE_CODE_EFFORT_LEVEL", "CLAUDE_CODE_EXTRA_BODY",
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

// TestRuntimesJSONShape pins the members of runtimes.json a server reads: version and
// runtimes; per runtime its name, title, reserves, denies, credential_files, declares
// and one_of, every one present; per declaration id, title, name, hosts, auth with its
// scheme, the header of a header scheme and the username of a basic scheme, and paths
// when it has some; per group id, required and of; and model when the descriptor has
// one, with formats, model, endpoint with its variable and optionally effort, with run
// and optionally agent, each place being exactly one of flag, setting and variable, and
// optionally overrides. The claude runtime has a model with overrides. Every built-in descriptor is one runtime, in name order.
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
		rt := members("runtime", r, []string{"name", "title", "reserves", "denies", "credential_files", "declares", "one_of"}, "model")
		if rt["name"] != dirs[i].Name() || rt["title"] == "" {
			t.Errorf("runtime %d is %v, %v; want %s and a title", i, rt["name"], rt["title"], dirs[i].Name())
		}
		for _, k := range []string{"reserves", "denies", "credential_files"} {
			strs(k, rt[k])
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
			members("endpoint", model["endpoint"], []string{"variable"})
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
