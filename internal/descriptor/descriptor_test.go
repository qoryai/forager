package descriptor_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/internal/descriptor"
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
		{Source: "output", Match: map[string]any{"type": "result", "num_turns": 1, "ok": true, "meta.kind": map[string]any{"present": true}}, Type: "dev.qory.session.result", Data: map[string]string{"n": "num_turns", "k": "meta.kind", "missing": "nope"}},
	}}
	rec := func(js string) descriptor.Record {
		var m map[string]any
		if err := json.Unmarshal([]byte(js), &m); err != nil {
			t.Fatal(err)
		}
		return descriptor.Record{Source: "output", Record: m}
	}
	typ, data, ok := d.Map(rec(`{"type":"result","num_turns":1,"ok":true,"meta":{"kind":"x"}}`))
	if !ok || typ != "dev.qory.session.result" || data["n"] != 1.0 || data["k"] != "x" {
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
// Code descriptor decode: the API key on x-api-key, the OAuth credential as a bearer,
// both on api.anthropic.com under /v1/, one of the two required, and the reserved,
// denied and credential file lists.
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
	if d.Title != "Claude Code" || s == nil || len(s.Declares) != 2 {
		t.Fatalf("title %q, secrets %+v", d.Title, s)
	}
	want := []descriptor.Declaration{
		{ID: "api_key", Title: "Anthropic API key", Name: "ANTHROPIC_API_KEY", Hosts: []string{"api.anthropic.com"}, Paths: []string{"/v1/*"}, Auth: descriptor.Auth{Scheme: "header", Header: "x-api-key"}},
		{ID: "oauth_token", Title: "Claude OAuth credential", Name: "CLAUDE_CODE_OAUTH_TOKEN", Hosts: []string{"api.anthropic.com"}, Paths: []string{"/v1/*"}, Auth: descriptor.Auth{Scheme: "bearer"}},
	}
	for i, w := range want {
		if !reflect.DeepEqual(s.Declares[i], w) {
			t.Errorf("declares[%d] = %+v; want %+v", i, s.Declares[i], w)
		}
	}
	if g := s.OneOf; len(g) != 1 || g[0].ID != "model_key" || !g[0].Required || !reflect.DeepEqual(g[0].Of, []string{"api_key", "oauth_token"}) {
		t.Errorf("one_of = %+v", g)
	}
	if !reflect.DeepEqual(s.Reserves, []string{"ANTHROPIC_AUTH_TOKEN"}) ||
		!reflect.DeepEqual(s.CredentialFiles, []string{"~/.claude/.credentials.json"}) ||
		len(s.Denies) != 18 || s.Denies[0] != "ANTHROPIC_BASE_URL" {
		t.Errorf("reserves %v, credential_files %v, denies %v", s.Reserves, s.CredentialFiles, s.Denies)
	}
}

// TestSecretsAreChecked pins what a descriptor's secrets are held to, by the schema and
// beyond it: exact hosts, a scheme of the closed set with its header, no secret of its
// own in a declaration's auth, and groups of declared ids, each in one group at most.
// A descriptor without secrets stays valid, and runtimes.json writes a basic
// declaration's username beside its scheme.
func TestSecretsAreChecked(t *testing.T) {
	const head = "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.session.ended, data: {reason: why}}]\n"
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
		"an auth secret":             " declares:\n  - {id: key, title: Key, name: AMP_KEY, hosts: [api.example.com], auth: {scheme: bearer, secret: key}}\n",
		"a username secret":          " declares:\n  - {id: key, title: Key, name: AMP_KEY, hosts: [api.example.com], auth: {scheme: basic, username_secret: key}}\n",
		"no hosts":                   " declares:\n  - {id: key, title: Key, name: AMP_KEY, auth: {scheme: bearer}}\n",
		"a relative credential file": " credential_files: [.amp/key]\n",
		"an id declared twice":       " declares:\n" + key + key,
		"an undeclared id":           " declares:\n" + key + " one_of: [{id: model, of: [key, other]}]\n",
		"an id in two groups":        " declares:\n" + key + " one_of: [{id: a, of: [key]}, {id: b, of: [key]}]\n",
		"a group defined twice": " declares:\n" + key + "  - {id: alt, title: Alt, name: AMP_ALT, hosts: [api.example.com], auth: {scheme: bearer}}\n" +
			" one_of: [{id: a, of: [key]}, {id: a, of: [alt]}]\n",
	} {
		if _, err := descriptor.Parse("amp.yaml", []byte(head+"secrets:\n"+secrets)); err == nil {
			t.Errorf("%s was accepted", name)
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
		t.Errorf("contracts/runner/v1/%s differs from the descriptors; run go generate ./contracts\n%s",
			descriptor.RuntimesFile, got)
	}
}

// TestRuntimesJSONShape pins the members of runtimes.json a server reads: version and
// runtimes; per runtime its name, title, reserves, denies, credential_files, declares
// and one_of, every one present; per declaration id, title, name, hosts, auth with its
// scheme, the header of a header scheme and the username of a basic scheme, and paths
// when it has some; per group id, required and of. Every built-in descriptor is one
// runtime, in name order.
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
		rt := members("runtime", r, []string{"name", "title", "reserves", "denies", "credential_files", "declares", "one_of"})
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
	}
}
