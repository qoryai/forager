package server_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// value is what every refused document below holds as a variable's value, so a test
// sees whether an error quotes it.
const value = "a-value-no-error-quotes"

// TestRunConfigurationReadsTheVariables pins that a run configuration's variables are
// decoded by name, each its value, beside its policy or without one, and that a member
// beside the value is ignored.
func TestRunConfigurationReadsTheVariables(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	runs := v.srv.URL + "/v1/runs"
	v.runDoc = `{"version":1,"variables":{"NODE_ENV":{"value":"test"},"APP_REGION":{"value":"eu-west-1","later":true},"EMPTY":{"value":""}},"later":{"x":1}}`
	rc, _, err := c.RunConfiguration(context.Background(), runs, runID)
	if err != nil {
		t.Fatal(err)
	}
	if rc.SecurityPolicy != nil || len(rc.Variables) != 3 || rc.Values()["NODE_ENV"] != "test" || rc.Values()["APP_REGION"] != "eu-west-1" || rc.Values()["EMPTY"] != "" {
		t.Errorf("read %+v", rc)
	}
	v.runDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"observe"}},"variables":{"A":{"value":"` + strings.Repeat("é", 2048) + `"}}}`
	if rc, _, err = c.RunConfiguration(context.Background(), runs, runID); err != nil || rc.SecurityPolicy == nil || len(rc.Variables["A"].Value) != 4096 {
		t.Errorf("a value of 4096 bytes: %v", err)
	}
}

// TestRunConfigurationRefusalsQuoteNoValue pins what Forager refuses of a run
// configuration, each with run_configuration_invalid, and that no error contains a
// variable's value: a member name twice, invalid UTF-8, a value with a NUL, a carriage
// return or a line feed, a value that is no string, a name outside the grammar, more
// than 128 variables, and a value of more than 4096 bytes, which the schema's count of
// characters lets through. A variable is an object with its value: one without a value,
// or a bare string, is refused as well.
func TestRunConfigurationRefusalsQuoteNoValue(t *testing.T) {
	many := make([]string, 129)
	for i := range many {
		many[i] = fmt.Sprintf(`"V%d":{"value":"%s"}`, i, value)
	}
	nul := string([]byte{92, 'u', '0', '0', '0', '0'})
	for _, tc := range []struct{ name, doc, where string }{
		{"a name twice", `{"version":1,"variables":{"A":{"value":"` + value + `"},"A":{"value":"` + value + `x"}}}`, "/variables/A"},
		{"invalid UTF-8", "{\"version\":1,\"variables\":{\"A\":{\"value\":\"" + value + "\xff\"}}}", ""},
		{"a line feed", `{"version":1,"variables":{"A":{"value":"` + value + `\n"}}}`, "/variables/A/value (pattern)"},
		{"a carriage return", `{"version":1,"variables":{"A":{"value":"` + value + `\r"}}}`, "/variables/A/value (pattern)"},
		{"a NUL", `{"version":1,"variables":{"A":{"value":"` + value + nul + `"}}}`, "/variables/A/value (pattern)"},
		{"a number", `{"version":1,"variables":{"A":{"value":4096},"B":{"value":"` + value + `"}}}`, "/variables/A/value (type)"},
		{"no value", `{"version":1,"variables":{"A":{"later":"` + value + `"}}}`, "/variables/A (required)"},
		{"a string in place of the object", `{"version":1,"variables":{"A":"` + value + `"}}`, "/variables/A (type)"},
		{"a name outside the grammar", `{"version":1,"variables":{"1A":{"value":"` + value + `"}}}`, "the member name 1A (propertyNames)"},
		{"129 variables", `{"version":1,"variables":{` + strings.Join(many, ",") + `}}`, "/variables (maxProperties)"},
		{"4097 bytes", `{"version":1,"variables":{"A":{"value":"` + value + strings.Repeat("é", 2048) + `"}}}`, "the variable A holds more than 4096 bytes"},
		{"a policy the schema refuses", `{"version":1,"security_policy":{"version":1,"egress":{"mode":"log"}},"variables":{"A":{"value":"` + value + `"}}}`, "/security_policy/egress/mode (enum)"},
		{"no version", `{"variables":{"A":{"value":"` + value + `"}}}`, "(required)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newVerified(t)
			v.runDoc = tc.doc
			_, _, err := v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t))
			var r *accesskey.Refusal
			if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid {
				t.Fatalf("refused with %v", err)
			}
			if strings.Contains(err.Error(), value) || strings.Contains(err.Error(), "é") {
				t.Errorf("the error quotes the value: %v", err)
			}
			if !strings.Contains(err.Error(), tc.where) {
				t.Errorf("the error %q does not contain %q", err, tc.where)
			}
		})
	}
}

// TestARunConfigurationIsReadOnlyOnceItsAnswerVerifies pins that the run
// configuration's body is read only after its answer's signature verifies under the
// pin: an answer unsigned, signed under another key or bound to another request is
// answer_unsigned and yields no variables, whether its body is a valid document or one
// the reader would refuse, and the error contains no value of it.
func TestARunConfigurationIsReadOnlyOnceItsAnswerVerifies(t *testing.T) {
	for _, doc := range []string{
		`{"version":1,"variables":{"NODE_ENV":{"value":"` + value + `"}}}`,
		`{"version":1,"variables":{"NODE_ENV":{"value":"` + value + `\n"}}}`,
	} {
		for _, sign := range []string{"none", "other", "elsewhere"} {
			v := newVerified(t)
			v.runDoc, v.sign = doc, sign
			for what, read := range map[string]func() (*server.RunConfiguration, string, error){
				"registration": func() (*server.RunConfiguration, string, error) {
					return v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t))
				},
				"reload": func() (*server.RunConfiguration, string, error) {
					return v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
				},
			} {
				rc, _, err := read()
				if rc != nil || code(err) != accesskey.CodeAnswerUnsigned {
					t.Errorf("%s, %s, %s: read %+v, %v; want answer_unsigned", what, sign, doc, rc, err)
				}
				if err != nil && strings.Contains(err.Error(), value) {
					t.Errorf("%s, %s: the error quotes the value: %v", what, sign, err)
				}
			}
		}
	}
	v := newVerified(t)
	v.runDoc = `{"version":1,"variables":{"NODE_ENV":{"value":"` + value + `"}}}`
	if rc, _, err := v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t)); err != nil || rc.Values()["NODE_ENV"] != value {
		t.Errorf("a signed answer: %+v, %v", rc, err)
	}
}

// TestARunConfigurationNamesItsImageByDigest pins a run configuration's image: a
// reference pinned by digest is read; a tag, upper case, no digest, a NAME of more than
// 255 characters and the machine's name for an image are run_configuration_invalid
// before the schema reads them, the image named in the refusal, quoted when it holds
// what is not printable; a value that is no string is the schema's.
func TestARunConfigurationNamesItsImageByDigest(t *testing.T) {
	const pinned = "registry.example/agents/app@sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	v := newVerified(t)
	runs := v.srv.URL + "/v1/runs"
	v.runDoc = `{"version":1,"image":"` + pinned + `"}`
	if rc, _, err := v.client().RunConfiguration(context.Background(), runs, runID); err != nil || rc.Image != pinned || rc.SecurityPolicy != nil {
		t.Errorf("read %+v, %v", rc, err)
	}
	long := strings.Repeat("a", 256) + "@sha256:" + strings.Repeat("b", 64)
	for _, tc := range []struct{ image, shown string }{
		{"registry.example/agents/app:1", "registry.example/agents/app:1"},
		{"registry.example/agents/app:1@sha256:" + strings.Repeat("b", 64), "registry.example/agents/app:1@sha256:" + strings.Repeat("b", 64)},
		{"Registry.example/agents/app@sha256:" + strings.Repeat("b", 64), "Registry.example/agents/app@sha256:" + strings.Repeat("b", 64)},
		{"registry.example/agents/app", "registry.example/agents/app"},
		{"base", "base"},
		{long, long},
		{"", `""`},
		{`base\nline`, `"base\nline"`},
	} {
		v.runDoc = `{"version":1,"image":"` + tc.image + `"}`
		_, _, err := v.client().RunConfiguration(context.Background(), runs, runID)
		want := "run configuration " + runs + "/" + runID + ": the image " + tc.shown + " is not a reference pinned by digest"
		if code(err) != refusal.RunConfigurationInvalid || err == nil || !strings.HasPrefix(err.Error(), want+":") {
			t.Errorf("%s: %v, want run_configuration_invalid and %q", tc.image, err, want)
		}
	}
	v.runDoc = `{"version":1,"image":1}`
	if _, _, err := v.client().RunConfiguration(context.Background(), runs, runID); code(err) != refusal.RunConfigurationInvalid || err == nil || !strings.Contains(err.Error(), "/image (type)") {
		t.Errorf("a number: %v", err)
	}
}

// TestARunConfigurationsCredentialsAreChecked pins that a run configuration's
// credentials are read against the schema: a document with an API credential and a
// host credential is read, and an entry with a value member, a *. host, a host with a
// port, an apply item with no scheme or with a token, hosts and auth in place of apply,
// an API credential with hosts or placeholders, an http endpoint, an
// endpoint with a user or a query, or key prefixes with a space is
// run_configuration_invalid at the entry, with an error that quotes no value. It pins
// the count too: 16 credentials, 6 of them API credentials, are read, and 17
// credentials, or 7 API credentials, are run_configuration_invalid at the list.
func TestARunConfigurationsCredentialsAreChecked(t *testing.T) {
	entry := func(extra string) string {
		return `{"version":1,"credentials":[{"name":"forge","apply":[{"hosts":["api.model.example"],"scheme":"bearer"}]` + extra + `}]}`
	}
	api := func(extra string) string {
		return `{"version":1,"credentials":[{"name":"model","group":"anthropic","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"bearer"}` + extra + `}]}`
	}
	// counted has api API credentials, the first the start key, and then hosts host
	// credentials, each on the host <name>.git.example.
	counted := func(api, hosts int) string {
		var items []string
		for i := range api + hosts {
			name := fmt.Sprintf("cred-%02d", i)
			if i < api {
				items = append(items, `{"name":"`+name+`","group":"anthropic","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"}}`)
				continue
			}
			items = append(items, `{"name":"`+name+`","apply":[{"hosts":["`+name+`.git.example"],"scheme":"bearer"}]}`)
		}
		start := ""
		if api > 0 {
			start = `"default_model_provider_credential_name":"cred-00",`
		}
		return `{"version":1,` + start + `"credentials":[` + strings.Join(items, ",") + `]}`
	}
	for name, doc := range map[string]string{
		"16 host credentials":           counted(0, 16),
		"6 API and 10 host credentials": counted(6, 10),
	} {
		v := newVerified(t)
		v.runDoc = doc
		if _, _, err := v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	v := newVerified(t)
	v.runDoc = `{"version":1,"credentials":[{"name":"model","group":"anthropic","format":"anthropic-messages","endpoint":"https://10.0.0.5:4443/anthropic","auth":{"scheme":"header","header":"x-api-key"},"key_prefixes":["sk-ant-"]},{"name":"forge","apply":[{"hosts":["git.example","fd00::5"],"scheme":"basic","username":"x-access-token","paths":["/v1/*"]}],"placeholders":["FORGE_TOKEN"]}]}`
	if _, _, err := v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t)); err != nil {
		t.Fatalf("a run configuration with credentials: %v", err)
	}
	for name, doc := range map[string]string{
		"a value":                   entry(`,"value":"` + value + `"`),
		"a *. host":                 strings.Replace(entry(""), `"api.model.example"`, `"*.model.example"`, 1),
		"a host and port":           strings.Replace(entry(""), `"api.model.example"`, `"api.model.example:443"`, 1),
		"no scheme":                 strings.Replace(entry(""), `,"scheme":"bearer"`, ``, 1),
		"hosts and auth":            `{"version":1,"credentials":[{"name":"forge","hosts":["api.model.example"],"auth":{"scheme":"bearer"}}]}`,
		"a token in apply":          strings.Replace(entry(""), `"scheme":"bearer"`, `"scheme":"bearer","token":"`+value+`"`, 1),
		"an API with hosts":         api(`,"hosts":["api.model.example"]`),
		"an API with placeholders":  api(`,"placeholders":["MODEL_API_KEY"]`),
		"an http endpoint":          strings.Replace(api(""), `https://`, `http://`, 1),
		"an endpoint with a user":   strings.Replace(api(""), `https://`, `https://`+value+`@`, 1),
		"an endpoint with a query":  strings.Replace(api(""), `/anthropic`, `/anthropic?key=`+value, 1),
		"a key prefix with a space": api(`,"key_prefixes":["sk ant"]`),
	} {
		v := newVerified(t)
		v.runDoc = doc
		_, _, err := v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t))
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.Contains(err.Error(), "/credentials") {
			t.Errorf("%s: %v; want run_configuration_invalid at /credentials", name, err)
		}
		if err != nil && strings.Contains(err.Error(), value) {
			t.Errorf("%s: the error quotes the value: %v", name, err)
		}
	}
	// The count limits fail on the list itself: 17 credentials on maxItems, 7 model keys
	// on maxContains.
	for name, c := range map[string]struct {
		doc, want string
	}{
		"17 host credentials": {counted(0, 17), "/credentials (maxItems)"},
		"6 API and 11 host":   {counted(6, 11), "/credentials (maxItems)"},
		"7 API and 9 host":    {counted(7, 9), "/credentials (maxContains)"},
	} {
		v := newVerified(t)
		v.runDoc = c.doc
		_, _, err := v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t))
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want run_configuration_invalid with %s", name, err, c.want)
		}
	}
}

// TestKeyGroupsAreChecked pins the key groups of a run configuration's API credentials:
// the fixture of two groups is read; an API credential without group, and a host
// credential with one, fail the schema; and CheckCredentials refuses, with the fix on
// the first line and the cause on the second, two keys of one group that differ in a
// member KeyGroupDiffers compares, as the fixture
// run-configuration-beyond-schema-model-keys-group-mixed.json has. Two groups, and two
// keys of two groups that differ, are read. A key with chosen fails the schema, as any
// member the schema does not define.
func TestKeyGroupsAreChecked(t *testing.T) {
	read := func(path string) string {
		b, err := fs.ReadFile(contracts.FS, path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	register := func(doc string) error {
		v := newVerified(t)
		v.runDoc = doc
		_, _, err := v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t))
		return err
	}
	if err := register(read("fixtures/run-configuration/model-keys-groups.json")); err != nil {
		t.Errorf("model-keys-groups.json: %v", err)
	}
	for _, f := range []string{"run-configuration-credentials-api-no-group.json", "run-configuration-credentials-host-group.json"} {
		var r *accesskey.Refusal
		if err := register(read("fixtures/invalid/" + f)); !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.Contains(err.Error(), "/credentials") {
			t.Errorf("%s: %v; want run_configuration_invalid at /credentials", f, err)
		}
	}
	withChosen := strings.Replace(read("fixtures/run-configuration/model-keys-groups.json"), `"pause_for_s": 18000}`, `"pause_for_s": 18000, "chosen": true}`, 1)
	if r, err := (*accesskey.Refusal)(nil), register(withChosen); !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.Contains(err.Error(), "/credentials") {
		t.Errorf("a key with chosen: %v; want run_configuration_invalid at /credentials", err)
	}
	for f, want := range map[string]string{
		"run-configuration-beyond-schema-model-keys-group-mixed.json": "Give the keys of group \"anthropic\" one format, endpoint and auth.\nThe credentials \"model\" and \"model-2\" differ in endpoint",
	} {
		var r *accesskey.Refusal
		if err := register(read("fixtures/invalid/" + f)); !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v; want run_configuration_invalid with %q", f, err, want)
		}
		if first, _, _ := strings.Cut(want, "\n"); len(first) > 100 {
			t.Errorf("%s: the first line has %d characters", f, len(first))
		}
	}
	key := func(name, group, extra string) server.RunCredential {
		c := server.RunCredential{Name: name, Group: group, Format: "anthropic-messages", Endpoint: "https://api.model.example/anthropic", Auth: server.Auth{Scheme: "header", Header: "x-api-key"}}
		switch extra {
		case "header case":
			c.Auth.Header = "X-Api-Key"
		case "scheme":
			c.Auth = server.Auth{Scheme: "bearer"}
		case "format":
			c.Format = "openai-responses"
		case "oauth":
			c.Auth = server.Auth{Scheme: "header", Header: "x-api-key", OAuth: true}
		}
		return c
	}
	for extra, want := range map[string]string{"header case": "", "scheme": "auth.scheme", "format": "format", "oauth": "auth.oauth"} {
		if got := server.KeyGroupDiffers(key("a", "g", ""), key("b", "g", extra)); got != want {
			t.Errorf("KeyGroupDiffers with another %s: %q; want %q", extra, got, want)
		}
	}
	if err := server.CheckCredentials([]server.RunCredential{key("a", "one", ""), key("b", "two", "scheme")}, "a"); err != nil {
		t.Errorf("two groups that differ: %v", err)
	}
	// One pair of keys of one group per member KeyGroupDiffers compares, each pair valid
	// but for that member; a header's name in another case is the same header.
	auth := func(scheme, header string) server.Auth { return server.Auth{Scheme: scheme, Header: header} }
	account := func(header, claim string) server.Auth {
		return server.Auth{Scheme: "bearer", OAuth: true, AccountHeader: header, AccountClaim: claim}
	}
	basic := func(username string) server.Auth { return server.Auth{Scheme: "basic", Username: username} }
	for _, p := range []struct {
		member string
		a, b   server.RunCredential
	}{
		{"format", server.RunCredential{Format: "anthropic-messages"}, server.RunCredential{Format: "openai-responses"}},
		{"endpoint", server.RunCredential{Endpoint: "https://api.model.example/anthropic"}, server.RunCredential{Endpoint: "https://api.model.example/v2"}},
		{"auth.scheme", server.RunCredential{Auth: auth("header", "x-api-key")}, server.RunCredential{Auth: auth("bearer", "")}},
		{"auth.username", server.RunCredential{Auth: basic("one")}, server.RunCredential{Auth: basic("two")}},
		{"auth.header", server.RunCredential{Auth: auth("header", "x-api-key")}, server.RunCredential{Auth: auth("header", "x-model-key")}},
		{"", server.RunCredential{Auth: auth("header", "x-api-key")}, server.RunCredential{Auth: auth("header", "X-Api-Key")}},
		{"auth.oauth", server.RunCredential{Auth: server.Auth{Scheme: "bearer"}}, server.RunCredential{Auth: server.Auth{Scheme: "bearer", OAuth: true}}},
		{"auth.account_header", server.RunCredential{Auth: account("x-account-one", "account_id")}, server.RunCredential{Auth: account("x-account-two", "account_id")}},
		{"", server.RunCredential{Auth: account("x-account-id", "account_id")}, server.RunCredential{Auth: account("X-Account-Id", "account_id")}},
		{"auth.account_claim", server.RunCredential{Auth: account("x-account-id", "account_id")}, server.RunCredential{Auth: account("x-account-id", "org_id")}},
	} {
		fill := func(c server.RunCredential, name string) server.RunCredential {
			c.Name, c.Group = name, "g"
			if c.Format == "" {
				c.Format = "anthropic-messages"
			}
			if c.Endpoint == "" {
				c.Endpoint = "https://api.model.example/anthropic"
			}
			if c.Auth.Scheme == "" {
				c.Auth = auth("header", "x-api-key")
			}
			return c
		}
		a, b := fill(p.a, "a"), fill(p.b, "b")
		err := server.CheckCredentials([]server.RunCredential{a, b}, "a")
		if p.member == "" {
			if err != nil {
				t.Errorf("two keys whose auth %+v and %+v differ in a header's case alone: %v; want them read", a.Auth, b.Auth, err)
			}
			continue
		}
		want := "Give the keys of group \"g\" one format, endpoint and auth.\nThe credentials \"a\" and \"b\" differ in " + p.member
		if err == nil || !strings.HasPrefix(err.Error(), want+": ") {
			t.Errorf("two keys that differ in %s: %v; want %q", p.member, err, want)
		}
	}
	host := server.RunCredential{Name: "forge", Group: "g", Apply: []server.Apply{{Hosts: []string{"git.example"}, Scheme: "bearer"}}}
	if err := server.CheckCredentials([]server.RunCredential{host}, ""); err == nil ||
		!strings.HasPrefix(err.Error(), "Remove group from the credential \"forge\".\nOnly an API credential, one with format, has a group: ") {
		t.Errorf("a host credential with group: %v", err)
	}
	if err := server.CheckCredentials([]server.RunCredential{{Name: "a", Format: "anthropic-messages", Endpoint: "https://api.model.example/anthropic", Auth: server.Auth{Scheme: "bearer"}}}, "a"); err == nil ||
		!strings.HasPrefix(err.Error(), "Give the API credential \"a\" a group, the id of its provider.\n") {
		t.Errorf("an API credential without group: %v", err)
	}
}

// TestARunHasSixAPICredentialsAtMost pins CheckCredentials on a document not read
// from bytes: 6 API credentials across two key groups are read, and a seventh is
// run_configuration_invalid with the count, as the schema refuses it for a document
// read from bytes. Host credentials do not count.
func TestARunHasSixAPICredentialsAtMost(t *testing.T) {
	var creds []server.RunCredential
	for i := range 7 {
		creds = append(creds, server.RunCredential{Name: fmt.Sprintf("key-%d", i+1), Group: []string{"one", "two"}[i%2], Format: "anthropic-messages",
			Endpoint: "https://api.model.example/anthropic", Auth: server.Auth{Scheme: "header", Header: "x-api-key"}})
	}
	host := server.RunCredential{Name: "forge", Apply: []server.Apply{{Hosts: []string{"git.example"}, Scheme: "bearer"}}}
	if err := server.CheckCredentials(append(slices.Clone(creds[:6]), host), "key-1"); err != nil {
		t.Errorf("6 API credentials and a host credential: %v", err)
	}
	err := server.CheckCredentials(creds, "key-1")
	var r *accesskey.Refusal
	const want = "Remove API credentials until the run has 6 at most.\nThe document lists 7"
	if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.HasPrefix(err.Error(), want+": ") {
		t.Errorf("7 API credentials: %v; want run_configuration_invalid %q", err, want)
	}
}

// TestARunConfigurationsResumeRunsAreChecked pins resume.runs: a document with a resume
// is read with runs, whose last item is run_id, and without them, as is the fixture
// resume-runs.json; one whose runs end in another run, as the fixture
// run-configuration-beyond-schema-resume-runs-last.json does, list a run twice, list
// 257 runs or list a run id in upper case is run_configuration_invalid at runs.
func TestARunConfigurationsResumeRunsAreChecked(t *testing.T) {
	const (
		paused  = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
		earlier = "0192f0a7-1c2d-7e3f-8a4b-5c6d7e8f9a0b"
	)
	fixture := func(name string) string {
		b, err := fs.ReadFile(contracts.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	doc := func(runs ...string) string {
		d := `{"version":1,"resume":{"run_id":"` + paused + `","session_id":"s-1","path":"~/.claude/projects/-workspace/s-1.jsonl"`
		if runs != nil {
			d += `,"runs":["` + strings.Join(runs, `","`) + `"]`
		}
		return d + `}}`
	}
	for name, c := range map[string]struct {
		doc  string
		want []string
	}{
		"with runs":    {doc(earlier, paused), []string{earlier, paused}},
		"without runs": {doc(), nil},
		"the fixture": {fixture("fixtures/run-configuration/resume-runs.json"),
			[]string{earlier, "0192f0b3-4d5e-7f6a-8b7c-9d0e1f2a3b4c", paused}},
	} {
		v := newVerified(t)
		v.runDoc = c.doc
		rc, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
		if err != nil || rc.Resume == nil || rc.Resume.RunID != paused || !slices.Equal(rc.Resume.Runs, c.want) {
			t.Errorf("%s: read %+v, %v; want runs %q", name, rc, err, c.want)
		}
	}
	many := make([]string, 256)
	for i := range many {
		many[i] = fmt.Sprintf("0192f0c1-7d4e-7a2b-8c3d-%012x", i)
	}
	for name, c := range map[string]struct{ doc, where string }{
		"another run last": {doc(paused, earlier), "set the last item of /resume/runs to /resume/run_id"},
		"a run twice":      {doc(earlier, earlier, paused), "/resume/runs (uniqueItems)"},
		"257 runs":         {doc(append(many, paused)...), "/resume/runs (maxItems)"},
		"a run upper case": {doc(strings.ToUpper(earlier), paused), "/resume/runs/0 (pattern)"},
		"the fixture":      {fixture("fixtures/invalid/run-configuration-beyond-schema-resume-runs-last.json"), "set the last item of /resume/runs to /resume/run_id"},
	} {
		v := newVerified(t)
		v.runDoc = c.doc
		_, _, err := v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t))
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.Contains(err.Error(), c.where) {
			t.Errorf("%s: %v; want run_configuration_invalid with %q", name, err, c.where)
		}
	}
}
