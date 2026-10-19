package server_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
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
// credentials are read against the schema: a document with two entries is read, and an
// entry with a value member, a *. host, a host with a port or no auth is
// run_configuration_invalid at the entry, with an error that quotes no value.
func TestARunConfigurationsCredentialsAreChecked(t *testing.T) {
	entry := func(extra string) string {
		return `{"version":1,"credentials":[{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"bearer"}` + extra + `}]}`
	}
	v := newVerified(t)
	v.runDoc = `{"version":1,"credentials":[{"name":"model","hosts":["api.model.example","10.0.0.5","fd00::5"],"paths":["/v1/*"],"auth":{"scheme":"header","header":"x-api-key"},"placeholders":["MODEL_API_KEY"]},{"name":"forge","hosts":["git.example"],"auth":{"scheme":"basic","username":"x-access-token"}}]}`
	if _, _, err := v.client().Register(context.Background(), v.srv.URL+"/v1/runs", registration(t)); err != nil {
		t.Fatalf("a run configuration with credentials: %v", err)
	}
	for name, doc := range map[string]string{
		"a value":          entry(`,"value":"` + value + `"`),
		"a *. host":        strings.Replace(entry(""), `"api.model.example"`, `"*.model.example"`, 1),
		"a host and port":  strings.Replace(entry(""), `"api.model.example"`, `"api.model.example:443"`, 1),
		"no auth":          strings.Replace(entry(""), `,"auth":{"scheme":"bearer"}`, ``, 1),
		"nine credentials": `{"version":1,"credentials":[` + strings.Repeat(`{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"bearer"}},`, 8) + `{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"bearer"}}]}`,
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
}
