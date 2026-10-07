package server_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/internal/refusal"
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
	run := v.srv.URL + "/v1/run-configuration"
	v.runDoc = `{"version":1,"variables":{"NODE_ENV":{"value":"test"},"APP_REGION":{"value":"eu-west-1","later":true},"EMPTY":{"value":""}},"later":{"x":1}}`
	rc, _, err := c.RunConfiguration(context.Background(), run, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rc.SecurityPolicy != nil || len(rc.Variables) != 3 || rc.Values()["NODE_ENV"] != "test" || rc.Values()["APP_REGION"] != "eu-west-1" || rc.Values()["EMPTY"] != "" {
		t.Errorf("read %+v", rc)
	}
	v.runDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"observe"}},"variables":{"A":{"value":"` + strings.Repeat("é", 2048) + `"}}}`
	if rc, _, err = c.RunConfiguration(context.Background(), run, nil); err != nil || rc.SecurityPolicy == nil || len(rc.Variables["A"].Value) != 4096 {
		t.Errorf("a value of 4096 bytes: %v", err)
	}
}

// TestRunConfigurationRefusalsQuoteNoValue pins what the runner refuses of a run
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
			_, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/run-configuration", nil)
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
			rc, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/run-configuration", nil)
			if rc != nil || code(err) != accesskey.CodeAnswerUnsigned {
				t.Errorf("%s, %s: read %+v, %v; want answer_unsigned", sign, doc, rc, err)
			}
			if err != nil && strings.Contains(err.Error(), value) {
				t.Errorf("%s: the error quotes the value: %v", sign, err)
			}
		}
	}
	v := newVerified(t)
	v.runDoc = `{"version":1,"variables":{"NODE_ENV":{"value":"` + value + `"}}}`
	if rc, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/run-configuration", nil); err != nil || rc.Values()["NODE_ENV"] != value {
		t.Errorf("a signed answer: %+v, %v", rc, err)
	}
}
