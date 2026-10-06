package server_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/qoryai/runner/internal/refusal"
)

// value is what every refused document below holds as a variable's value, so a test
// sees whether an error quotes it.
const value = "a-value-no-error-quotes"

// TestRunConfigurationReadsTheVariables pins that a run configuration's variables are
// decoded by name, beside its policy or without one.
func TestRunConfigurationReadsTheVariables(t *testing.T) {
	v := newVerified(t)
	c := v.client()
	run := v.srv.URL + "/v1/run-configuration"
	v.runDoc = `{"version":1,"variables":{"NODE_ENV":"test","APP_REGION":"eu-west-1","EMPTY":""},"later":{"x":1}}`
	rc, _, err := c.RunConfiguration(context.Background(), run, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rc.SecurityPolicy != nil || len(rc.Variables) != 3 || rc.Variables["NODE_ENV"] != "test" || rc.Variables["APP_REGION"] != "eu-west-1" || rc.Variables["EMPTY"] != "" {
		t.Errorf("read %+v", rc)
	}
	v.runDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"observe"}},"variables":{"A":"` + strings.Repeat("é", 2048) + `"}}`
	if rc, _, err = c.RunConfiguration(context.Background(), run, nil); err != nil || rc.SecurityPolicy == nil || len(rc.Variables["A"]) != 4096 {
		t.Errorf("a value of 4096 bytes: %v", err)
	}
}

// TestRunConfigurationRefusalsQuoteNoValue pins what the runner refuses of a run
// configuration, each with run_configuration_invalid, and that no error contains a
// variable's value: a member name twice, invalid UTF-8, a value with a NUL, a carriage
// return or a line feed, a value that is no string, a name outside the grammar, more
// than 128 variables, and a value of more than 4096 bytes, which the schema's count of
// characters lets through.
func TestRunConfigurationRefusalsQuoteNoValue(t *testing.T) {
	many := make([]string, 129)
	for i := range many {
		many[i] = fmt.Sprintf(`"V%d":"%s"`, i, value)
	}
	nul := string([]byte{92, 'u', '0', '0', '0', '0'})
	for _, tc := range []struct{ name, doc, where string }{
		{"a name twice", `{"version":1,"variables":{"A":"` + value + `","A":"` + value + `x"}}`, "/variables/A"},
		{"invalid UTF-8", "{\"version\":1,\"variables\":{\"A\":\"" + value + "\xff\"}}", ""},
		{"a line feed", `{"version":1,"variables":{"A":"` + value + `\n"}}`, "/variables/A (pattern)"},
		{"a carriage return", `{"version":1,"variables":{"A":"` + value + `\r"}}`, "/variables/A (pattern)"},
		{"a NUL", `{"version":1,"variables":{"A":"` + value + nul + `"}}`, "/variables/A (pattern)"},
		{"a number", `{"version":1,"variables":{"A":4096,"B":"` + value + `"}}`, "/variables/A (type)"},
		{"a name outside the grammar", `{"version":1,"variables":{"1A":"` + value + `"}}`, "the member name 1A (propertyNames)"},
		{"129 variables", `{"version":1,"variables":{` + strings.Join(many, ",") + `}}`, "/variables (maxProperties)"},
		{"4097 bytes", `{"version":1,"variables":{"A":"` + value + strings.Repeat("é", 2048) + `"}}`, "the variable A holds more than 4096 bytes"},
		{"a policy the schema refuses", `{"version":1,"security_policy":{"version":1,"egress":{"mode":"log"}},"variables":{"A":"` + value + `"}}`, "/security_policy/egress/mode (enum)"},
		{"no version", `{"variables":{"A":"` + value + `"}}`, "(required)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newVerified(t)
			v.runDoc = tc.doc
			_, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/run-configuration", nil)
			var r *refusal.Error
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
