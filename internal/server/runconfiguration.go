package server

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/internal/refusal"
)

// MaxVariableValue is the most bytes of UTF-8 a run configuration's variable value
// holds. The schema's maxLength counts characters, so it is not the check.
const MaxVariableValue = 4096

// readRunConfiguration reads a run configuration document: through encoding/json/v2
// first, which refuses a member name that appears twice and invalid UTF-8, then against
// the schema, then against the limits the schema cannot state. Every refusal is a
// refusal with [refusal.RunConfigurationInvalid] whose message contains where
// in the document it is and which rule refused it, and never a value: a variable's
// value may be anything the server holds, and no decoder's own message is wrapped,
// since those quote what they refuse.
func readRunConfiguration(body []byte) (*RunConfiguration, error) {
	invalid := func(format string, a ...any) error {
		return refusal.New(refusal.RunConfigurationInvalid, nil, "the document is refused: "+format, a...)
	}
	var v any
	if err := jsonv2.Unmarshal(body, &v); err != nil {
		var syn *jsontext.SyntacticError
		if errors.As(err, &syn) && syn.JSONPointer != "" {
			return nil, invalid("it is not one JSON value in UTF-8 with each member name once, at %s", syn.JSONPointer)
		}
		return nil, invalid("it is not one JSON value in UTF-8 with each member name once")
	}
	doc, err := contracts.Decode("run-configuration.json", body)
	if err != nil {
		return nil, invalid("it is not JSON")
	}
	schema, err := contracts.Compile("run-configuration.schema.json")
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(doc); err != nil {
		var ve *jsonschema.ValidationError
		if !errors.As(err, &ve) {
			return nil, invalid("run-configuration.schema.json refuses it")
		}
		return nil, invalid("run-configuration.schema.json refuses %s", strings.Join(leaves(ve), ", "))
	}
	var rc RunConfiguration
	if err := jsonv2.Unmarshal(body, &rc); err != nil {
		return nil, invalid("it does not decode as a run configuration")
	}
	for name, value := range rc.Variables {
		if len(value) > MaxVariableValue {
			return nil, refusal.New(refusal.RunConfigurationInvalid, []string{name}, "the document is refused: the variable %s holds more than %d bytes", name, MaxVariableValue)
		}
	}
	return &rc, nil
}

// leaves are the places the schema refused, each as the JSON pointer of the value and
// the keyword that refused it, sorted, each once. A member name propertyNames refuses
// is reported by the name, which is no value: the validator's location of it is not
// one to rely on, as it shares its storage with the locations validated after it.
func leaves(ve *jsonschema.ValidationError) []string {
	if pn, ok := ve.ErrorKind.(*kind.PropertyNames); ok {
		return []string{"the member name " + pn.Property + " (propertyNames)"}
	}
	if len(ve.Causes) == 0 {
		where := "/" + strings.Join(escaped(ve.InstanceLocation), "/")
		keyword := ""
		if ve.ErrorKind != nil {
			keyword = strings.Join(ve.ErrorKind.KeywordPath(), "/")
		}
		if keyword == "" {
			return []string{where}
		}
		return []string{where + " (" + keyword + ")"}
	}
	var out []string
	for _, c := range ve.Causes {
		out = append(out, leaves(c)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// escaped are the parts of a JSON pointer as RFC 6901 writes them.
func escaped(parts []string) []string {
	out := make([]string, len(parts))
	for i, t := range parts {
		out[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~", "~0"), "/", "~1")
	}
	return out
}
