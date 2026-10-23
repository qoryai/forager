package contracts_test

import (
	"testing"

	"github.com/qoryai/forager/contracts"
)

// TestTheNameFieldsAcceptEachPhrase pins the event fields whose schema lists the name
// phrases: session.started's image_name, run.policy_applied's image and the name of a
// variable and of a credential variable, and run.started's label keys. Each accepts the
// phrase of an access key secret, of a run key, of a run code and of an enrolment code,
// and refuses any other phrase.
func TestTheNameFieldsAcceptEachPhrase(t *testing.T) {
	for _, field := range []string{
		"events/session.started.schema.json#/properties/image_name",
		"events/run.policy_applied.schema.json#/properties/image",
		"events/run.policy_applied.schema.json#/properties/variables/items/properties/name",
		"events/run.policy_applied.schema.json#/properties/credential_variables/items/properties/name",
		"events/run.started.schema.json#/properties/labels/propertyNames",
	} {
		schema, err := contracts.Compile(field)
		if err != nil {
			t.Fatal(err)
		}
		for _, phrase := range []string{
			"(a name that contains an access key secret)",
			"(a name that contains a run key)",
			"(a name that contains a run code)",
			"(a name that contains an enrolment code)",
		} {
			if err := schema.Validate(phrase); err != nil {
				t.Errorf("%s refuses %s: %v", field, phrase, err)
			}
		}
		if schema.Validate("(a name that contains a secret)") == nil {
			t.Errorf("%s accepts a phrase Forager does not write", field)
		}
	}
}
