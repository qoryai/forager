package gateway

import (
	"errors"
	"fmt"
	"testing"

	"github.com/qoryai/forager/sealed"
)

// TestSealedFixNamesTheFaultOfARequestOrASchema pins the step and the clause of the two
// refusals of sealed.Open that come from no answer: a request outside the contract's
// forms, and an answer refused while secrets-answer.schema.json does not compile.
func TestSealedFixNamesTheFaultOfARequestOrASchema(t *testing.T) {
	compiles := answerSchemaCompiles
	t.Cleanup(func() { answerSchemaCompiles = compiles })
	for name, c := range map[string]struct {
		err        error
		compiles   bool
		fix, cause string
	}{
		"a request outside its forms": {fmt.Errorf("%w: the run id or the digest is outside its form", sealed.ErrRequest), true,
			"report this bug in the gateway's secrets request to the Forager maintainers", "the gateway does not open the answer"},
		"a schema that does not compile": {fmt.Errorf("%w: secrets-answer.schema.json does not compile: x", sealed.ErrAnswer), false,
			"report this bug in secrets-answer.schema.json to the Forager maintainers", "the answer does not open"},
		"an answer outside the schema": {sealed.ErrAnswer, true,
			"report this answer to whoever runs Qory Apiary", "the answer does not open"},
		"a signature": {sealed.ErrSignature, true,
			"pin Qory Apiary's current signing key in apiary_public_key", "the answer does not open"},
	} {
		answerSchemaCompiles = func() bool { return c.compiles }
		if fix, cause := sealedFix(c.err); fix != c.fix || cause != c.cause {
			t.Errorf("%s: %q, %q; want %q, %q", name, fix, cause, c.fix, c.cause)
		}
	}
	answerSchemaCompiles = compiles
	if !answerSchemaCompiles() {
		t.Error("secrets-answer.schema.json does not compile")
	}
	if fix, _ := sealedFix(errors.New("another error")); fix != "report this answer to whoever runs Qory Apiary" {
		t.Errorf("another error: %q", fix)
	}
}
