package descriptor_test

import (
	"strings"
	"testing"

	"github.com/qoryai/forager/session/internal/descriptor"
)

// TestParsePrintsAPhraseForASecret pins the errors of Parse: a document's name, an id
// of its secrets or a value that fails the schema that contains qak_ or qrk_ is the
// phrase, and a clean one prints as before.
func TestParsePrintsAPhraseForASecret(t *testing.T) {
	const head = "version: 1\nruntime: amp\nruntime_version: \"1\"\nsources: {output: {format: jsonl}}\n" +
		"rules: [{source: output, match: {type: end}, type: dev.qory.runtime.ended, data: {reason: why}}]\n"
	declare := func(id string) string {
		return "  - {id: " + id + ", title: Key, name: AMP_KEY, hosts: [api.example.com], auth: {scheme: bearer}}\n"
	}
	for _, c := range []struct{ name, secrets, want string }{
		{"amp.yaml", " declares:\n" + declare("qak_x") + declare("qak_x"),
			"amp.yaml: secrets: (a name that contains an access key secret) is declared twice"},
		{"amp.yaml", " declares:\n" + declare("key") + declare("key"), "amp.yaml: secrets: key is declared twice"},
		{"amp.yaml", " declares:\n" + declare("key") + " one_of: [{id: qrk_y, of: [qak_z]}]\n",
			"amp.yaml: secrets: one_of (a name that contains a run key) lists (a name that contains an access key secret), which no declaration has as its id"},
		{"amp.yaml", " declares:\n" + declare("key") + " one_of: [{id: model, of: [other]}]\n",
			"amp.yaml: secrets: one_of model lists other, which no declaration has as its id"},
		{"/d/QRK_y/amp.yaml", " declares:\n" + declare("key") + declare("key"),
			"(a value that contains a run key): secrets: key is declared twice"},
	} {
		if _, err := descriptor.Parse(c.name, []byte(head+"secrets:\n"+c.secrets)); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// A value that fails the schema, and a document that is not YAML, are the phrase
	// when the name or the value contains a secret's prefix.
	for name, doc := range map[string]string{
		"amp.yaml":          head + "title: qak_x\nextra: QRK_y\n",
		"/d/qak_x/amp.yaml": "version: 1\n",
		"/d/qrk_y/amp.yaml": "a: [\n",
	} {
		_, err := descriptor.Parse(name, []byte(doc))
		if err == nil || strings.Contains(strings.ToLower(err.Error()), "qak_") || strings.Contains(strings.ToLower(err.Error()), "qrk_") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
