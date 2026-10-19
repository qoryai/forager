package credential

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/policy"
)

// adapter writes a program that answers as a source code host's adapter would for the
// repository it is given: one token, git over HTTPS with basic, the API with bearer,
// and the repository's paths alone.
func adapter(t *testing.T, body string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "adapter")
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return file
}

const answerFor = `cat <<JSON
{"version": 1, "token": "token-for-$1", "expires_at": "2099-01-01T00:00:00Z",
 "apply": [
  {"hosts": ["git.example.com"], "scheme": "basic", "username": "x-access-token", "paths": ["/$1.git/*"]},
  {"hosts": ["api.git.example.com"], "scheme": "bearer", "paths": ["/repos/$1", "/repos/$1/*"]}],
 "placeholders": ["GIT_HOST_TOKEN"]}
JSON
`

func TestAnAdapterSaysHowItsTokenIsUsed(t *testing.T) {
	defs := []Definition{{Name: "product", Adapter: []string{adapter(t, answerFor), "${argument}"}, Argument: `[a-z0-9-]+/[a-z0-9-]+`, Hosts: []string{"*.example.com"}}}
	allow := []string{"git.example.com", "api.git.example.com"}
	held, err := Resolve(context.Background(), defs, []policy.Selected{{Name: "product", Argument: "acme/shop"}}, policy.Enforce, allow, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if len(held.Uses) != 2 || held.Uses[0].Scheme != "basic" || held.Uses[0].Paths[0] != "/acme/shop.git/*" || held.Uses[1].Token() != "token-for-acme/shop" {
		t.Errorf("uses %+v", held.Uses)
	}
	if len(held.Placeholders) != 1 || held.Placeholders[0] != "GIT_HOST_TOKEN" {
		t.Errorf("placeholders %v", held.Placeholders)
	}
	for _, u := range held.Uses {
		if u.Argument != "acme/shop" {
			t.Errorf("a use of %s has the argument %q, want the policy's", u.Name, u.Argument)
		}
	}
}

// TestEachCredentialHasItsHostsAndPlaceholders pins Credentials: one entry per
// credential, in the policy's order, with the hosts of every use of it in their order
// and the placeholders it sets alone, the definition's and then the adapter's, each once;
// a credential that sets none has an empty list.
func TestEachCredentialHasItsHostsAndPlaceholders(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "a-token")
	defs := []Definition{
		{Name: "model", Env: "MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer", Placeholders: []string{"MODEL_KEY"}},
		{Name: "product", Adapter: []string{adapter(t, answerFor), "${argument}"}, Argument: `[a-z0-9-]+/[a-z0-9-]+`, Placeholders: []string{"GIT_HOST_TOKEN", "PRODUCT_KEY"}},
		{Name: "plain", Env: "MODEL_TOKEN", Hosts: []string{"plain.example"}, Scheme: "bearer"},
	}
	sel := []policy.Selected{{Name: "product", Argument: "acme/shop"}, {Name: "model"}, {Name: "plain"}}
	held, err := Resolve(context.Background(), defs, sel, policy.Observe, nil, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	want := []Credential{
		{Name: "product", Hosts: []string{"git.example.com", "api.git.example.com"}, Placeholders: []string{"GIT_HOST_TOKEN", "PRODUCT_KEY"}},
		{Name: "model", Hosts: []string{"api.model.example"}, Placeholders: []string{"MODEL_KEY"}},
		{Name: "plain", Hosts: []string{"plain.example"}, Placeholders: []string{}},
	}
	if got := held.Credentials(); !reflect.DeepEqual(got, want) {
		t.Errorf("credentials %+v, want %+v", got, want)
	}
}

func TestWhatCannotHoldIsNoRun(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "a-token")
	good := adapter(t, answerFor)
	env := Definition{Name: "model", Env: "MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"}
	for name, c := range map[string]struct {
		defs  []Definition
		sel   []policy.Selected
		allow []string
		want  string
	}{
		"a name the machine does not define": {nil, []policy.Selected{{Name: "product"}}, nil, "does not define"},
		"an argument that is a flag": {[]Definition{{Name: "product", Adapter: []string{good, "${argument}"}, Argument: `[a-z]+/[a-z]+`}},
			[]policy.Selected{{Name: "product", Argument: "--upload-pack=x"}}, nil, "not one the machine provides for"},
		"an argument nobody provided for": {[]Definition{env}, []policy.Selected{{Name: "model", Argument: "x"}}, nil, "takes no argument"},
		"a pattern that compiles alone and not anchored": {[]Definition{{Name: "product", Adapter: []string{good, "${argument}"}, Argument: `a\Q`}},
			[]policy.Selected{{Name: "product", Argument: "a"}}, nil, "argument: error parsing regexp"},
		"a host the run does not reach": {[]Definition{env}, []policy.Selected{{Name: "model"}}, []string{"example.com"}, "which no allow entry covers"},
		"a claim above the machine's": {[]Definition{{Name: "product", Adapter: []string{good, "${argument}"}, Argument: `.+`, Hosts: []string{"git.example.com"}}},
			[]policy.Selected{{Name: "product", Argument: "acme/shop"}}, []string{"*.example.com"}, "above the hosts"},
		"paths above the machine's": {[]Definition{{Name: "product", Adapter: []string{good, "${argument}"}, Argument: `.+`, Paths: []string{"/acme/*", "/repos/acme/*"}}},
			[]policy.Selected{{Name: "product", Argument: "other/shop"}}, []string{"*.example.com", "git.example.com"}, "above the paths"},
		"an adapter that fails": {[]Definition{{Name: "product", Adapter: []string{adapter(t, "echo 'no installation for this repository' >&2; exit 3\n")}}},
			[]policy.Selected{{Name: "product"}}, nil, "no installation for this repository"},
		"an adapter that answers with another scheme": {[]Definition{{Name: "product", Adapter: []string{adapter(t, `echo '{"version":1,"token":"t","apply":[{"hosts":["a.example"],"scheme":"digest"}]}'`+"\n")}}},
			[]policy.Selected{{Name: "product"}}, nil, "scheme"},
		"two that claim one host": {[]Definition{env, {Name: "other", Env: "MODEL_TOKEN", Hosts: []string{"*.model.example"}, Scheme: "bearer"}},
			[]policy.Selected{{Name: "model"}, {Name: "other"}}, []string{"*.model.example"}, "both claim"},
		"a definition with two sources": {[]Definition{{Name: "model", Env: "MODEL_TOKEN", File: "/x", Hosts: []string{"a.example"}, Scheme: "bearer"}},
			[]policy.Selected{{Name: "model"}}, nil, "exactly one"},
		"a variable that is not set": {[]Definition{{Name: "model", Env: "NOT_SET_ANYWHERE", Hosts: []string{"a.example"}, Scheme: "bearer"}},
			[]policy.Selected{{Name: "model"}}, []string{"a.example"}, "empty"},
	} {
		held, err := Resolve(context.Background(), c.defs, c.sel, policy.Enforce, c.allow, func(l string) { t.Log(l) })
		if err == nil {
			held.Close()
			t.Errorf("%s: the credentials resolved", name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		} else if strings.Contains(err.Error(), "a-token") || strings.Contains(err.Error(), "token-for") {
			t.Errorf("%s: a token in an error: %v", name, err)
		}
	}
}

func TestAFileIsReadWhenItIsUsed(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	os.WriteFile(file, []byte("first\n"), 0o600)
	held, err := Resolve(context.Background(), []Definition{{Name: "api", File: file, Hosts: []string{"api.example"}, Scheme: "header", Header: "X-Api-Key"}}, []policy.Selected{{Name: "api"}}, policy.Observe, nil, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	os.WriteFile(file, []byte("second\n"), 0o600)
	if got := held.Uses[0].Token(); got != "second" {
		t.Errorf("the token is %q after the file changed", got)
	}
}

// TestAnAdapterReceivesNoAccessKeyVariable pins that the access key's variables, the
// gateway's alone, are not in an adapter's environment, while Forager's others are.
func TestAnAdapterReceivesNoAccessKeyVariable(t *testing.T) {
	t.Setenv("QORY_ACCESS_KEY_SECRET", "qak_not-a-real-one")
	t.Setenv("QORY_ACCESS_KEY_ID", "ak_f1xt0re000000000")
	t.Setenv("QORY_APIARY_PUBLIC_KEY", "[]")
	t.Setenv("ADAPTER_SEES", "yes")
	check := `if [ -n "$QORY_ACCESS_KEY_SECRET$QORY_ACCESS_KEY_ID$QORY_APIARY_PUBLIC_KEY" ] || [ "$ADAPTER_SEES" != yes ]; then echo "the environment is wrong" >&2; exit 1; fi
` + answerFor
	defs := []Definition{{Name: "product", Adapter: []string{adapter(t, check), "${argument}"}, Argument: `[a-z0-9-]+/[a-z0-9-]+`, Hosts: []string{"*.example.com"}}}
	held, err := Resolve(context.Background(), defs, []policy.Selected{{Name: "product", Argument: "acme/shop"}}, policy.Enforce, []string{"git.example.com", "api.git.example.com"}, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	held.Close()
}

// The phrases a credential message prints in place of a name that contains qak_ or
// qrk_ in any case.
const (
	accessKeyPhrase = "(a name that contains an access key secret)"
	runKeyPhrase    = "(a name that contains a run key)"
)

// resolveError is the error of Resolve for defs and the selection sel, with the token
// of MODEL_TOKEN set and allow as the allow list under enforce.
func resolveError(t *testing.T, defs []Definition, sel []policy.Selected, allow []string) error {
	t.Helper()
	t.Setenv("MODEL_TOKEN", "a-token")
	held, err := Resolve(context.Background(), defs, sel, policy.Enforce, allow, func(l string) { t.Log(l) })
	if err == nil {
		held.Close()
	}
	return err
}

// envDefinition is a credential named name whose token comes from MODEL_TOKEN.
func envDefinition(name string) Definition {
	return Definition{Name: name, Env: "MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"}
}

// nameMessages are the eight credential messages that print a name or a placeholder
// as accesskey.ShownName shows it: the policy's two selection messages, the token read,
// the allow-list check, and Check's name, source, argument and placeholder checks. The
// placeholder message has two entries, one for the credential's name and one for the
// placeholder. Each entry is a function of that name, with the message it gives for the
// phrase p in its place; a clean name gives the message with the name itself in place
// of p.
var nameMessages = map[string]struct {
	err  func(t *testing.T, name string) error
	want func(p string) string
}{
	"a name the machine does not define": {
		func(t *testing.T, name string) error {
			return resolveError(t, nil, []policy.Selected{{Name: name}}, nil)
		},
		func(p string) string {
			return "the policy selects the credential " + p + ", which this machine does not define"
		},
	},
	"a name selected twice": {
		func(t *testing.T, name string) error {
			return resolveError(t, []Definition{envDefinition(name)}, []policy.Selected{{Name: name}, {Name: name}}, []string{"api.model.example"})
		},
		func(p string) string { return "the policy selects the credential " + p + " twice" },
	},
	"a token that cannot be read": {
		func(t *testing.T, name string) error {
			return resolveError(t, []Definition{{Name: name, Env: "NOT_SET_ANYWHERE", Hosts: []string{"api.model.example"}, Scheme: "bearer"}}, []policy.Selected{{Name: name}}, nil)
		},
		func(p string) string { return "credential " + p + ": the token is empty" },
	},
	"a host the allow list does not cover": {
		func(t *testing.T, name string) error {
			return resolveError(t, []Definition{envDefinition(name)}, []policy.Selected{{Name: name}}, []string{"example.com"})
		},
		func(p string) string {
			return "add api.model.example to the run's egress allow list, or remove the credential " + p + ": the credential " + p + " is for api.model.example, which no allow entry covers"
		},
	},
	"a name outside the grammar": {
		func(_ *testing.T, name string) error { return Definition{Name: name + "!"}.Check() },
		func(p string) string {
			return "the credential name " + p + " is not 1 to 64 of a-z, 0-9, underscore, dot and dash"
		},
	},
	"a definition without a source": {
		func(_ *testing.T, name string) error { return Definition{Name: name}.Check() },
		func(p string) string {
			return "credential " + p + ": exactly one of env, file and adapter says where the token comes from"
		},
	},
	"an argument pattern that does not compile": {
		func(_ *testing.T, name string) error {
			d := envDefinition(name)
			d.Argument = "("
			return d.Check()
		},
		func(p string) string {
			return "credential " + p + ": argument: error parsing regexp: missing closing ): `(`"
		},
	},
	"a placeholder outside a variable's grammar": {
		func(_ *testing.T, name string) error {
			d := envDefinition(name)
			d.Placeholders = []string{"bad-name"}
			return d.Check()
		},
		func(p string) string {
			return "credential " + p + ": the placeholder \"bad-name\" is not a variable's name"
		},
	},
	"a placeholder with the name in it": {
		func(_ *testing.T, name string) error {
			d := envDefinition("model")
			d.Placeholders = []string{name + "-"}
			return d.Check()
		},
		func(p string) string { return "credential model: the placeholder " + p + " is not a variable's name" },
	},
}

// noSecretPrefix fails the test when the error contains qak_ or qrk_ in any case.
func noSecretPrefix(t *testing.T, what string, err error) {
	t.Helper()
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "qak_") || strings.Contains(lower, "qrk_") {
		t.Errorf("%s: the error contains a secret's prefix: %v", what, err)
	}
}

// TestACredentialMessagePrintsAPhraseForASecretInAName pins that the eight credential
// messages of nameMessages, the policy's two selection messages, the token read, the
// allow-list check, and Check's name, source, argument and placeholder checks, print a
// phrase in place of a name or a placeholder that contains qak_ or qrk_ in any case,
// and the rest of the sentence word for word. The
// messages Resolve gives after Check, and Check's after its name check, see only a name
// the grammar admits, lower case; Check refuses any other case first, as the cases of
// "a name outside the grammar" show.
func TestACredentialMessagePrintsAPhraseForASecretInAName(t *testing.T) {
	lower := map[string]string{
		"qak_x": accessKeyPhrase, "a.qak_b": accessKeyPhrase, "x-qak_": accessKeyPhrase,
		"qrk_x": runKeyPhrase, "a.qrk_b": runKeyPhrase, "x-qrk_": runKeyPhrase,
	}
	anyCase := map[string]string{
		"QAK_x": accessKeyPhrase, "QaK_x": accessKeyPhrase, "x-qAk_": accessKeyPhrase,
		"QRK_x": runKeyPhrase, "qRk_x": runKeyPhrase, "x-QrK_": runKeyPhrase,
	}
	for what, m := range nameMessages {
		names := lower
		switch what {
		case "a name the machine does not define", "a name outside the grammar", "a placeholder with the name in it":
			names = maps.Clone(lower)
			maps.Copy(names, anyCase)
		}
		for name, phrase := range names {
			err := m.err(t, name)
			if err == nil {
				t.Errorf("%s, %s: no error", what, name)
				continue
			}
			if got, want := err.Error(), m.want(phrase); got != want {
				t.Errorf("%s, %s:\n got %s\nwant %s", what, name, got, want)
			}
			noSecretPrefix(t, what+", "+name, err)
		}
	}
}

// TestAnAccessKeyPhraseWinsOverARunKeyPhrase pins that a name with both prefixes, the
// run key's first, prints the access key secret's phrase.
func TestAnAccessKeyPhraseWinsOverARunKeyPhrase(t *testing.T) {
	for _, what := range []string{"a name the machine does not define", "a definition without a source", "a placeholder with the name in it"} {
		m := nameMessages[what]
		err := m.err(t, "qrk_x.qak_y")
		if err == nil {
			t.Fatalf("%s: no error", what)
		}
		if got, want := err.Error(), m.want(accessKeyPhrase); got != want {
			t.Errorf("%s:\n got %s\nwant %s", what, got, want)
		}
		noSecretPrefix(t, what, err)
	}
}

// TestACleanNamePrintsAsItIs pins that a name without qak_ or qrk_ prints as before:
// quoted where the message quotes it and bare where it does not.
func TestACleanNamePrintsAsItIs(t *testing.T) {
	shown := map[string]string{
		"a name the machine does not define":         `"model"`,
		"a name selected twice":                      `"model"`,
		"a token that cannot be read":                "model",
		"a host the allow list does not cover":       "model",
		"a name outside the grammar":                 `"model!"`,
		"a definition without a source":              "model",
		"an argument pattern that does not compile":  "model",
		"a placeholder outside a variable's grammar": "model",
		"a placeholder with the name in it":          `"model-"`,
	}
	for what, m := range nameMessages {
		err := m.err(t, "model")
		if err == nil {
			t.Errorf("%s: no error", what)
			continue
		}
		if got, want := err.Error(), m.want(shown[what]); got != want {
			t.Errorf("%s:\n got %s\nwant %s", what, got, want)
		}
	}
}

// The phrases a credential message prints in place of a value that is not a name, such
// as an adapter's path, its error or its error output, that contains qak_ or qrk_ in
// any case.
const (
	accessKeyValuePhrase = "(a value that contains an access key secret)"
	runKeyValuePhrase    = "(a value that contains a run key)"
)

// phraseMessages are the credential messages that print one part as
// accesskey.ShownName or accesskey.ShownValue shows it, beside the eight of
// nameMessages. Each entry is the error for v in that part, the message it gives for p
// in the part's place, whether the part is a value and not a name, whether v may be in
// any case or only in lower case, as the name grammar holds a name a check sees after
// Check, and how the part shows for the clean v "model".
var phraseMessages = map[string]struct {
	err     func(t *testing.T, v string) error
	want    func(p string) string
	value   bool
	anyCase bool
	clean   string
}{
	"the first of two credentials that claim one host": {
		err: func(t *testing.T, v string) error {
			return resolveError(t, []Definition{envDefinition(v), envDefinition("other")}, []policy.Selected{{Name: v}, {Name: "other"}}, []string{"api.model.example"})
		},
		want: func(p string) string {
			return "claim api.model.example in only one of the credentials " + p + " and other; both claim it, and a host has one"
		},
		clean: "model",
	},
	"the second of two credentials that claim one host": {
		err: func(t *testing.T, v string) error {
			return resolveError(t, []Definition{envDefinition("other"), envDefinition(v)}, []policy.Selected{{Name: "other"}, {Name: v}}, []string{"api.model.example"})
		},
		want: func(p string) string {
			return "claim api.model.example in only one of the credentials other and " + p + "; both claim it, and a host has one"
		},
		clean: "model",
	},
	"an argument pattern whose error quotes it": {
		err: func(_ *testing.T, v string) error {
			d := envDefinition("model")
			d.Argument = v + "("
			return d.Check()
		},
		want:    func(p string) string { return "credential model: argument: " + p },
		value:   true,
		anyCase: true,
		clean:   "error parsing regexp: missing closing ): `model(`",
	},
	"an adapter with a scheme": {
		err: func(_ *testing.T, v string) error {
			return Definition{Name: v, Adapter: []string{"/bin/true"}, Scheme: "bearer"}.Check()
		},
		want: func(p string) string {
			return "credential " + p + ": an adapter says how its token is used; the scheme is not the definition's to give"
		},
		clean: "model",
	},
	"an argument for env": {
		err: func(_ *testing.T, v string) error {
			return Definition{Name: v, Env: "MODEL_TOKEN", Argument: "x"}.Check()
		},
		want: func(p string) string {
			return "credential " + p + ": an argument is an adapter's; env and file take none"
		},
		clean: "model",
	},
	"env without hosts": {
		err: func(_ *testing.T, v string) error { return Definition{Name: v, Env: "MODEL_TOKEN"}.Check() },
		want: func(p string) string {
			return "credential " + p + ": a token from env or file needs the hosts it is for"
		},
		clean: "model",
	},
	"an argument for a credential that takes none, its name": {
		err: func(t *testing.T, v string) error {
			return resolveError(t, []Definition{envDefinition(v)}, []policy.Selected{{Name: v, Argument: "x"}}, nil)
		},
		want:  func(p string) string { return "credential " + p + ` takes no argument and the policy gives "x"` },
		clean: "model",
	},
	"an argument for a credential that takes none, the argument": {
		err: func(t *testing.T, v string) error {
			return resolveError(t, []Definition{envDefinition("model")}, []policy.Selected{{Name: "model", Argument: v}}, nil)
		},
		want:    func(p string) string { return "credential model takes no argument and the policy gives " + p },
		anyCase: true,
		clean:   `"model"`,
	},
	"an argument the machine does not provide for, its name": {
		err: func(t *testing.T, v string) error {
			return resolveError(t, []Definition{{Name: v, Adapter: []string{"/bin/false"}, Argument: `[a-z]+/[a-z]+`}}, []policy.Selected{{Name: v, Argument: "x"}}, nil)
		},
		want: func(p string) string {
			return "credential " + p + `: the argument "x" is not one the machine provides for`
		},
		clean: "model",
	},
	"an argument the machine does not provide for, the argument": {
		err: func(t *testing.T, v string) error {
			return resolveError(t, []Definition{{Name: "product", Adapter: []string{"/bin/false"}, Argument: `[a-z]+/[a-z]+`}}, []policy.Selected{{Name: "product", Argument: v}}, nil)
		},
		want: func(p string) string {
			return "credential product: the argument " + p + " is not one the machine provides for"
		},
		anyCase: true,
		clean:   `"model"`,
	},
}

// phrases are the values each prefix is tried in, with the phrase each gives: in lower
// case and, for a part that may be in any case, in others too, the access key secret's
// phrase when both are in it.
func phrases(value, anyCase bool) map[string]string {
	ak, rk := accessKeyPhrase, runKeyPhrase
	if value {
		ak, rk = accessKeyValuePhrase, runKeyValuePhrase
	}
	out := map[string]string{"qak_x": ak, "a.qak_b": ak, "x-qak_": ak, "qrk_x": rk, "a.qrk_b": rk, "x-qrk_": rk, "qrk_x.qak_y": ak}
	if anyCase {
		maps.Copy(out, map[string]string{"QAK_x": ak, "x-qAk_": ak, "QRK_x": rk, "qRk_x": rk, "QRK_x.QAK_y": ak})
	}
	return out
}

// TestMoreCredentialMessagesPrintAPhraseForASecret pins that the messages of
// phraseMessages print a phrase in place of a name, an argument or an error's text that
// contains qak_ or qrk_ in any case, with the rest of the sentence word for word, and
// the part as before for a clean value.
func TestMoreCredentialMessagesPrintAPhraseForASecret(t *testing.T) {
	for what, m := range phraseMessages {
		for v, phrase := range phrases(m.value, m.anyCase) {
			err := m.err(t, v)
			if err == nil {
				t.Errorf("%s, %s: no error", what, v)
				continue
			}
			if got, want := err.Error(), m.want(phrase); got != want {
				t.Errorf("%s, %s:\n got %s\nwant %s", what, v, got, want)
			}
			noSecretPrefix(t, what+", "+v, err)
		}
		err := m.err(t, "model")
		if err == nil {
			t.Errorf("%s, model: no error", what)
		} else if got, want := err.Error(), m.want(m.clean); got != want {
			t.Errorf("%s, model:\n got %s\nwant %s", what, got, want)
		}
	}
}

// TestAnAdaptersFailurePrintsAPhraseForASecret pins the message of an adapter that
// fails: its path, its error and the first line of its error output, where the run's
// argument can be, each print a phrase when they contain qak_ or qrk_ in any case, and
// print as before when they do not.
func TestAnAdaptersFailurePrintsAPhraseForASecret(t *testing.T) {
	echo := adapter(t, `echo "no installation for $1" >&2; exit 3`+"\n")
	for v, phrase := range phrases(true, true) {
		err := resolveError(t, []Definition{{Name: "product", Adapter: []string{echo, "${argument}"}, Argument: `.+`}}, []policy.Selected{{Name: "product", Argument: v}}, nil)
		if want := "credential product: the adapter " + echo + ": exit status 3: " + phrase; err == nil || err.Error() != want {
			t.Errorf("the run's argument %s in the error output:\n got %v\nwant %s", v, err, want)
		} else {
			noSecretPrefix(t, "the run's argument "+v, err)
		}
		missing := filepath.Join(t.TempDir(), v)
		err = resolveError(t, []Definition{{Name: "product", Adapter: []string{missing}}}, []policy.Selected{{Name: "product"}}, nil)
		if want := "credential product: the adapter " + phrase + ": " + phrase + ": "; err == nil || err.Error() != want {
			t.Errorf("the path %s:\n got %v\nwant %s", v, err, want)
		} else {
			noSecretPrefix(t, "the path "+v, err)
		}
	}
	err := resolveError(t, []Definition{{Name: "product", Adapter: []string{echo, "${argument}"}, Argument: `.+`}}, []policy.Selected{{Name: "product", Argument: "acme/shop"}}, nil)
	if want := "credential product: the adapter " + echo + ": exit status 3: no installation for acme/shop"; err == nil || err.Error() != want {
		t.Errorf("a clean argument:\n got %v\nwant %s", err, want)
	}
	missing := filepath.Join(t.TempDir(), "model")
	err = resolveError(t, []Definition{{Name: "product", Adapter: []string{missing}}}, []policy.Selected{{Name: "product"}}, nil)
	if want := "credential product: the adapter " + missing + ": fork/exec " + missing + ": no such file or directory: "; err == nil || err.Error() != want {
		t.Errorf("a clean path:\n got %v\nwant %s", err, want)
	}
}

// renewReport is the line a renewal of a credential named name reports, with the
// adapter body and the shape the first answer had.
func renewReport(t *testing.T, name, body, shape string) string {
	t.Helper()
	said := make(chan string, 1)
	h := &held{
		def:    Definition{Name: name, Adapter: []string{adapter(t, body)}},
		report: func(l string) { said <- l },
		shape:  shape,
		done:   make(chan struct{}),
		// Expired, and asked long ago, so the renewal runs at once.
		expires: time.Now(),
		asked:   time.Now().Add(-time.Hour),
	}
	go h.renew()
	defer h.stop()
	select {
	case l := <-said:
		return l
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: no renewal was reported", name)
	}
	return ""
}

// TestARenewalReportPrintsAPhraseForASecretInAName pins the two lines a renewal
// reports, one that fails and one that answers with another shape: a name that
// contains qak_ or qrk_ prints the phrase, and a clean name prints as it is.
func TestARenewalReportPrintsAPhraseForASecretInAName(t *testing.T) {
	const fails = "echo 'no installation' >&2; exit 3\n"
	answers := `echo '{"version":1,"token":"t","expires_at":"2099-01-01T00:00:00Z","apply":[{"hosts":["a.example"],"scheme":"bearer"}]}'` + "\n"
	for name, phrase := range map[string]string{"qak_x": accessKeyPhrase, "a.qrk_b": runKeyPhrase, "qrk_x.qak_y": accessKeyPhrase, "model": "model"} {
		if l := renewReport(t, name, fails, ""); !strings.HasPrefix(l, "credential "+phrase+" was not renewed: the adapter ") || !strings.HasSuffix(l, ": exit status 3: no installation") {
			t.Errorf("a renewal of %s that fails: %s", name, l)
		} else if lower := strings.ToLower(l); strings.Contains(lower, "qak_") || strings.Contains(lower, "qrk_") {
			t.Errorf("a renewal of %s that fails: a secret's prefix in %s", name, l)
		}
		want := "credential " + phrase + " was not renewed: the adapter answered with other hosts, schemes or paths than when the run started"
		if l := renewReport(t, name, answers, "another shape"); l != want {
			t.Errorf("a renewal of %s with another shape:\n got %s\nwant %s", name, l, want)
		}
	}
}

// adapterIn writes a program that runs body into a directory named dir under a new
// temporary directory, and returns its path.
func adapterIn(t *testing.T, dir, body string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), dir)
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(d, "adapter")
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestAnAdaptersAnswerPrintsAPhraseForASecretInItsPath pins the messages about an
// adapter's answer, each of which prints the adapter's path: when the path contains
// qak_ or qrk_ in any case it prints the value's phrase, and a clean path prints as it
// is. The rest of each message is the same for both.
func TestAnAdaptersAnswerPrintsAPhraseForASecretInItsPath(t *testing.T) {
	answer := func(apply string) string {
		return `echo '{"version":1,"token":"t","apply":[` + apply + `]}'` + "\n"
	}
	for what, c := range map[string]struct {
		body string
		def  Definition
		rest string
	}{
		"no JSON document":         {"echo not-a-document\n", Definition{}, " did not print a JSON document: "},
		"outside the schema":       {`echo '{"version":1}'` + "\n", Definition{}, ": "},
		"basic without a username": {answer(`{"hosts":["a.example"],"scheme":"basic"}`), Definition{}, ": the scheme basic needs a username without a colon or a space"},
		"no token":                 {`echo '{"version":1,"apply":[{"hosts":["a.example"],"scheme":"bearer"}]}'` + "\n", Definition{}, " gave no token for [a.example]"},
		"a host above":             {answer(`{"hosts":["a.example"],"scheme":"bearer"}`), Definition{Hosts: []string{"b.example"}}, " claims a.example, above the hosts the machine gives it"},
		"every path":               {answer(`{"hosts":["a.example"],"scheme":"bearer"}`), Definition{Paths: []string{"/x/*"}}, " claims every path of [a.example], above the paths the machine gives it"},
		"a path above":             {answer(`{"hosts":["a.example"],"scheme":"bearer","paths":["/y"]}`), Definition{Paths: []string{"/x/*"}}, " claims the path /y, above the paths the machine gives it"},
	} {
		for dir, phrase := range map[string]string{"qak_x": accessKeyValuePhrase, "QRK_x": runKeyValuePhrase, "a.qRk_b.QaK_c": accessKeyValuePhrase, "model": ""} {
			path := adapterIn(t, dir, c.body)
			d := c.def
			d.Name, d.Adapter = "product", []string{path}
			err := resolveError(t, []Definition{d}, []policy.Selected{{Name: "product"}}, nil)
			shown := phrase
			if phrase == "" {
				shown = path
			}
			want := "credential product: the adapter " + shown + c.rest
			// A rest that ends with ": " is followed by a decoder's or a schema's error.
			if err == nil || !strings.HasPrefix(err.Error(), want) || (!strings.HasSuffix(c.rest, ": ") && err.Error() != want) {
				t.Errorf("%s, %s:\n got %v\nwant %s", what, dir, err, want)
				continue
			}
			if phrase != "" {
				noSecretPrefix(t, what+", "+dir, err)
			}
		}
	}
}

// TestAFileThatCannotBeReadPrintsAPhraseForASecretInItsPath pins the error of a
// credential's file that cannot be read: when its text contains qak_ or qrk_ in any
// case, as the path in it can, the value's phrase is printed in its place, and a clean
// error prints as it is.
func TestAFileThatCannotBeReadPrintsAPhraseForASecretInItsPath(t *testing.T) {
	for dir, phrase := range map[string]string{"qak_x": accessKeyValuePhrase, "QRK_x": runKeyValuePhrase, "a.qRk_b.QaK_c": accessKeyValuePhrase} {
		file := filepath.Join(t.TempDir(), dir, "token")
		err := resolveError(t, []Definition{{Name: "model", File: file, Hosts: []string{"api.model.example"}, Scheme: "bearer"}}, []policy.Selected{{Name: "model"}}, nil)
		if want := "credential model: " + phrase; err == nil || err.Error() != want {
			t.Errorf("%s:\n got %v\nwant %s", dir, err, want)
			continue
		}
		noSecretPrefix(t, dir, err)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %v does not wrap fs.ErrNotExist", dir, err)
		}
	}
	file := filepath.Join(t.TempDir(), "model", "token")
	err := resolveError(t, []Definition{{Name: "model", File: file, Hosts: []string{"api.model.example"}, Scheme: "bearer"}}, []policy.Selected{{Name: "model"}}, nil)
	if want := "credential model: open " + file + ": no such file or directory"; err == nil || err.Error() != want {
		t.Errorf("a clean path:\n got %v\nwant %s", err, want)
	}
}

// TestAnAdaptersAnswerContentsPrintAPhraseForASecret pins the messages that print what
// an adapter's answer contains: a path it claims, the schema's or the decoder's error,
// which can quote the answer, and a scheme a definition gives. Each prints the value's
// phrase in place of a value or an error text that contains qak_ or qrk_ in any case,
// and a clean one as it is.
func TestAnAdaptersAnswerContentsPrintAPhraseForASecret(t *testing.T) {
	answer := func(apply string) string {
		return `echo '{"version":1,"token":"t","apply":[` + apply + `]}'` + "\n"
	}
	for what, c := range map[string]struct {
		body string
		def  Definition
		want string
	}{
		"a path above":           {answer(`{"hosts":["a.example"],"scheme":"bearer","paths":["/qak_x"]}`), Definition{Paths: []string{"/x/*"}}, " claims the path " + accessKeyValuePhrase + ", above the paths the machine gives it"},
		"a clean path above":     {answer(`{"hosts":["a.example"],"scheme":"bearer","paths":["/y"]}`), Definition{Paths: []string{"/x/*"}}, " claims the path /y, above the paths the machine gives it"},
		"a host of the schema":   {answer(`{"hosts":["QRK_x.example"],"scheme":"bearer"}`), Definition{}, ": " + runKeyValuePhrase},
		"a member of the schema": {`echo '{"version":1,"token":"t","apply":[{"hosts":["a.example"],"scheme":"bearer"}],"qak_x":1}'` + "\n", Definition{}, ": " + accessKeyValuePhrase},
	} {
		path := adapterIn(t, "model", c.body)
		d := c.def
		d.Name, d.Adapter = "product", []string{path}
		err := resolveError(t, []Definition{d}, []policy.Selected{{Name: "product"}}, nil)
		if want := "credential product: the adapter " + path + c.want; err == nil || err.Error() != want {
			t.Errorf("%s:\n got %v\nwant %s", what, err, want)
			continue
		}
		noSecretPrefix(t, what, err)
	}
	for scheme, want := range map[string]string{"qak_x": accessKeyValuePhrase, "a QRK_x": runKeyValuePhrase, "other": `"other"`} {
		err := Definition{Name: "product", Env: "PRODUCT_TOKEN", Hosts: []string{"a.example"}, Scheme: scheme}.Check()
		if want := "the scheme " + want + " is not bearer, basic or header"; err == nil || err.Error() != want {
			t.Errorf("%s:\n got %v\nwant %s", scheme, err, want)
		}
	}
}

// modelKey is a model key named name whose token comes from MODEL_TOKEN, for the
// Messages API at api.model.example, set in x-api-key.
func modelKey(name string) Definition {
	return Definition{Name: name, Env: "MODEL_TOKEN", Format: "anthropic-messages", Endpoint: "https://api.model.example/anthropic", Scheme: "header", Header: "x-api-key"}
}

// TestAModelKeyThatCannotBeOneIsRefused pins each refusal of Check for a model key's
// definition, word for word: a format outside api-format.schema.json, an endpoint from
// which no host is read, hosts, paths or placeholders beside the endpoint, a scheme
// the proxy does not implement, oauth beside a scheme other than bearer, key prefixes
// other than 1 to 4 of 1 to 32 printable ASCII characters without a space, a prefix
// twice, and an argument for env; and, for a credential without format, endpoint,
// oauth or key_prefixes.
func TestAModelKeyThatCannotBeOneIsRefused(t *testing.T) {
	const (
		endpoint = "credential model: set endpoint to an https URL with a host and no user, query or fragment: Forager reads no host from it"
		beside   = "credential model: remove hosts, paths and placeholders from the model key: its endpoint gives its host, and the session gives the runtime the key's variable"
		shape    = "credential model: write each key prefix as 1 to 32 characters of printable ASCII without a space: "
		noFormat = "credential plain: add format to the credential, or remove endpoint, oauth and key_prefixes: only a model key has them"
	)
	plain := Definition{Name: "plain", Env: "MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"}
	for name, c := range map[string]struct {
		change func(*Definition)
		want   string
	}{
		"an unknown format": {func(d *Definition) { d.Format = "other-format" },
			`credential model: set format to anthropic-messages, openai-responses, openai-chat or gemini: "other-format" is no API format Forager knows`},
		"no endpoint":                 {func(d *Definition) { d.Endpoint = "" }, endpoint},
		"an http endpoint":            {func(d *Definition) { d.Endpoint = "http://api.model.example/anthropic" }, endpoint},
		"an endpoint with a user":     {func(d *Definition) { d.Endpoint = "https://user@api.model.example/anthropic" }, endpoint},
		"an endpoint with a query":    {func(d *Definition) { d.Endpoint = "https://api.model.example/anthropic?beta=1" }, endpoint},
		"an endpoint with a fragment": {func(d *Definition) { d.Endpoint = "https://api.model.example/anthropic#messages" }, endpoint},
		"an endpoint with port 0":     {func(d *Definition) { d.Endpoint = "https://api.model.example:0/anthropic" }, endpoint},
		"hosts":                       {func(d *Definition) { d.Hosts = []string{"api.model.example"} }, beside},
		"paths":                       {func(d *Definition) { d.Paths = []string{"/anthropic/*"} }, beside},
		"placeholders":                {func(d *Definition) { d.Placeholders = []string{"ANTHROPIC_API_KEY"} }, beside},
		"an unknown scheme":           {func(d *Definition) { d.Scheme = "digest" }, `credential model: the scheme "digest" is not bearer, basic or header`},
		"header without a name":       {func(d *Definition) { d.Header = "" }, "credential model: the scheme header needs a header's name"},
		"oauth beside header":         {func(d *Definition) { d.OAuth = true }, "credential model: remove oauth, or set the scheme to bearer: oauth marks a bearer alone"},
		"oauth beside basic": {func(d *Definition) { d.Scheme, d.Header, d.Username, d.OAuth = "basic", "", "x", true },
			"credential model: remove oauth, or set the scheme to bearer: oauth marks a bearer alone"},
		"an empty list of key prefixes": {func(d *Definition) { d.KeyPrefixes = []string{} }, "credential model: list 1 to 4 key prefixes, or none: the model key lists 0"},
		"five key prefixes": {func(d *Definition) { d.KeyPrefixes = []string{"a-", "b-", "c-", "d-", "e-"} },
			"credential model: list 1 to 4 key prefixes, or none: the model key lists 5"},
		"an empty key prefix":           {func(d *Definition) { d.KeyPrefixes = []string{""} }, shape + `"" is not`},
		"a key prefix with a space":     {func(d *Definition) { d.KeyPrefixes = []string{"sk ant"} }, shape + `"sk ant" is not`},
		"a key prefix with a tab":       {func(d *Definition) { d.KeyPrefixes = []string{"sk\tant"} }, shape + `"sk\tant" is not`},
		"a key prefix outside ASCII":    {func(d *Definition) { d.KeyPrefixes = []string{"sk-ä"} }, shape + `"sk-ä" is not`},
		"a key prefix of 33 characters": {func(d *Definition) { d.KeyPrefixes = []string{strings.Repeat("k", 33)} }, shape + `"` + strings.Repeat("k", 33) + `" is not`},
		"a key prefix twice": {func(d *Definition) { d.KeyPrefixes = []string{"sk-ant-", "sk-ant-oat", "sk-ant-"} },
			`credential model: list the key prefix "sk-ant-" once: the model key lists it twice`},
		"an argument for env": {func(d *Definition) { d.Argument = "x" }, "credential model: an argument is an adapter's; env and file take none"},
	} {
		d := modelKey("model")
		c.change(&d)
		if err := d.Check(); err == nil || err.Error() != c.want {
			t.Errorf("%s:\n got %v\nwant %s", name, err, c.want)
		}
	}
	for name, change := range map[string]func(*Definition){
		"an endpoint":                   func(d *Definition) { d.Endpoint = "https://api.model.example/anthropic" },
		"oauth":                         func(d *Definition) { d.OAuth = true },
		"key prefixes":                  func(d *Definition) { d.KeyPrefixes = []string{"sk-ant-"} },
		"an empty list of key prefixes": func(d *Definition) { d.KeyPrefixes = []string{} },
	} {
		d := plain
		change(&d)
		if err := d.Check(); err == nil || err.Error() != noFormat {
			t.Errorf("a credential without format with %s:\n got %v\nwant %s", name, err, noFormat)
		}
	}
	for name, change := range map[string]func(*Definition){
		"as given":        func(*Definition) {},
		"oauth as bearer": func(d *Definition) { d.Scheme, d.Header, d.OAuth = "bearer", "", true },
		"four key prefixes of 32 characters": func(d *Definition) {
			d.KeyPrefixes = []string{strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("~", 32), strings.Repeat("!", 32)}
		},
		"an endpoint with a port": func(d *Definition) { d.Endpoint = "https://api.model.example:8443/anthropic" },
		"a file":                  func(d *Definition) { d.Env, d.File = "", "/run/model-key" },
		"an adapter": func(d *Definition) {
			d.Env, d.Adapter, d.Argument = "", []string{"/bin/true", "${argument}"}, "[a-z]+"
		},
	} {
		d := modelKey("model")
		change(&d)
		if err := d.Check(); err != nil {
			t.Errorf("a model key %s: %v", name, err)
		}
	}
}

// TestAModelKeyMatchesItsPrefixes pins KeyMatches: a value that starts with one of the
// prefixes, or any value when there are none.
func TestAModelKeyMatchesItsPrefixes(t *testing.T) {
	for _, c := range []struct {
		prefixes []string
		value    string
		want     bool
	}{
		{nil, "anything", true},
		{nil, "", true},
		{[]string{}, "anything", true},
		{[]string{"sk-ant-"}, "sk-ant-fake-value", true},
		{[]string{"sk-ant-"}, "sk-ant-", true},
		{[]string{"sk-ant-api", "sk-ant-oat"}, "sk-ant-oat01-fake-value", true},
		{[]string{"sk-ant-"}, "SK-ANT-fake-value", false},
		{[]string{"sk-ant-"}, " sk-ant-fake-value", false},
		{[]string{"sk-ant-"}, "sk-an", false},
		{[]string{"sk-ant-"}, "", false},
	} {
		if got := KeyMatches(c.prefixes, []byte(c.value)); got != c.want {
			t.Errorf("KeyMatches(%q, %q) = %v, want %v", c.prefixes, c.value, got, c.want)
		}
	}
}

// TestAModelKeysTokenThatMatchesNoPrefixIsRefused pins the prefix check of a model
// key's token, from env, from a file, and from an adapter: Resolve refuses the run
// with the prefixes in the message and never the token. An adapter that gives a model
// key placeholders, or sets it with another scheme than the definition's, is refused
// as well.
func TestAModelKeysTokenThatMatchesNoPrefixIsRefused(t *testing.T) {
	const token = "other-fake-value"
	file := filepath.Join(t.TempDir(), "model-key")
	if err := os.WriteFile(file, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	answer := func(apply, more string) string {
		return `echo '{"version":1,"token":"` + token + `","apply":[` + apply + `]` + more + `}'` + "\n"
	}
	set := `{"hosts":["api.model.example"],"scheme":"header","header":"X-Api-Key"}`
	one := "credential model: give the model key model a token that starts with \"sk-ant-\", its key_prefixes: the token starts with none of them"
	for name, c := range map[string]struct {
		change func(*Definition)
		want   string
	}{
		"env":  {func(*Definition) {}, one},
		"file": {func(d *Definition) { d.Env, d.File = "", file }, one},
		"env, two prefixes": {func(d *Definition) { d.KeyPrefixes = []string{"sk-ant-api", "sk-ant-oat"} },
			"credential model: give the model key model a token that starts with \"sk-ant-api\" or \"sk-ant-oat\", its key_prefixes: the token starts with none of them"},
		"an adapter": {func(d *Definition) { d.Env, d.Adapter = "", []string{adapter(t, answer(set, ""))} }, one},
	} {
		d := modelKey("model")
		d.KeyPrefixes = []string{"sk-ant-"}
		c.change(&d)
		t.Setenv("MODEL_TOKEN", token)
		held, err := Resolve(context.Background(), []Definition{d}, []policy.Selected{{Name: "model"}}, policy.Observe, nil, func(l string) { t.Log(l) })
		if err == nil {
			held.Close()
			t.Errorf("%s: the credentials resolved", name)
			continue
		}
		if err.Error() != c.want || strings.Contains(err.Error(), token) {
			t.Errorf("%s:\n got %v\nwant %s", name, err, c.want)
		}
	}
	for name, c := range map[string]struct {
		body string
		want string
	}{
		"placeholders":     {answer(set, `,"placeholders":["MODEL_KEY"]`), "remove placeholders from the answer of the adapter %s: the model key model takes none, since the session gives the runtime the key's variable"},
		"another scheme":   {answer(`{"hosts":["api.model.example"],"scheme":"bearer"}`, ""), "set the model key model in the answer of the adapter %s with the scheme of its definition: the answer has another"},
		"another header":   {answer(`{"hosts":["api.model.example"],"scheme":"header","header":"Authorization"}`, ""), "set the model key model in the answer of the adapter %s with the scheme of its definition: the answer has another"},
		"a host above its": {answer(`{"hosts":["other.model.example"],"scheme":"header","header":"x-api-key"}`, ""), "the adapter %s claims other.model.example, above the hosts the machine gives it"},
	} {
		path := adapter(t, c.body)
		d := modelKey("model")
		d.Env, d.Adapter = "", []string{path}
		held, err := Resolve(context.Background(), []Definition{d}, []policy.Selected{{Name: "model"}}, policy.Observe, nil, func(l string) { t.Log(l) })
		if err == nil {
			held.Close()
			t.Errorf("an adapter's answer with %s: the credentials resolved", name)
			continue
		}
		if want := "credential model: " + fmt.Sprintf(c.want, path); err.Error() != want {
			t.Errorf("an adapter's answer with %s:\n got %v\nwant %s", name, err, want)
		}
	}
	d := modelKey("model")
	d.KeyPrefixes = []string{"sk-ant-"}
	t.Setenv("MODEL_TOKEN", "sk-ant-fake-value")
	held, err := Resolve(context.Background(), []Definition{d}, []policy.Selected{{Name: "model"}}, policy.Observe, nil, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatalf("a token that starts with the prefix: %v", err)
	}
	defer held.Close()
	if len(held.Uses) != 1 || held.Uses[0].Token() != "sk-ant-fake-value" {
		t.Errorf("uses %+v", held.Uses)
	}
}

// TestAModelKeysFileReadAgainKeepsAMatchingToken pins a model key's file read as it is
// used: a value that starts with none of the key prefixes is not taken, and the token
// read when the run started stays; a value that matches is taken.
func TestAModelKeysFileReadAgainKeepsAMatchingToken(t *testing.T) {
	file := filepath.Join(t.TempDir(), "model-key")
	if err := os.WriteFile(file, []byte("sk-ant-fake-first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := modelKey("model")
	d.Env, d.File, d.KeyPrefixes = "", file, []string{"sk-ant-"}
	held, err := Resolve(context.Background(), []Definition{d}, []policy.Selected{{Name: "model"}}, policy.Observe, nil, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	for _, c := range []struct{ written, want string }{
		{"other-fake-value\n", "sk-ant-fake-first"},
		{"\n", "sk-ant-fake-first"},
		{"sk-ant-fake-second\n", "sk-ant-fake-second"},
	} {
		if err := os.WriteFile(file, []byte(c.written), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := held.Uses[0].Token(); got != c.want {
			t.Errorf("after the file became %q the token is %q, want %q", c.written, got, c.want)
		}
	}
}

// TestAModelKeyIsHeldOnItsEndpointsHost pins a model key of the machine's resolved:
// one use on the endpoint's host, on every path, with the definition's scheme, format,
// endpoint and oauth, and a credential with no placeholder.
func TestAModelKeyIsHeldOnItsEndpointsHost(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "sk-ant-oat01-fake-value")
	d := modelKey("model")
	d.Scheme, d.Header, d.OAuth = "bearer", "", true
	d.Endpoint = "https://API.Model.example:8443/anthropic"
	held, err := Resolve(context.Background(), []Definition{d}, []policy.Selected{{Name: "model"}}, policy.Enforce, []string{"api.model.example"}, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if len(held.Uses) != 1 {
		t.Fatalf("uses %+v", held.Uses)
	}
	if u := held.Uses[0]; !slices.Equal(u.Hosts, []string{"api.model.example"}) || u.Paths != nil || u.Scheme != "bearer" || u.Format != "anthropic-messages" ||
		u.Endpoint != d.Endpoint || !u.OAuth || u.Stored || u.Token() != "sk-ant-oat01-fake-value" {
		t.Errorf("the use %+v", u)
	}
	want := []Credential{{Name: "model", Hosts: []string{"api.model.example"}, Placeholders: []string{}, Scheme: "bearer",
		Format: "anthropic-messages", Endpoint: d.Endpoint, OAuth: true}}
	if got := held.Credentials(); !reflect.DeepEqual(got, want) {
		t.Errorf("credentials %+v, want %+v", got, want)
	}
	if len(held.Placeholders) != 0 || held.Start != "model" {
		t.Errorf("placeholders %v, start %q", held.Placeholders, held.Start)
	}
}

// TestAModelKeyOutsideTheAllowListIsRefused pins the allow-list check for a model key
// under enforce: an endpoint host that no allow entry covers is refused with the text
// of a host credential, the endpoint's host in place of a credential's hosts, and no
// token in the message.
func TestAModelKeyOutsideTheAllowListIsRefused(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "sk-ant-fake-value")
	held, err := Resolve(context.Background(), []Definition{modelKey("model")}, []policy.Selected{{Name: "model"}}, policy.Enforce, []string{"other.example", "*.other-model.example"}, func(l string) { t.Log(l) })
	want := "add api.model.example to the run's egress allow list, or remove the credential model: the credential model is for api.model.example, which no allow entry covers"
	if err == nil {
		held.Close()
		t.Fatal("a model key outside the allow list resolved")
	}
	if err.Error() != want || strings.Contains(err.Error(), "sk-ant-fake-value") {
		t.Errorf("\n got %v\nwant %s", err, want)
	}
	held, err = Resolve(context.Background(), []Definition{modelKey("model")}, []policy.Selected{{Name: "model"}}, policy.Enforce, []string{"*.model.example"}, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatalf("a model key whose endpoint host an allow entry covers: %v", err)
	}
	held.Close()
}
