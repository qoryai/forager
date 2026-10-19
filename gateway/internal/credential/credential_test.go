package credential

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		"a host the run does not reach": {[]Definition{env}, []policy.Selected{{Name: "model"}}, []string{"example.com"}, "allow list does not cover"},
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
			return "the credential " + p + " is for api.model.example, which the run's allow list does not cover"
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
