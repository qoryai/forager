package credential

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/runner/policy"
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
		"a host the run does not reach":   {[]Definition{env}, []policy.Selected{{Name: "model"}}, []string{"example.com"}, "allow list does not cover"},
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
// runner's alone, are not in an adapter's environment, while the runner's others are.
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
