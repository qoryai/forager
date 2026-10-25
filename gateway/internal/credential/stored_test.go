package credential

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/policy"
)

// storedModel is a credential from the server for api.model.example.
func storedModel(value string) Stored {
	return Stored{Name: "server-model", Apply: []StoredApply{{Hosts: []string{"api.model.example"}, Scheme: "header", Header: "x-api-key"}}, Placeholders: []string{"MODEL_API_KEY"},
		Value: func() []byte { return []byte(value) }}
}

// TestACredentialFromTheServerReplacesTheMachinesOnItsHost pins the precedence: a
// machine's credential whose hosts claim a host of a credential from the server, the
// same host or one above or below it, is not read, and the server's is the one use on
// the host, its value and no token, and the credential with its scheme and header; a machine's credential for another host stays; an
// adapter whose answer claims the host is dropped.
func TestACredentialFromTheServerReplacesTheMachinesOnItsHost(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "a-token")
	for name, hosts := range map[string][]string{
		"the same host":  {"api.model.example"},
		"a host above":   {"*.model.example"},
		"another casing": {"API.model.example"},
	} {
		t.Run(name, func(t *testing.T) {
			defs := []Definition{
				{Name: "model", Env: "MODEL_TOKEN", Hosts: hosts, Scheme: "bearer", Placeholders: []string{"MACHINE_KEY"}},
				{Name: "plain", Env: "MODEL_TOKEN", Hosts: []string{"plain.example"}, Scheme: "bearer"},
			}
			held, err := ResolveWith(context.Background(), defs, []policy.Selected{{Name: "model"}, {Name: "plain"}}, []Stored{storedModel("server-value")}, "", policy.Observe, nil, func(l string) { t.Log(l) })
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			var names []string
			for _, u := range held.Uses {
				names = append(names, u.Name)
			}
			if !slices.Equal(names, []string{"plain", "server-model"}) {
				t.Fatalf("uses %v, want plain and server-model", names)
			}
			u := held.Uses[1]
			if !u.Stored || u.Token() != "" || string(u.Value()) != "server-value" || u.Header != "x-api-key" || u.Scheme != "header" {
				t.Errorf("the server's use %+v", u)
			}
			if held.Uses[0].Value() != nil || held.Uses[0].Token() != "a-token" {
				t.Errorf("the machine's use plain %+v", held.Uses[0])
			}
			if !slices.Equal(held.Placeholders, []string{"MODEL_API_KEY"}) {
				t.Errorf("placeholders %v, want the server's alone", held.Placeholders)
			}
			want := []Credential{{Name: "plain", Hosts: []string{"plain.example"}, Placeholders: []string{}}, {Name: "server-model", Hosts: []string{"api.model.example"}, Placeholders: []string{"MODEL_API_KEY"},
				Stored: true, Scheme: "header", Header: "x-api-key", Items: []Item{{Hosts: []string{"api.model.example"}, Scheme: "header", Header: "x-api-key"}}}}
			if got := held.Credentials(); !reflect.DeepEqual(got, want) {
				t.Errorf("credentials %+v, want %+v", got, want)
			}
		})
	}
	t.Run("an adapter", func(t *testing.T) {
		defs := []Definition{{Name: "product", Adapter: []string{adapter(t, `echo '{"version":1,"token":"t","apply":[{"hosts":["api.model.example"],"scheme":"bearer"}]}'`+"\n")}}}
		held, err := ResolveWith(context.Background(), defs, []policy.Selected{{Name: "product"}}, []Stored{storedModel("server-value")}, "", policy.Observe, nil, func(l string) { t.Log(l) })
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		if len(held.Uses) != 1 || held.Uses[0].Name != "server-model" {
			t.Errorf("uses %+v", held.Uses)
		}
	})
}

// TestACredentialFromTheServerOfTheSameNameReplacesTheMachines pins the plan's case:
// forager.yaml's model on api.anthropic.com and the run configuration's model on the
// same host. The server's replaces the machine's, the name check runs against the
// machine's credentials that stay, and the one use is the server's model.
func TestACredentialFromTheServerOfTheSameNameReplacesTheMachines(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "a-token")
	defs := []Definition{{Name: "model", Env: "MODEL_TOKEN", Hosts: []string{"api.anthropic.com"}, Scheme: "header", Header: "x-api-key", Placeholders: []string{"ANTHROPIC_API_KEY"}}}
	stored := []Stored{{Name: "model", Apply: []StoredApply{{Hosts: []string{"api.anthropic.com"}, Scheme: "header", Header: "x-api-key"}}, Placeholders: []string{"ANTHROPIC_API_KEY"},
		Value: func() []byte { return []byte("server-value") }}}
	held, err := ResolveWith(context.Background(), defs, []policy.Selected{{Name: "model"}}, stored, "", policy.Enforce, []string{"api.anthropic.com"}, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if len(held.Uses) != 1 || !held.Uses[0].Stored || held.Uses[0].Name != "model" || string(held.Uses[0].Value()) != "server-value" || held.Uses[0].Token() != "" {
		t.Errorf("uses %+v, want the server's model alone", held.Uses)
	}
	if !slices.Equal(held.Placeholders, []string{"ANTHROPIC_API_KEY"}) {
		t.Errorf("placeholders %v", held.Placeholders)
	}
}

// TestTwoCredentialsFromTheServerOnOneHostShowNoSecretInAName pins the overlap message
// of two credentials from the server whose names contain qak_: the phrase in place of
// each name.
func TestTwoCredentialsFromTheServerOnOneHostShowNoSecretInAName(t *testing.T) {
	a, b := storedModel("server-value"), storedModel("server-value")
	a.Name, b.Name = "x-qak_not-a-real-secret", "y-qak_not-a-real-secret"
	_, err := ResolveWith(context.Background(), nil, nil, []Stored{a, b}, "", policy.Observe, nil, func(l string) { t.Log(l) })
	if err == nil || strings.Contains(strings.ToLower(err.Error()), "qak_") || !strings.HasPrefix(err.Error(), "claim api.model.example in only one of the credentials") {
		t.Errorf("%v", err)
	}
}

// TestNoCredentialFromTheServerIsResolveUnchanged pins ResolveWith with no credential
// from the server: what Resolve gives, the machine's key.
func TestNoCredentialFromTheServerIsResolveUnchanged(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "a-token")
	defs := []Definition{envDefinition("model")}
	held, err := ResolveWith(context.Background(), defs, []policy.Selected{{Name: "model"}}, nil, "", policy.Observe, nil, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if len(held.Uses) != 1 || held.Uses[0].Stored || held.Uses[0].Token() != "a-token" || held.Uses[0].Value() != nil {
		t.Errorf("uses %+v", held.Uses)
	}
}

// TestACredentialFromTheServerIsCheckedAsTheMachines pins the checks: a name a
// selected machine's credential has, two from the server on one host, and, under
// enforce, a host the allow list does not cover, each no run, with no value in the
// message.
func TestACredentialFromTheServerIsCheckedAsTheMachines(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "a-token")
	other := storedModel("server-value")
	other.Name = "server-other"
	for name, c := range map[string]struct {
		defs   []Definition
		sel    []policy.Selected
		stored []Stored
		allow  []string
		want   string
	}{
		"a name the machine's has": {[]Definition{{Name: "server-model", Env: "MODEL_TOKEN", Hosts: []string{"plain.example"}, Scheme: "bearer"}}, []policy.Selected{{Name: "server-model"}},
			[]Stored{storedModel("server-value")}, []string{"plain.example", "api.model.example"},
			`rename the run configuration's credential "server-model" or this machine's credential of that name; the machine's is for other hosts, so it stays, and the record lists each credential once`},
		"two on one host": {nil, nil, []Stored{storedModel("server-value"), other}, []string{"api.model.example"}, "claim api.model.example in only one of the credentials"},
		"a host the run does not reach": {nil, nil, []Stored{storedModel("server-value")}, []string{"plain.example"},
			"add api.model.example to the run's egress allow list, or remove the credential server-model: the credential server-model is for api.model.example, which no allow entry covers"},
	} {
		held, err := ResolveWith(context.Background(), c.defs, c.sel, c.stored, "", policy.Enforce, c.allow, func(l string) { t.Log(l) })
		if err == nil {
			held.Close()
			t.Errorf("%s: the credentials resolved", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "server-value") {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// startRefusal is the code, the names and the text of a refusal err is, empty when err
// is none.
func startRefusal(err error) (code string, names []string, text string) {
	var r *accesskey.Refusal
	if !errors.As(err, &r) {
		return "", nil, ""
	}
	return r.Code, r.Names, err.Error()
}

// TestAModelKeyStartsTheRunAsModelCredentialSays pins Held.Start: the model key that
// start names, the run's one model key when start is empty, and none when the run has
// no model key and start is empty. It pins each refusal, run_configuration_invalid
// with its text word for word: an empty start beside two model keys, with no name; a
// start beside no model key; and a start that names no model key of the run, a host
// credential included, each with the start as its name. A model key from the server
// counts as the machine's does.
func TestAModelKeyStartsTheRunAsModelCredentialSays(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "sk-ant-fake-value")
	first, second := modelKey("first"), modelKey("second")
	second.Endpoint = "https://api.other-model.example/v1"
	plain := Definition{Name: "plain", Env: "MODEL_TOKEN", Hosts: []string{"plain.example"}, Scheme: "bearer"}
	server := Stored{Name: "server-model", Format: "openai-responses", Endpoint: "https://api.server-model.example/v1", Apply: []StoredApply{{Hosts: []string{"api.server-model.example"}, Scheme: "bearer"}},
		Value: func() []byte { return []byte("sk-fake-server-value") }}
	selected := func(defs []Definition) []policy.Selected {
		var out []policy.Selected
		for _, d := range defs {
			out = append(out, policy.Selected{Name: d.Name})
		}
		return out
	}
	for name, c := range map[string]struct {
		defs   []Definition
		stored []Stored
		start  string
		want   string
	}{
		"no model key and no start":         {[]Definition{plain}, nil, "", ""},
		"one model key and no start":        {[]Definition{plain, first}, nil, "", "first"},
		"one model key from the server":     {[]Definition{plain}, []Stored{server}, "", "server-model"},
		"the start among two":               {[]Definition{first, second}, nil, "second", "second"},
		"the server's among two":            {[]Definition{first}, []Stored{server}, "server-model", "server-model"},
		"the machine's beside the server's": {[]Definition{first}, []Stored{server}, "first", "first"},
	} {
		held, err := ResolveWith(context.Background(), c.defs, selected(c.defs), c.stored, c.start, policy.Observe, nil, func(l string) { t.Log(l) })
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if held.Start != c.want {
			t.Errorf("%s: the start %q, want %q", name, held.Start, c.want)
		}
		held.Close()
	}
	for name, c := range map[string]struct {
		defs   []Definition
		stored []Stored
		start  string
		names  []string
		want   string
	}{
		"two model keys and no start": {[]Definition{first, plain, second}, nil, "", nil,
			"set model_credential in the run configuration, or give the run one model key: the run has the model keys first, second: run_configuration_invalid"},
		"a model key of each and no start": {[]Definition{first}, []Stored{server}, "", nil,
			"set model_credential in the run configuration, or give the run one model key: the run has the model keys first, server-model: run_configuration_invalid"},
		"a start and no model key": {[]Definition{plain}, nil, "first", []string{"first"},
			`remove model_credential from the run configuration, or give the run a model key "first": the run has no model key: run_configuration_invalid: first`},
		"a start and no credential": {nil, nil, "first", []string{"first"},
			`remove model_credential from the run configuration, or give the run a model key "first": the run has no model key: run_configuration_invalid: first`},
		"a start that names no model key": {[]Definition{first, second}, nil, "third", []string{"third"},
			`set model_credential in the run configuration to one of the run's model keys, first, second: the run has no model key "third": run_configuration_invalid: third`},
		"a start that names a host credential": {[]Definition{first, plain}, nil, "plain", []string{"plain"},
			`set model_credential in the run configuration to one of the run's model keys, first: the run has no model key "plain": run_configuration_invalid: plain`},
		"a start with a secret in its name": {[]Definition{first}, nil, "x-qak_not-a-real-secret", []string{"(a name that contains an access key secret)"},
			"set model_credential in the run configuration to one of the run's model keys, first: the run has no model key (a name that contains an access key secret): run_configuration_invalid: (a name that contains an access key secret)"},
	} {
		held, err := ResolveWith(context.Background(), c.defs, selected(c.defs), c.stored, c.start, policy.Observe, nil, func(l string) { t.Log(l) })
		if err == nil {
			held.Close()
			t.Errorf("%s: the credentials resolved", name)
			continue
		}
		code, names, text := startRefusal(err)
		if code != "run_configuration_invalid" || !slices.Equal(names, c.names) || text != c.want {
			t.Errorf("%s: %q %q\n got %v\nwant %s", name, code, names, err, c.want)
		}
		if strings.Contains(text, "sk-ant-fake-value") || strings.Contains(text, "sk-fake-server-value") {
			t.Errorf("%s: a value in the refusal: %s", name, text)
		}
	}
}

// TestTwoModelKeysMayShareAHost pins the host check beside model keys: two model keys
// on one host resolve, both held, since the proxy sets the start key alone; a model key
// and a host credential on one host are refused as two host credentials are, whichever
// comes first, and so are a model key and a host credential, both from the server, on
// one host.
func TestTwoModelKeysMayShareAHost(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "sk-ant-fake-value")
	first, second := modelKey("first"), modelKey("second")
	held, err := ResolveWith(context.Background(), []Definition{first, second}, []policy.Selected{{Name: "first"}, {Name: "second"}}, nil, "second", policy.Enforce, []string{"api.model.example"}, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatalf("two model keys on one host: %v", err)
	}
	if len(held.Uses) != 2 || held.Uses[0].Name != "first" || held.Uses[1].Name != "second" || held.Start != "second" {
		t.Errorf("uses %+v, start %q", held.Uses, held.Start)
	}
	held.Close()
	host := Definition{Name: "plain", Env: "MODEL_TOKEN", Hosts: []string{"api.model.example"}, Scheme: "bearer"}
	above := Definition{Name: "plain", Env: "MODEL_TOKEN", Hosts: []string{"*.model.example"}, Scheme: "bearer"}
	for name, c := range map[string]struct {
		defs []Definition
		want string
	}{
		"the model key first":       {[]Definition{first, host}, "claim api.model.example in only one of the credentials first and plain; both claim it, and a credential without paths is alone on its hosts"},
		"the host credential first": {[]Definition{host, first}, "claim api.model.example in only one of the credentials plain and first; both claim it, and a credential without paths is alone on its hosts"},
		"a host above":              {[]Definition{first, above}, "claim *.model.example in only one of the credentials first and plain; both claim it, and a credential without paths is alone on its hosts"},
	} {
		sel := []policy.Selected{{Name: c.defs[0].Name}, {Name: c.defs[1].Name}}
		held, err := ResolveWith(context.Background(), c.defs, sel, nil, "first", policy.Observe, nil, func(l string) { t.Log(l) })
		if err == nil {
			held.Close()
			t.Errorf("%s: the credentials resolved", name)
		} else if err.Error() != c.want {
			t.Errorf("%s:\n got %v\nwant %s", name, err, c.want)
		}
	}
	stored := Stored{Name: "server-key", Format: "anthropic-messages", Endpoint: "https://api.model.example/anthropic", Apply: []StoredApply{{Hosts: []string{"api.model.example"}, Scheme: "header", Header: "x-api-key"}},
		Value: func() []byte { return []byte("sk-ant-fake-server-value") }}
	held, err = ResolveWith(context.Background(), []Definition{first}, []policy.Selected{{Name: "first"}}, []Stored{stored, storedModel("server-value")}, "server-key", policy.Observe, nil, func(l string) { t.Log(l) })
	if err == nil {
		held.Close()
		t.Error("a model key and a host credential from the server on one host resolved")
	} else if want := "claim api.model.example in only one of the credentials server-key and server-model; both claim it, and a credential without paths is alone on its hosts"; err.Error() != want {
		t.Errorf("a model key and a host credential from the server:\n got %v\nwant %s", err, want)
	}
}

// TestAValueThatExpiresIsRenewedOnA401 pins a credential from the server with
// ExpiresAt and Rejected: one use per apply item, each Renewed, whose Rejected calls
// the Stored's; one without ExpiresAt is not Renewed, and its Rejected calls nothing.
func TestAValueThatExpiresIsRenewedOnA401(t *testing.T) {
	calls := 0
	forge := Stored{Name: "forge", Apply: []StoredApply{
		{Hosts: []string{"git.example"}, Scheme: "basic", Username: "x-access-token", Paths: []string{"/example-org/app.git/*"}},
		{Hosts: []string{"api.git.example"}, Scheme: "bearer"},
	}, Value: func() []byte { return []byte("forge-value") }, ExpiresAt: time.Date(2026, 10, 24, 13, 0, 0, 0, time.UTC), Rejected: func() { calls++ }}
	model := storedModel("model-value")
	model.Rejected = func() { t.Error("Rejected of a value without expires_at was called") }
	held, err := ResolveWith(context.Background(), nil, nil, []Stored{forge, model}, "", policy.Observe, nil, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	var got []string
	for _, u := range held.Uses {
		got = append(got, fmt.Sprintf("%s %v %s %v renewed=%v", u.Name, u.Hosts, u.Scheme, u.Paths, u.Renewed))
		u.Rejected()
	}
	want := []string{
		"forge [git.example] basic [/example-org/app.git/*] renewed=true",
		"forge [api.git.example] bearer [] renewed=true",
		"server-model [api.model.example] header [] renewed=false",
	}
	if !slices.Equal(got, want) {
		t.Errorf("uses %q, want %q", got, want)
	}
	if calls != 2 {
		t.Errorf("forge's Rejected was called %d times, want once per use", calls)
	}
}
