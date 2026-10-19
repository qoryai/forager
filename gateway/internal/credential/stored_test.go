package credential

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/policy"
)

// storedModel is a credential from the server for api.model.example.
func storedModel(value string) Stored {
	return Stored{Name: "server-model", Hosts: []string{"api.model.example"}, Scheme: "header", Header: "x-api-key", Placeholders: []string{"MODEL_API_KEY"},
		KeyForm: "api_key", Value: func() []byte { return []byte(value) }}
}

// TestACredentialFromTheServerReplacesTheMachinesOnItsHost pins the precedence: a
// machine's credential whose hosts claim a host of a credential from the server, the
// same host or one above or below it, is not read, and the server's is the one use on
// the host, its value and no token, with its key_form, and the credential with its
// scheme, header and key_form; a machine's credential for another host stays; an
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
			held, err := ResolveWith(context.Background(), defs, []policy.Selected{{Name: "model"}, {Name: "plain"}}, []Stored{storedModel("server-value")}, policy.Observe, nil, func(l string) { t.Log(l) })
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
			if !u.Stored || u.Token() != "" || string(u.Value()) != "server-value" || u.Header != "x-api-key" || u.Scheme != "header" || u.KeyForm != "api_key" {
				t.Errorf("the server's use %+v", u)
			}
			if held.Uses[0].Value() != nil || held.Uses[0].Token() != "a-token" {
				t.Errorf("the machine's use plain %+v", held.Uses[0])
			}
			if !slices.Equal(held.Placeholders, []string{"MODEL_API_KEY"}) {
				t.Errorf("placeholders %v, want the server's alone", held.Placeholders)
			}
			want := []Credential{{Name: "plain", Hosts: []string{"plain.example"}, Placeholders: []string{}}, {Name: "server-model", Hosts: []string{"api.model.example"}, Placeholders: []string{"MODEL_API_KEY"},
				Stored: true, Scheme: "header", Header: "x-api-key", KeyForm: "api_key"}}
			if got := held.Credentials(); !reflect.DeepEqual(got, want) {
				t.Errorf("credentials %+v, want %+v", got, want)
			}
		})
	}
	t.Run("an adapter", func(t *testing.T) {
		defs := []Definition{{Name: "product", Adapter: []string{adapter(t, `echo '{"version":1,"token":"t","apply":[{"hosts":["api.model.example"],"scheme":"bearer"}]}'`+"\n")}}}
		held, err := ResolveWith(context.Background(), defs, []policy.Selected{{Name: "product"}}, []Stored{storedModel("server-value")}, policy.Observe, nil, func(l string) { t.Log(l) })
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
	stored := []Stored{{Name: "model", Hosts: []string{"api.anthropic.com"}, Scheme: "header", Header: "x-api-key", Placeholders: []string{"ANTHROPIC_API_KEY"},
		Value: func() []byte { return []byte("server-value") }}}
	held, err := ResolveWith(context.Background(), defs, []policy.Selected{{Name: "model"}}, stored, policy.Enforce, []string{"api.anthropic.com"}, func(l string) { t.Log(l) })
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
	_, err := ResolveWith(context.Background(), nil, nil, []Stored{a, b}, policy.Observe, nil, func(l string) { t.Log(l) })
	if err == nil || strings.Contains(strings.ToLower(err.Error()), "qak_") || !strings.Contains(err.Error(), "both claim api.model.example") {
		t.Errorf("%v", err)
	}
}

// TestNoCredentialFromTheServerIsResolveUnchanged pins ResolveWith with no credential
// from the server: what Resolve gives, the machine's key.
func TestNoCredentialFromTheServerIsResolveUnchanged(t *testing.T) {
	t.Setenv("MODEL_TOKEN", "a-token")
	defs := []Definition{envDefinition("model")}
	held, err := ResolveWith(context.Background(), defs, []policy.Selected{{Name: "model"}}, nil, policy.Observe, nil, func(l string) { t.Log(l) })
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
			`rename the run configuration's credential "server-model" or this machine's credential of that name; the machine's is for other hosts, so it stays, and the record names each credential once`},
		"two on one host": {nil, nil, []Stored{storedModel("server-value"), other}, []string{"api.model.example"}, "both claim api.model.example"},
		"a host the run does not reach": {nil, nil, []Stored{storedModel("server-value")}, []string{"plain.example"},
			"the credential server-model is for api.model.example, which the run's allow list does not cover"},
	} {
		held, err := ResolveWith(context.Background(), c.defs, c.sel, c.stored, policy.Enforce, c.allow, func(l string) { t.Log(l) })
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
