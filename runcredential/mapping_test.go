package runcredential

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/refusal"
)

func TestAllowed(t *testing.T) {
	open := issuer()
	open.Allow = nil
	two := issuer()
	two.Allow.Values = []string{"example-namespace", "second-namespace"}
	for _, c := range []struct {
		name  string
		i     Issuer
		value any // nil removes the claim
		want  bool
	}{
		{"listed", issuer(), "example-namespace", true},
		{"the second listed", two, "second-namespace", true},
		{"not listed", issuer(), "other-namespace", false},
		{"a prefix of one listed", issuer(), "example", false},
		{"missing", issuer(), nil, false},
		{"not a string", issuer(), []any{"example-namespace"}, false},
		{"no allow", open, "other-namespace", true},
	} {
		claims := validClaims()
		if c.value == nil {
			delete(claims, "namespace")
		} else {
			claims["namespace"] = c.value
		}
		if got := c.i.Allowed(claims); got != c.want {
			t.Errorf("%s: Allowed = %v; want %v", c.name, got, c.want)
		}
	}
}

func TestLabels(t *testing.T) {
	want := map[string]string{"forge": "example-forge", "repository": "example-namespace/project", "run_key": "rk-0001"}
	fromClaim := issuer()
	fromClaim.LabelMapping.Forge = Source{Claim: "forge"}
	fromClaim.LabelMapping.Repository = Source{Claim: "project"}
	constant := issuer()
	constant.LabelMapping.Repository = Source{Value: "example-namespace/project"}
	for _, c := range []struct {
		name   string
		i      Issuer
		change map[string]any
		want   map[string]string
		reason string
	}{
		{"the example", issuer(), nil, want, ""},
		{"labels the claims hold beside are ignored", issuer(), map[string]any{"forge": "other-forge", "repository": "other", "run_key": "other"}, want, ""},
		{"from claims", fromClaim, map[string]any{"forge": "example-forge"}, map[string]string{"forge": "example-forge", "repository": "project", "run_key": "rk-0001"}, ""},
		{"a constant repository", constant, map[string]any{"namespace": nil, "project": nil}, want, ""},
		{"no namespace", issuer(), map[string]any{"namespace": nil}, nil, "a claim the mapping names is missing or not a string"},
		{"project a number", issuer(), map[string]any{"project": 7.0}, nil, "a claim the mapping names is missing or not a string"},
		{"project empty", issuer(), map[string]any{"project": ""}, nil, "a claim the mapping names is missing or not a string"},
		{"no sub", issuer(), map[string]any{"sub": nil}, nil, "a claim the mapping names is missing or not a string"},
		{"forge claim missing", fromClaim, nil, nil, "a claim the mapping names is missing or not a string"},
		{"a claim holds the join", issuer(), map[string]any{"namespace": "example-namespace/inner"}, nil, "a claim of repository holds the join"},
		{"a repository of 257 bytes", issuer(), map[string]any{"project": strings.Repeat("p", 257-len("example-namespace/"))}, nil, "a label is beyond the label limits"},
		{"a repository of 256 bytes", issuer(), map[string]any{"project": strings.Repeat("p", 256-len("example-namespace/"))}, map[string]string{"forge": "example-forge", "repository": "example-namespace/" + strings.Repeat("p", 256-len("example-namespace/")), "run_key": "rk-0001"}, ""},
		{"a sub of 257 bytes", issuer(), map[string]any{"sub": strings.Repeat("r", 257)}, nil, "a label is beyond the label limits"},
		{"a sub not UTF-8", issuer(), map[string]any{"sub": "rk-\xff"}, nil, "a label is beyond the label limits"},
	} {
		t.Run(c.name, func(t *testing.T) {
			claims := validClaims()
			for k, v := range c.change {
				if v == nil {
					delete(claims, k)
				} else {
					claims[k] = v
				}
			}
			got, err := c.i.Labels(claims)
			if r := reason(t, err); r != c.reason {
				t.Fatalf("Labels refuses with %q; want %q", r, c.reason)
			}
			if !maps.Equal(got, c.want) {
				t.Errorf("Labels = %v; want %v", got, c.want)
			}
		})
	}
	odd := issuer()
	odd.LabelMapping.RunKey.Claim = "run"
	if _, err := odd.Labels(validClaims()); reason(t, err) != "run_key is not the claim sub" {
		t.Errorf("a run_key from another claim: %v", err)
	}
}

func TestDetails(t *testing.T) {
	none := issuer()
	none.DetailMapping = nil
	two := issuer()
	two.DetailMapping = map[string]Claim{"requester": {Claim: "requester"}, "team": {Claim: "team"}}
	for _, c := range []struct {
		name   string
		i      Issuer
		change map[string]any
		want   map[string]string
		reason string
	}{
		{"the example", issuer(), nil, map[string]string{"requester": "example-requester"}, ""},
		{"no details", none, nil, nil, ""},
		{"two keys", two, map[string]any{"team": "example-team"}, map[string]string{"requester": "example-requester", "team": "example-team"}, ""},
		{"an empty value", issuer(), map[string]any{"requester": ""}, map[string]string{"requester": ""}, ""},
		{"missing, so not decided", issuer(), map[string]any{"requester": nil}, map[string]string{}, ""},
		{"one of two missing", two, nil, map[string]string{"requester": "example-requester"}, ""},
		{"a number", issuer(), map[string]any{"requester": 1.0}, nil, "a claim of details is not a string"},
		{"an array", issuer(), map[string]any{"requester": []any{"example-requester"}}, nil, "a claim of details is not a string"},
		{"a line feed", issuer(), map[string]any{"requester": "a\nb"}, nil, "a claim of details holds a control character"},
		{"U+2029", issuer(), map[string]any{"requester": "a b"}, nil, "a claim of details holds a control character"},
		{"not UTF-8", issuer(), map[string]any{"requester": "a\xffb"}, nil, "a claim of details holds a control character"},
	} {
		t.Run(c.name, func(t *testing.T) {
			claims := validClaims()
			for k, v := range c.change {
				if v == nil {
					delete(claims, k)
				} else {
					claims[k] = v
				}
			}
			got, err := c.i.Details(claims)
			if r := reason(t, err); r != c.reason {
				t.Fatalf("Details refuses with %q; want %q", r, c.reason)
			}
			if !maps.Equal(got, c.want) {
				t.Errorf("Details = %v; want %v", got, c.want)
			}
		})
	}
}

// TestDetailsNullIsPresent pins that a claim present as JSON null is a claim that is not
// a string, not a missing one.
func TestDetailsNullIsPresent(t *testing.T) {
	claims := validClaims()
	claims["requester"] = nil
	if _, err := issuer().Details(claims); reason(t, err) != "a claim of details is not a string" {
		t.Errorf("a requester of null: %v", err)
	}
}

// TestCompareKeepsAKeyTheCredentialDoesNotDecide pins that a details key whose claim
// the run credential does not carry is the session's: Details leaves it out, and
// Compare lets the session's value stand.
func TestCompareKeepsAKeyTheCredentialDoesNotDecide(t *testing.T) {
	claims := validClaims()
	delete(claims, "requester")
	i := issuer()
	labels, err := i.Labels(claims)
	if err != nil {
		t.Fatal(err)
	}
	details, err := i.Details(claims)
	if err != nil {
		t.Fatal(err)
	}
	if r := Compare(nil, map[string]any{"requester": "example-requester-flag"}, labels, details); r != nil {
		t.Errorf("Compare = %v; want the session's requester to stand", r)
	}
}

func TestCompare(t *testing.T) {
	cred := map[string]string{"forge": "example-forge", "repository": "example-namespace/project", "run_key": "rk-0001"}
	credDetails := map[string]string{"requester": "example-requester"}
	for _, c := range []struct {
		name    string
		labels  map[string]string
		details map[string]any
		code    string
		names   []string
	}{
		{"nothing sent", nil, nil, "", nil},
		{"the same", map[string]string{"forge": "example-forge", "repository": "example-namespace/project", "run_key": "rk-0001"},
			map[string]any{"requester": "example-requester"}, "", nil},
		{"labels and details the mapping does not set", map[string]string{"forge": "example-forge", "team": "example-team"},
			map[string]any{"ticket": "example-ticket", "count": 3.0}, "", nil},
		{"another repository", map[string]string{"forge": "example-forge", "repository": "example-namespace/other"}, nil,
			refusal.TargetDiffersFromCredential, []string{"labels.repository=example-namespace/project"}},
		{"another forge and repository", map[string]string{"forge": "other-forge", "repository": "other"}, nil,
			refusal.TargetDiffersFromCredential, []string{"labels.forge=example-forge", "labels.repository=example-namespace/project"}},
		{"the target first", map[string]string{"forge": "other-forge", "run_key": "rk-0002"}, map[string]any{"requester": "someone-else"},
			refusal.TargetDiffersFromCredential, []string{"labels.forge=example-forge"}},
		{"another run key", map[string]string{"run_key": "rk-0002"}, nil,
			refusal.DiffersFromCredential, []string{"labels.run_key=rk-0001"}},
		{"another requester", nil, map[string]any{"requester": "someone-else"},
			refusal.DiffersFromCredential, []string{"about.details.requester=example-requester"}},
		{"a requester that is not a string", nil, map[string]any{"requester": []any{"example-requester"}},
			refusal.DiffersFromCredential, []string{"about.details.requester=example-requester"}},
		{"another run key and requester", map[string]string{"run_key": ""}, map[string]any{"requester": "someone-else"},
			refusal.DiffersFromCredential, []string{"about.details.requester=example-requester", "labels.run_key=rk-0001"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := Compare(c.labels, c.details, cred, credDetails)
			if c.code == "" {
				if r != nil {
					t.Fatalf("Compare = %v; want nil", r)
				}
				return
			}
			if r == nil {
				t.Fatalf("Compare = nil; want %s", c.code)
			}
			if r.Code != c.code || !slices.Equal(r.Names, c.names) {
				t.Errorf("Compare = %s %v; want %s %v", r.Code, r.Names, c.code, c.names)
			}
			if !refusal.GatewayDecides(r.Code) {
				t.Errorf("%s is not a gateway's code", r.Code)
			}
		})
	}
}
