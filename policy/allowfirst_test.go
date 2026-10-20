package policy_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/policy"
)

// TestAllowFirstReadsAsHostsThemselves pins the allow_first grammar: read when
// present, nil when absent; refused by the schema for a *. pattern, an upper-case name,
// a port, a repeated entry and a 65th entry; and, for an entry that is neither a host
// name nor an IPv4 address in canonical form, refused with the error the other lists
// get.
func TestAllowFirstReadsAsHostsThemselves(t *testing.T) {
	l, err := policy.Read("observe-allow-first.yaml", fixture(t, "fixtures/policy/observe-allow-first.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(l.Policy.Egress.AllowFirst, []string{"api.example", "10.0.0.5"}) {
		t.Errorf("observe-allow-first read as %+v", l.Policy.Egress)
	}
	plain, err := policy.Read("observe.yaml", fixture(t, "fixtures/policy/observe.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Policy.Egress.AllowFirst != nil {
		t.Errorf("observe.yaml read with an allow_first list %v", plain.Policy.Egress.AllowFirst)
	}
	for _, name := range []string{"fixtures/invalid/policy-allow-first-pattern.yaml", "fixtures/invalid/policy-allow-first-too-many.yaml"} {
		var pe *policy.Error
		if _, err := policy.Read(name, fixture(t, name)); !errors.As(err, &pe) {
			t.Errorf("%s: %v, want a *policy.Error", name, err)
		}
	}
	many := func(n int) string {
		entries := make([]string, n)
		for i := range entries {
			entries[i] = fmt.Sprintf("%q", fmt.Sprintf("host-%d.example", i))
		}
		return `{"version":1,"egress":{"mode":"enforce","allow_first":[` + strings.Join(entries, ",") + `]}}`
	}
	for _, doc := range []string{
		`{"version":1,"egress":{"mode":"observe","allow_first":["*.example"]}}`,
		`{"version":1,"egress":{"mode":"observe","allow_first":["Api.example"]}}`,
		`{"version":1,"egress":{"mode":"observe","allow_first":["api.example:443"]}}`,
		`{"version":1,"egress":{"mode":"observe","allow_first":["api.example","api.example"]}}`,
		many(65),
	} {
		if _, err := policy.Read("policy", []byte(doc)); err == nil {
			t.Errorf("%.120s was accepted", doc)
		}
	}
	if _, err := policy.Read("policy", []byte(many(64))); err != nil {
		t.Errorf("64 entries: %v", err)
	}
	_, err = policy.Read("policy", []byte(`{"version":1,"egress":{"mode":"observe","allow_first":["127.1"]}}`))
	if want := "egress.allow_first holds 127.1, which is neither a host name nor an IPv4 address in canonical form"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("127.1: %v, want %q", err, want)
	}
}

// TestAllowFirstIsCheckedBeforeDenyAndAllow pins one side's decision, [Egress.Allows]:
// in either mode a host allow_first lists is allowed though a *. deny entry or an exact
// one covers it, and under enforce though allow is empty; a host below an entry is not
// matched, and deny and allow decide it.
func TestAllowFirstIsCheckedBeforeDenyAndAllow(t *testing.T) {
	for _, mode := range []policy.Mode{policy.Observe, policy.Enforce} {
		for _, deny := range [][]string{{"*.example"}, {"api.example"}, nil} {
			e := policy.Egress{Mode: mode, AllowFirst: []string{"api.example"}, Deny: deny}
			if !e.Allows("api.example") || !e.Allows("API.example.") {
				t.Errorf("%s, deny %v: api.example denied", mode, deny)
			}
			below := mode == policy.Observe && !slices.Contains(deny, "*.example")
			if e.Allows("x.api.example") != below {
				t.Errorf("%s, deny %v: x.api.example allowed %v, want %v", mode, deny, !below, below)
			}
			if mode == policy.Enforce && e.Allows("other.example") {
				t.Errorf("enforce, deny %v: other.example allowed with an empty allow", deny)
			}
		}
	}
	if rule, ok := policy.Exact([]string{"api.example"}, "x.api.example"); ok {
		t.Errorf("Exact matched a host below the entry: %q", rule)
	}
}

// TestNarrowedAllowFirstLiftsOnlyItsSide pins the allow_first row of a node's narrowing:
// an entry of one side lifts that side's deny and allow alone, so the run's list is each
// side's entries the other side allows, the server's first, each once. A node's deny,
// exact or *., still denies a server's entry, and under the node's enforce the node's
// allow must cover it; a server's deny still denies a node's entry.
func TestNarrowedAllowFirstLiftsOnlyItsSide(t *testing.T) {
	server := `{"version":1,"egress":{"mode":"observe","allow_first":["api.example","b.example"],"deny":["*.example"]}}`
	for _, c := range []struct {
		name, server, node string
		want               []string
		allowed, denied    []string
	}{
		{"a node that observes", server, `{"version":1,"egress":{"mode":"observe"}}`,
			[]string{"api.example", "b.example"}, []string{"api.example", "b.example"}, []string{"x.api.example", "c.example"}},
		{"a node's exact deny", server, `{"version":1,"egress":{"mode":"observe","deny":["api.example"]}}`,
			[]string{"b.example"}, []string{"b.example"}, []string{"api.example"}},
		{"a node's *. deny", server, `{"version":1,"egress":{"mode":"observe","deny":["*.example"]}}`,
			nil, nil, []string{"api.example", "b.example"}},
		{"a node that enforces and covers one", server, `{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`,
			[]string{"api.example"}, []string{"api.example"}, []string{"b.example"}},
		{"a node that enforces with a *. entry", server, `{"version":1,"egress":{"mode":"enforce","allow":["*.example"]}}`,
			[]string{"api.example", "b.example"}, []string{"api.example", "b.example"}, []string{"c.example"}},
		{"a node's entry under a server's deny", `{"version":1,"egress":{"mode":"observe","deny":["*.example"]}}`, `{"version":1,"egress":{"mode":"observe","allow_first":["api.example"]}}`,
			nil, nil, []string{"api.example"}},
		{"a node's entry the server allows", `{"version":1,"egress":{"mode":"enforce","allow":["*.example"],"deny":["api.example"]}}`, `{"version":1,"egress":{"mode":"observe","allow_first":["api.example","b.example"],"deny":["b.example"]}}`,
			[]string{"b.example"}, []string{"b.example"}, []string{"api.example"}},
		{"an entry both list", server, `{"version":1,"egress":{"mode":"enforce","allow_first":["b.example"]}}`,
			[]string{"b.example"}, []string{"b.example"}, []string{"api.example"}},
	} {
		l := narrowed(t, c.server, c.node)
		if !slices.Equal(l.Policy.Egress.AllowFirst, c.want) {
			t.Errorf("%s: allow_first %q, want %q", c.name, l.Policy.Egress.AllowFirst, c.want)
		}
		for _, h := range c.allowed {
			if !l.Policy.Egress.Allows(h) {
				t.Errorf("%s: %s denied", c.name, h)
			}
		}
		for _, h := range c.denied {
			if l.Policy.Egress.Allows(h) {
				t.Errorf("%s: %s allowed", c.name, h)
			}
		}
	}
}
