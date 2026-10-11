package proxy

import (
	"testing"

	"github.com/qoryai/forager/policy"
)

// decidePath is how the terminator decides one request's path, under the proxy's mode.
func decidePath(t *testing.T, p *Proxy, host, path string) (rule string, allowed bool) {
	t.Helper()
	_, rule, allowed, _ = p.term.Load().path(host, path)
	return rule, allowed
}

// TestTheMostSpecificEntryHoldsAHost pins the terminator's choice of a side's path
// rules when several of its entries match a host: the host's name itself before any
// "*." entry, and of "*." entries the one with the longest suffix, on every request,
// whatever order a map is read in, of the policy's side and of the node's alike. An
// entry with an empty list holds its host to no path.
func TestTheMostSpecificEntryHoldsAHost(t *testing.T) {
	overlapping := map[string][]string{
		"example":        {"/apex/*"},
		"*.example":      {"/v1/*"},
		"api.example":    {"/v2/*"},
		"*.api.example":  {"/v3/*"},
		"closed.example": {},
	}
	cases := []struct {
		host, path, rule string
		allowed          bool
	}{
		{"api.example", "/v2/x", "/v2/*", true},
		{"api.example", "/v1/x", "", false},
		{"api.example", "/v3/x", "", false},
		{"example", "/apex/x", "/apex/*", true},
		{"example", "/v1/x", "", false},
		{"other.example", "/v1/x", "/v1/*", true},
		{"other.example", "/v2/x", "", false},
		{"a.api.example", "/v3/x", "/v3/*", true},
		{"a.api.example", "/v1/x", "", false},
		{"a.api.example", "/v2/x", "", false},
		{"closed.example", "/", "", false},
		{"closed.example", "/v1/x", "", false},
	}
	for _, mode := range []policy.Mode{policy.Enforce, policy.Observe} {
		for _, side := range []string{"policy", "node"} {
			p, err := New(mode, []string{"*.example", "example"}, nil, func(Decision) {})
			if err != nil {
				t.Fatal(err)
			}
			if side == "node" {
				p.NodePaths(overlapping)
				p.Terminate(nil, nil, nil, nil)
			} else {
				p.Terminate(nil, nil, overlapping, nil)
			}
			for range 200 {
				for _, c := range cases {
					rule, allowed := decidePath(t, p, c.host, c.path)
					want := c.allowed || mode == policy.Observe
					if rule != c.rule || allowed != want {
						t.Fatalf("%s, %s side: %s%s is %v with the rule %q, want %v with %q", mode, side, c.host, c.path, allowed, rule, want, c.rule)
					}
				}
			}
		}
	}
}
