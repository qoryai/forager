package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/qoryai/forager/policy"
)

// TestAnAllowFirstHostIsReachedBeforeDenyAndAllow pins the allow_first list in the
// proxy: in either mode a host an entry matches exactly is reached, through a tunnel and
// by a plain request, though a *. deny entry or an exact one covers it, and under
// enforce with an empty allow list, recorded as allowed with the entry as its rule. A
// host below the entry is decided by deny and allow as before.
func TestAnAllowFirstHostIsReachedBeforeDenyAndAllow(t *testing.T) {
	for _, mode := range []policy.Mode{policy.Observe, policy.Enforce} {
		for _, deny := range [][]string{{"*.example"}, {"api.example"}, nil} {
			p, rec, seen := formProxy(t, mode, nil, deny)
			p.AllowFirst([]string{"api.example"})
			for _, line := range []string{"CONNECT api.example:443", "GET http://api.example/x"} {
				code, body := askBody(t, p, line)
				d := seen.at(-1)
				got := rec.take()
				if code != 200 || (line[0] == 'G' && body != "origin") || !d.Allowed || d.Rule != "api.example" || d.Outcome != Connected || len(got) != 1 {
					t.Errorf("%s, deny %v, %s: %d %q, decision %+v, dialled %v; want it reached by the allow_first entry", mode, deny, line, code, body, d, got)
				}
			}
			// A host below the entry is not matched.
			code, _ := askBody(t, p, "GET http://x.api.example/x")
			d := seen.at(-1)
			switch {
			case len(deny) == 1 && deny[0] == "*.example":
				if code != 403 || d.Rule != "*.example" || d.Allowed {
					t.Errorf("%s, deny %v: x.api.example %d, decision %+v; want the deny entry's 403", mode, deny, code, d)
				}
			case mode == policy.Enforce:
				if code != 403 || d.Rule != "" || d.Allowed {
					t.Errorf("%s, deny %v: x.api.example %d, decision %+v; want the policy's 403", mode, deny, code, d)
				}
			default:
				if code != 200 || d.Rule != "" || !d.Allowed {
					t.Errorf("%s, deny %v: x.api.example %d, decision %+v; want it reached", mode, deny, code, d)
				}
			}
			rec.take()
			p.Close()
		}
	}
}

// TestAReloadCarriesTheAllowFirstList pins that SetPolicyOpening replaces the
// allow_first list with the rest of the policy, and SetPolicy leaves none.
func TestAReloadCarriesTheAllowFirstList(t *testing.T) {
	p, _, seen := formProxy(t, policy.Observe, nil, []string{"*.example"})
	if code := ask(t, p, "GET http://api.example/x"); code != 403 {
		t.Errorf("before the reload: %d, want 403", code)
	}
	p.SetPolicyOpening(policy.Enforce, []string{"api.example"}, nil, []string{"*.example"}, nil, nil, nil)
	if code := ask(t, p, "GET http://api.example/x"); code != 200 || seen.at(-1).Rule != "api.example" || seen.at(-1).Mode != policy.Enforce {
		t.Errorf("after a reload with allow_first: %d, decision %+v", code, seen.at(-1))
	}
	p.SetPolicy(policy.Observe, nil, []string{"*.example"}, nil, nil)
	if code := ask(t, p, "GET http://api.example/x"); code != 403 || seen.at(-1).Rule != "*.example" {
		t.Errorf("after a reload without it: %d, decision %+v", code, seen.at(-1))
	}
}

// TestAllowFirstOpensNoPrivateAddressWithoutAGuardName pins that behind a wall an
// allow_first entry for a private network address, or for a name that resolves to one,
// does not open it: the guard refuses it unless one of its names is the host.
func TestAllowFirstOpensNoPrivateAddressWithoutAGuardName(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	file := &hostsEntries{names: map[string][]netip.Addr{"nas": {netip.MustParseAddr("192.168.1.20")}}}
	for _, host := range []string{"10.1.2.3", "nas"} {
		for _, open := range [][]string{nil, {host}} {
			seen := &decisions{}
			p, err := Listen("", policy.Enforce, nil, []string{"*.example"}, seen.observe)
			if err != nil {
				t.Fatal(err)
			}
			rec := &resolvingDial{origin: origin.Listener.Addr().String()}
			p.dial = rec.dialler(p)
			p.hosts = file.lookup
			p.AllowFirst([]string{host})
			p.Guard(open)
			code, body := raw(t, p, "GET http://"+host+"/x", host)
			d := seen.at(-1)
			got := rec.take()
			p.Close()
			if open == nil {
				if code != 403 || d.Rule != GuardRule || len(got) != 0 {
					t.Errorf("%s with no guard name: %d %q, decision %+v, connected %v; want the wall's refusal", host, code, body, d, got)
				}
			} else if code != 200 || body != "origin" || d.Rule != host || len(got) != 1 {
				t.Errorf("%s with a guard name: %d %q, decision %+v, connected %v; want it reached", host, code, body, d, got)
			}
		}
	}
}
