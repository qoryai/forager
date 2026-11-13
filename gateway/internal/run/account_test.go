package run_test

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/modelkey"
	"github.com/qoryai/forager/gateway/internal/run"
)

// fakeToken is a JWT of three parts with payload, base64url, and no real signature: a
// fake value for a subscription key.
func fakeToken(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(payload)) + ".fake-signature"
}

// accountOf is a fake token whose payload has the account id id at accountDoc's
// account_claim.
func accountOf(id string) string {
	return fakeToken(`{"https://auth.model.example/auth":{"account_id":"` + id + `"}}`)
}

// accountDoc is the configuration of the 521 probe's fix 2 in a run configuration: two
// subscription keys of one group on chat.model.example with paths and an account
// header, a host credential, files, on other paths of that host, and an API key on
// another host, under a policy that allows both hosts.
const accountDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["chat.model.example","api.model.example"]}},"model_credential":"subscription","credentials":[` +
	`{"name":"subscription","format":"openai-responses","endpoint":"https://chat.model.example/backend-api/codex","auth":{"scheme":"bearer","oauth":true,"account_header":"chatgpt-account-id","account_claim":"/https:~1~1auth.model.example~1auth/account_id"},"paths":["/backend-api/codex/*"],"pause_for_s":18000},` +
	`{"name":"subscription-2","format":"openai-responses","endpoint":"https://chat.model.example/backend-api/codex","auth":{"scheme":"bearer","oauth":true,"account_header":"chatgpt-account-id","account_claim":"/https:~1~1auth.model.example~1auth/account_id"},"paths":["/backend-api/codex/*"],"pause_for_s":18000},` +
	`{"name":"api-key","format":"openai-responses","endpoint":"https://api.model.example/v1","auth":{"scheme":"bearer"},"paths":["/v1/responses","/v1/responses/*"]},` +
	`{"name":"files","apply":[{"hosts":["chat.model.example"],"scheme":"bearer","paths":["/backend-api/files/*"]}],"placeholders":["FILES_TOKEN"]}]}`

// accountValues answers each subscription with a token of its account id, and every
// other credential with a fake value of its name; values replaces the answer of a name.
func accountValues(values map[string]string) func(string, int) (answer, error) {
	return func(name string, _ int) (answer, error) {
		if v, ok := values[name]; ok {
			return answer{value: v}, nil
		}
		if strings.HasPrefix(name, "subscription") {
			return answer{value: accountOf("acct-fake-" + name)}, nil
		}
		return answer{value: "value-of-" + name}, nil
	}
}

// TestAPathLimitedSubscriptionSitsBesideAHostCredential pins the 521 probe's fix 2: a
// subscription key with paths opens beside a host credential with other paths of its
// host. Each use has its paths, the subscription its account header and the account
// id of its value, and both subscriptions are the key group. With the host
// credential's paths gone, or overlapping the key's, or the key's paths gone, the run is
// refused as before.
func TestAPathLimitedSubscriptionSitsBesideAHostCredential(t *testing.T) {
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, accountDoc, digest('1')),
		Secrets: (&controlPlane{answer: accountValues(nil)}).fetch})
	if got := r.Held().Group; !slices.Equal(got, []string{"subscription", "subscription-2"}) {
		t.Errorf("Group %v; want the two subscriptions", got)
	}
	if out := r.KeysOut(); len(out) != 0 {
		t.Errorf("KeysOut %v; want none", out)
	}
	paths := map[string][]string{}
	for _, u := range r.Uses() {
		paths[u.Name] = u.Paths
		switch {
		case strings.HasPrefix(u.Name, "subscription"):
			if u.AccountHeader != "chatgpt-account-id" || u.Account == nil {
				t.Errorf("%s: account header %q", u.Name, u.AccountHeader)
				continue
			}
			if id, err := u.Account(u.Value()); err != nil || id != "acct-fake-"+u.Name {
				t.Errorf("%s: the account id %q, %v", u.Name, id, err)
			}
		case u.AccountHeader != "" || u.Account != nil:
			t.Errorf("%s has an account header %q", u.Name, u.AccountHeader)
		}
	}
	want := map[string][]string{"subscription": {"/backend-api/codex/*"}, "subscription-2": {"/backend-api/codex/*"},
		"api-key": {"/v1/responses", "/v1/responses/*"}, "files": {"/backend-api/files/*"}}
	for name, p := range want {
		if !slices.Equal(paths[name], p) {
			t.Errorf("%s: paths %v; want %v", name, paths[name], p)
		}
	}
	for name, c := range map[string]struct{ doc, want string }{
		"the host credential without paths": {strings.Replace(accountDoc, `,"paths":["/backend-api/files/*"]`, ``, 1),
			"a credential without paths is alone on its hosts"},
		"overlapping paths": {strings.Replace(accountDoc, `"/backend-api/files/*"`, `"/backend-api/*"`, 1),
			"give the credentials subscription and files paths that do not overlap"},
		"the key without paths": {strings.Replace(accountDoc, `,"paths":["/backend-api/codex/*"],"pause_for_s":18000},{"name":"subscription-2"`, `,"pause_for_s":18000},{"name":"subscription-2"`, 1),
			"a credential without paths is alone on its hosts"},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := run.Open(t.Context(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, c.doc, digest('1')),
				Secrets: (&controlPlane{answer: accountValues(nil)}).fetch})
			if err == nil {
				r.Close()
				t.Fatal("the run opened")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v; want %q", err, c.want)
			}
		})
	}
}

// TestAValueWithoutItsClaimLeavesTheGroup pins a key whose value has no account claim
// when the run opens: the run opens, KeysOut has the key, the run's record has one
// line that starts with the fix and contains neither the token nor an account id, and
// the group made with KeysOut sets the other key. With no key of the group left, the
// run is refused, run_configuration_invalid.
func TestAValueWithoutItsClaimLeavesTheGroup(t *testing.T) {
	over := `{"https://auth.model.example/auth":{"account_id":"acct-fake-over"},"pad":"` + strings.Repeat("p", credential.MaxClaimPayload) + `"}`
	for name, c := range map[string]struct{ value, cause string }{
		"no claim":       {fakeToken(`{"https://auth.model.example/auth":{"org_id":"org-fake"}}`), "its JWT payload has no string at account_claim"},
		"over 8 KiB":     {fakeToken(over), "its JWT payload is over 8192 bytes"},
		"no JWT":         {"opaque-fake-token", "the value is no JWT"},
		"a broken token": {"e30.not*base64.sig", "its JWT payload is not base64url"},
	} {
		t.Run(name, func(t *testing.T) {
			log := &reports{}
			r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, accountDoc, digest('1')), Log: log.report,
				Secrets: (&controlPlane{answer: accountValues(map[string]string{"subscription": c.value})}).fetch})
			if out := r.KeysOut(); !slices.Equal(out, []string{"subscription"}) {
				t.Errorf("KeysOut %v; want subscription", out)
			}
			lines := log.lines()
			if len(lines) != 1 || !strings.HasPrefix(lines[0], `Store in the control plane a value of the model key "subscription" with a string at its account_claim; the run does not set the key: `+c.cause) {
				t.Fatalf("the record's lines %q", lines)
			}
			if strings.Contains(lines[0], c.value) || strings.Contains(lines[0], "acct-fake") || strings.Contains(lines[0], "org-fake") {
				t.Errorf("the line contains the token or a claim: %s", lines[0])
			}
			g := modelkey.New(r.ModelKeys(), r.Held().Start, nil)
			for _, name := range r.KeysOut() {
				g.Out(name)
			}
			if active, ok := g.Pick(); active != "subscription-2" || !ok {
				t.Errorf("the group's active key %s, %v; want subscription-2", active, ok)
			}
		})
	}
	t.Run("no key left", func(t *testing.T) {
		none := fakeToken(`{"sub":"fake"}`)
		r, err := run.Open(t.Context(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, accountDoc, digest('1')),
			Secrets: (&controlPlane{answer: accountValues(map[string]string{"subscription": none, "subscription-2": none})}).fetch})
		if err == nil {
			r.Close()
			t.Fatal("the run opened")
		}
		if code, names := refusalOf(err); code != "run_configuration_invalid" || !slices.Equal(names, []string{"subscription"}) ||
			!strings.Contains(err.Error(), `store in the control plane a value of a model key of the key group of "subscription" with a string at its account_claim: no key of the group has one`) {
			t.Errorf("%v (%s %v)", err, code, names)
		}
	})
}

// TestARenewalWithoutTheClaimKeepsTheValue pins a renewal of a subscription key whose
// renewed value has no account claim: the renewal is refused as one with another
// apply is, the report has why and no value, and the run keeps the value it had.
func TestARenewalWithoutTheClaimKeepsTheValue(t *testing.T) {
	clock := &fakeClock{now: start}
	first, renewed := accountOf("acct-fake-first"), fakeToken(`{"sub":"fake"}`)
	s := &controlPlane{answer: func(name string, call int) (answer, error) {
		switch {
		case name == "subscription" && call == 0:
			return answer{value: first, expires: start.Add(time.Hour)}, nil
		case name == "subscription":
			return answer{value: renewed, expires: start.Add(2 * time.Hour)}, nil
		}
		return accountValues(nil)(name, call)
	}}
	rep := &reports{}
	r := renewRun(t, accountDoc, s, clock, rep, nil)
	clock.step(t, time.Hour-credential.RenewBefore)
	want := `run ` + runID + `: If this repeats, check the control plane: credential "subscription" was not renewed: its JWT payload has no string at account_claim "/https:~1~1auth.model.example~1auth/account_id"`
	if value(r, "subscription") != first || !rep.reported(want) {
		t.Fatalf("after the renewal: the value is the first %v, reports %q", value(r, "subscription") == first, rep.lines())
	}
	for _, l := range rep.lines() {
		if strings.Contains(l, renewed) || strings.Contains(l, first) {
			t.Errorf("a report contains a value: %s", l)
		}
	}
}
