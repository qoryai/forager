package run_test

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/refusal"
)

// harnessDoc is a run configuration with a work credential, work-1, and a harness
// credential, harness-1, on one host, git.example, which its stack_hosts lists: the
// run's policy allows git.example for work-1, and harness-1 is held to the harness's
// repository.
const harnessDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["git.example"]}},` +
	`"stack_hosts":["git.example"],"credentials":[` +
	`{"name":"work-1","purpose":"work","apply":[{"hosts":["git.example"],"scheme":"basic","username":"x-access-token"}],"placeholders":["GIT_TOKEN"]},` +
	`{"name":"harness-1","purpose":"harness","apply":[{"hosts":["git.example"],"scheme":"basic","username":"x-access-token","paths":["/example-org/harness.git/*"]}]}]}`

// harnessValue is the fake value the server opens for each credential name.
func harnessValue(name string, _ int) (answer, error) { return answer{value: "value-of-" + name}, nil }

// stackValue is the value the stack proxy sets for the credential name now, "(none)"
// when it sets none.
func stackValue(r *run.Run, name string) string {
	for _, u := range r.StackUses() {
		if u.Name == name && u.Value != nil {
			if v := u.Value(); len(v) > 0 {
				return string(v)
			}
		}
	}
	return "(none)"
}

// TestAHarnessCredentialIsTheStackProxysAlone pins the split of a run configuration's
// credentials: one secrets request opens both, in the document's order; the run's
// proxy, which the session, the host proxy and the setup step go through, sets work-1
// alone, and the run's placeholders are work-1's; the stack proxy sets harness-1 alone,
// on its item, though both are on git.example; CloseHarness clears harness-1's value and
// leaves work-1's.
func TestAHarnessCredentialIsTheStackProxysAlone(t *testing.T) {
	s := &controlPlane{answer: harnessValue}
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, harnessDoc, digest('1')), Secrets: s.fetch})
	if got := s.called(); len(got) != 1 || !slices.Equal(got[0], []string{digest('c'), "work-1", "harness-1"}) {
		t.Fatalf("the secrets requests %v, want one for work-1 and harness-1", got)
	}
	var names []string
	for _, u := range r.Uses() {
		names = append(names, u.Name)
	}
	if !slices.Equal(names, []string{"work-1"}) || value(r, "work-1") != "value-of-work-1" {
		t.Errorf("the run's proxy sets %v with %s; want work-1 alone", names, value(r, "work-1"))
	}
	if got := r.CredentialPlaceholders(); !slices.Equal(got, []string{"GIT_TOKEN"}) {
		t.Errorf("the run's placeholders %v, want work-1's", got)
	}
	uses := r.StackUses()
	if len(uses) != 1 || uses[0].Name != "harness-1" || !slices.Equal(uses[0].Hosts, []string{"git.example"}) || uses[0].Scheme != "basic" ||
		uses[0].Username != "x-access-token" || !slices.Equal(uses[0].Paths, []string{"/example-org/harness.git/*"}) || !uses[0].Stored || uses[0].Rejected != nil {
		t.Fatalf("the stack proxy's credentials %+v; want harness-1 on its item, with no renewal", uses)
	}
	if stackValue(r, "harness-1") != "value-of-harness-1" || !r.NeedsCA() || r.HarnessHidden() {
		t.Errorf("the stack proxy sets %s, NeedsCA %v, hidden %v", stackValue(r, "harness-1"), r.NeedsCA(), r.HarnessHidden())
	}
	r.CloseHarness()
	if stackValue(r, "harness-1") != "(none)" || value(r, "work-1") != "value-of-work-1" {
		t.Errorf("after CloseHarness, the stack proxy sets %s and the run's proxy %s; want none and work-1's", stackValue(r, "harness-1"), value(r, "work-1"))
	}
}

// TestHarnessHiddenIsTheStartsDocuments pins HarnessHidden: true for a run
// configuration with harness_hidden true, false without it.
func TestHarnessHiddenIsTheStartsDocuments(t *testing.T) {
	hidden := strings.Replace(harnessDoc, `{"version":1,`, `{"version":1,"harness_hidden":true,`, 1)
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, hidden, digest('1')), Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if !r.HarnessHidden() {
		t.Error("HarnessHidden is false for harness_hidden true")
	}
}

// TestAHarnessCredentialTheStackProxyCannotSetIsRefused pins Decide's check of the
// harness credentials, each run_configuration_invalid with the fix first and the
// credentials' names: placeholders, a host in neither stack_hosts list, a host of the
// run configuration's list that the node's policy does not allow or has path rules for,
// and two harness credentials on one host, one without paths or with paths that
// overlap. A host of gateway.stack_hosts alone passes, as do two harness credentials on
// one host with paths apart; nothing is fetched for a refused one.
func TestAHarnessCredentialTheStackProxyCannotSetIsRefused(t *testing.T) {
	entry := func(name, host, paths, more string) string {
		e := `{"name":"` + name + `","purpose":"harness","apply":[{"hosts":["` + host + `"],"scheme":"bearer"`
		if paths != "" {
			e += `,"paths":[` + paths + `]`
		}
		return e + `}]` + more + `}`
	}
	doc := func(stack string, entries ...string) string {
		d := `{"version":1`
		if stack != "" {
			d += `,"stack_hosts":[` + stack + `]`
		}
		return d + `,"credentials":[` + strings.Join(entries, ",") + `]}`
	}
	allow := func(hosts ...string) *run.Policy {
		return &run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: hosts}}
	}
	for _, c := range []struct {
		name  string
		doc   string
		node  *run.Policy
		yaml  []string
		want  string
		names []string
	}{
		{"placeholders", doc(`"git.example"`, entry("harness-1", "git.example", "", `,"placeholders":["HARNESS_TOKEN"]`)), nil, nil,
			`Remove placeholders from the harness credential "harness-1": no session gets it`, []string{"harness-1"}},
		{"a host in neither list", doc(`"api.git.example"`, entry("harness-1", "git.example", "", "")), nil, []string{"other.example"},
			`Add git.example to a stack_hosts list: the harness credential "harness-1" is for it`, []string{"harness-1"}},
		{"a host the node's policy does not allow", doc(`"git.example"`, entry("harness-1", "git.example", "", "")), allow("api.example"), nil,
			`Allow git.example in the node's policy: the harness credential "harness-1" is for it`, []string{"harness-1"}},
		{"a host the node's policy has path rules for", doc(`"git.example"`, entry("harness-1", "git.example", "", "")),
			&run.Policy{Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"git.example"}, Paths: map[string][]string{"git.example": {"/example-org/*"}}}}, nil,
			`List git.example in gateway.stack_hosts: node path rules cover the harness credential "harness-1"`, []string{"harness-1"}},
		{"two on one host, one without paths", doc(`"git.example"`, entry("harness-1", "git.example", `"/example-org/a.git/*"`, ""), entry("harness-2", "git.example", "", "")), nil, nil,
			`Claim git.example in only one of the harness credentials harness-1 and harness-2: one has no paths`, []string{"harness-1", "harness-2"}},
		{"two on one host whose paths overlap", doc(`"git.example"`, entry("harness-1", "git.example", `"/example-org/*"`, ""), entry("harness-2", "git.example", `"/example-org/a.git/*"`, "")), nil, nil,
			`Give the harness credentials harness-1 and harness-2 paths that do not overlap on git.example`, []string{"harness-1", "harness-2"}},
		{"a host of gateway.stack_hosts alone", doc("", entry("harness-1", "git.example", "", "")), allow("api.example"), []string{"*.example"}, "", nil},
		{"two on one host with paths apart", doc(`"git.example"`, entry("harness-1", "git.example", `"/example-org/a.git/*"`, ""), entry("harness-2", "git.example", `"/example-org/b.git/*"`, "")), nil, nil, "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &controlPlane{answer: harnessValue}
			r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Node: c.node, StackHosts: c.yaml,
				Fetched: computed(t, c.doc, digest('1')), Secrets: s.fetch})
			if c.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				r.Close()
				return
			}
			code, names := refusalOf(err)
			var ref *accesskey.Refusal
			if r != nil || code != refusal.RunConfigurationInvalid || !slices.Equal(names, c.names) || !errors.As(err, &ref) || ref.Detail != c.want {
				t.Fatalf("Open: %v, %s %v; want %q with %v", err, code, names, c.want, c.names)
			}
			if len(c.want) > 100 {
				t.Errorf("the refusal's first line is %d characters, over 100", len(c.want))
			}
			if got := s.called(); len(got) != 0 {
				t.Errorf("the secrets requests %v; want none", got)
			}
		})
	}
}

// TestCloseHarnessStopsItsRenewals pins the renewals of a harness credential: before
// CloseHarness its value is renewed as a work credential's; after it, the renewer asks
// for the work credential alone, and a renewal of the harness credential that was in
// flight puts no value back.
func TestCloseHarnessStopsItsRenewals(t *testing.T) {
	expiring := func(name string, call int) (answer, error) {
		return answer{value: name + "-" + string(rune('0'+call)), expires: start.Add(time.Hour + time.Duration(call)*time.Hour)}, nil
	}
	c := &fakeClock{now: start}
	s := &controlPlane{answer: expiring}
	r := renewRun(t, harnessDoc, s, c, &reports{}, nil)
	if uses := r.StackUses(); len(uses) != 1 || uses[0].Rejected == nil {
		t.Fatalf("the stack proxy's credentials %+v; want harness-1 with a renewal on a 401", uses)
	}
	c.step(t, time.Hour-credential.RenewBefore)
	if got := s.called(); len(got) != 2 || !slices.Equal(got[1], []string{digest('c'), "work-1", "harness-1"}) || stackValue(r, "harness-1") != "harness-1-1" {
		t.Fatalf("the first renewal: calls %v, harness-1 %s", got, stackValue(r, "harness-1"))
	}
	r.CloseHarness()
	c.step(t, time.Hour)
	if got := s.called(); len(got) != 3 || !slices.Equal(got[2], []string{digest('c'), "work-1"}) {
		t.Errorf("after CloseHarness: calls %v; want work-1 alone", got)
	}
	if stackValue(r, "harness-1") != "(none)" || value(r, "work-1") != "work-1-2" {
		t.Errorf("after CloseHarness: harness-1 %s, work-1 %s", stackValue(r, "harness-1"), value(r, "work-1"))
	}
}

// TestARenewalInFlightPutsNoHarnessValueBack pins CloseHarness during a renewal: the
// request that was sent before it returns harness-1's value, which the run drops.
func TestARenewalInFlightPutsNoHarnessValueBack(t *testing.T) {
	c := &fakeClock{now: start}
	release := make(chan struct{})
	closed := make(chan struct{})
	s := &controlPlane{answer: func(name string, call int) (answer, error) {
		if call == 1 && name == "harness-1" {
			close(release)
			<-closed
		}
		return answer{value: name + "-" + string(rune('0'+call)), expires: start.Add(time.Hour + time.Duration(call)*time.Hour)}, nil
	}}
	r := renewRun(t, strings.Replace(harnessDoc, `,"placeholders":["GIT_TOKEN"]`, "", 1), s, c, &reports{}, nil)
	n := c.count()
	c.advance(time.Hour - credential.RenewBefore)
	<-release
	r.CloseHarness()
	close(closed)
	c.idle(t, n)
	if stackValue(r, "harness-1") != "(none)" || value(r, "work-1") != "work-1-1" {
		t.Errorf("after the renewal in flight: harness-1 %s, work-1 %s; want none and work-1-1", stackValue(r, "harness-1"), value(r, "work-1"))
	}
}

// TestTheHarnessPlaceholdersFixtureIsRefused pins the contract's fixture of a harness
// credential with placeholders, which run-configuration.schema.json accepts: the run
// is refused, run_configuration_invalid.
func TestTheHarnessPlaceholdersFixtureIsRefused(t *testing.T) {
	b, err := fs.ReadFile(contracts.FS, "fixtures/invalid/run-configuration-beyond-schema-credentials-harness-placeholders.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, string(b), digest('1')),
		Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if code, names := refusalOf(err); code != refusal.RunConfigurationInvalid || !slices.Equal(names, []string{"harness-1"}) ||
		!strings.HasPrefix(err.Error(), "Remove placeholders from the harness credential") {
		t.Errorf("Open: %v; want the placeholders refused", err)
	}
}
