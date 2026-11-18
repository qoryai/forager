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

// pushDoc is a run configuration of a write run: a read work credential, work-1, on the
// repository's paths of git.example, and a push credential, push-1, whose one item is
// for the same paths with the branch guard's ref.
const pushDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["git.example"]}},"credentials":[` +
	`{"name":"work-1","apply":[{"hosts":["git.example"],"scheme":"basic","username":"x-access-token","paths":["/example-org/app.git/*"]}],"placeholders":["GIT_TOKEN"]},` +
	`{"name":"push-1","purpose":"push","apply":[{"hosts":["git.example"],"scheme":"basic","username":"x-access-token","paths":["/example-org/app.git/*"],"push_ref":"refs/heads/qory/wi_01"}]}]}`

// pushValueOf is the value the push proxy sets for the credential name now, "(none)"
// when it sets none.
func pushValueOf(r *run.Run, name string) string {
	for _, u := range r.PushUses() {
		if u.Name == name && u.Value != nil {
			if v := u.Value(); len(v) > 0 {
				return string(v)
			}
		}
	}
	return "(none)"
}

// TestAPushCredentialIsThePushProxysAlone pins the split of a write run's credentials:
// one secrets request opens both; the run's proxy, which the sessions, the setup step,
// After, the image step and the host proxy go through, sets work-1 alone, though push-1
// is for the same paths, and the run's placeholders are work-1's; the push proxy sets
// push-1 alone, on its item, with the branch guard's ref; the run needs its authority.
func TestAPushCredentialIsThePushProxysAlone(t *testing.T) {
	s := &controlPlane{answer: harnessValue}
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, pushDoc, digest('1')), Secrets: s.fetch})
	if got := s.called(); len(got) != 1 || !slices.Equal(got[0], []string{digest('c'), "work-1", "push-1"}) {
		t.Fatalf("the secrets requests %v, want one for work-1 and push-1", got)
	}
	var names []string
	for _, u := range r.Uses() {
		names = append(names, u.Name)
	}
	if !slices.Equal(names, []string{"work-1"}) || value(r, "work-1") != "value-of-work-1" || value(r, "push-1") != "(none)" {
		t.Errorf("the run's proxy sets %v with %s, push-1 %s; want work-1 alone", names, value(r, "work-1"), value(r, "push-1"))
	}
	if got := r.CredentialPlaceholders(); !slices.Equal(got, []string{"GIT_TOKEN"}) {
		t.Errorf("the run's placeholders %v, want work-1's", got)
	}
	uses := r.PushUses()
	if len(uses) != 1 || uses[0].Name != "push-1" || !slices.Equal(uses[0].Hosts, []string{"git.example"}) ||
		!slices.Equal(uses[0].Paths, []string{"/example-org/app.git/*"}) || uses[0].PushRef != "refs/heads/qory/wi_01" || !uses[0].Stored {
		t.Fatalf("the push proxy's credentials %+v; want push-1 on its item", uses)
	}
	if pushValueOf(r, "push-1") != "value-of-push-1" || !r.HasPush() || !r.NeedsCA() || len(r.StackUses()) != 0 {
		t.Errorf("the push proxy sets %s, HasPush %v, NeedsCA %v, stack %v", pushValueOf(r, "push-1"), r.HasPush(), r.NeedsCA(), r.StackUses())
	}
}

// TestARunWithoutAPushCredentialHasNoPush pins the shape of a write-no-push run, a read
// work credential alone: HasPush is false and the push proxy sets nothing.
func TestARunWithoutAPushCredentialHasNoPush(t *testing.T) {
	doc := `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["git.example"]}},"credentials":[` +
		`{"name":"work-1","apply":[{"hosts":["git.example"],"scheme":"basic","username":"x-access-token"}]}]}`
	s := &controlPlane{answer: harnessValue}
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')), Secrets: s.fetch})
	if r.HasPush() || r.PushUses() != nil {
		t.Errorf("HasPush %v, the push proxy's credentials %+v; want none", r.HasPush(), r.PushUses())
	}
	if got := s.called(); len(got) != 1 || !slices.Equal(got[0], []string{digest('c'), "work-1"}) {
		t.Errorf("the secrets requests %v, want work-1 alone", got)
	}
}

// TestAPushCredentialThePushProxyCannotSetIsRefused pins Decide's and the hold's checks
// of the push credentials, each run_configuration_invalid with a first line of fixed
// text within 100 characters and the credentials' names: placeholders, two items on one
// host with one of them without paths or with paths that overlap, of one credential or
// of two, a host the run's enforce allow list does not cover, a host a deny list of the
// run's or of the node's covers, and a host a path rule of the node's covers. Two push credentials
// on one host with paths apart pass, and so does any host under observe; nothing is
// fetched for a refused one.
func TestAPushCredentialThePushProxyCannotSetIsRefused(t *testing.T) {
	entry := func(name, host, paths, more string) string {
		e := `{"name":"` + name + `","purpose":"push","apply":[{"hosts":["` + host + `"],"scheme":"bearer"`
		if paths != "" {
			e += `,"paths":[` + paths + `]`
		}
		return e + `}]` + more + `}`
	}
	doc := func(mode string, entries ...string) string {
		return `{"version":1,"security_policy":{"version":1,"egress":{"mode":"` + mode + `","allow":["git.example"]}},"credentials":[` + strings.Join(entries, ",") + `]}`
	}
	nodes := map[string]*run.Policy{
		"a host the node's deny list covers": {Version: 1, Egress: run.PolicyEgress{Mode: "observe", Deny: []string{"git.example"}}},
		"a host the node's path rules cover": {Version: 1, Egress: run.PolicyEgress{Mode: "enforce", Allow: []string{"git.example"}, Paths: map[string][]string{"git.example": {"/example-org/*"}}}},
	}
	for _, c := range []struct {
		name, doc, want string
		names           []string
	}{
		{"placeholders", doc("enforce", entry("push-1", "git.example", "", `,"placeholders":["PUSH_TOKEN"]`)),
			"Remove placeholders from push credentials: no session gets a push credential.\nThe push credential \"push-1\" has placeholders.", []string{"push-1"}},
		{"two items of one on one host, one without paths", doc("enforce",
			`{"name":"push-1","purpose":"push","apply":[{"hosts":["git.example"],"scheme":"bearer","paths":["/example-org/a.git/*"]},{"hosts":["git.example"],"scheme":"bearer"}]}`),
			"Give paths to every apply item of a push credential on a host that another push item is for.\nThe push credential \"push-1\" is for git.example in two apply items, and one of them has no paths.", []string{"push-1"}},
		{"two items of one on one host whose paths overlap", doc("enforce",
			`{"name":"push-1","purpose":"push","apply":[{"hosts":["git.example"],"scheme":"bearer","paths":["/example-org/*"]},{"hosts":["git.example"],"scheme":"bearer","paths":["/example-org/a.git/*"]}]}`),
			"Change the paths of push credential items on one host so that they do not overlap.\nThe push credential \"push-1\" has apply items with overlapping paths on git.example.", []string{"push-1"}},
		{"two on one host, one without paths", doc("enforce", entry("push-1", "git.example", `"/example-org/a.git/*"`, ""), entry("push-2", "git.example", "", "")),
			"Give paths to every apply item of a push credential on a host that another push item is for.\nThe push credentials \"push-1\" and \"push-2\" are both for git.example, and one of them has no paths.", []string{"push-1", "push-2"}},
		{"two on one host whose paths overlap", doc("enforce", entry("push-1", "git.example", `"/example-org/*"`, ""), entry("push-2", "git.example", `"/example-org/a.git/*"`, "")),
			"Change the paths of push credential items on one host so that they do not overlap.\nThe push credentials \"push-1\" and \"push-2\" have overlapping paths on git.example.", []string{"push-1", "push-2"}},
		{"a host the allow list does not cover", doc("enforce", entry("push-1", "api.git.example", "", "")),
			"Add each push credential's host to the run's egress allow list.\nThe push credential \"push-1\" is for api.git.example, which no allow entry covers.", []string{"push-1"}},
		{"a host the run's deny list covers", strings.Replace(doc("observe", entry("push-1", "api.git.example", "", "")), `"allow":["git.example"]`, `"deny":["*.git.example"]`, 1),
			"Remove each push credential's host from the egress deny lists.\nThe push credential \"push-1\" is for api.git.example, which a deny entry covers.", []string{"push-1"}},
		{"a host the node's deny list covers", doc("enforce", entry("push-1", "git.example", "", "")),
			"Remove each push credential's host from the egress deny lists.\nThe push credential \"push-1\" is for git.example, which a deny entry covers.", []string{"push-1"}},
		{"a host the node's path rules cover", doc("enforce", entry("push-1", "git.example", "", "")),
			"Remove the node's path rules for each push credential's host: the push proxy checks none.\nThe push credential \"push-1\" is for git.example, which a path rule of the node covers.", []string{"push-1"}},
		{"two on one host with paths apart", doc("enforce", entry("push-1", "git.example", `"/example-org/a.git/*"`, ""), entry("push-2", "git.example", `"/example-org/b.git/*"`, "")), "", nil},
		{"a host outside the allow list under observe", doc("observe", entry("push-1", "api.git.example", "", "")), "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &controlPlane{answer: harnessValue}
			r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Node: nodes[c.name], Fetched: computed(t, c.doc, digest('1')), Secrets: s.fetch})
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
			if first, _, _ := strings.Cut(c.want, "\n"); len(first) > 100 {
				t.Errorf("the refusal's first line is %d characters, over 100", len(first))
			}
			if got := s.called(); len(got) != 0 {
				t.Errorf("the secrets requests %v; want none", got)
			}
		})
	}
}

// TestAReloadMustAllowThePushHosts pins the hold's check at a reload: a policy whose
// enforce allow list no longer covers a host of push-1 is refused, and the policy in
// force stays.
func TestAReloadMustAllowThePushHosts(t *testing.T) {
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, pushDoc, digest('1')), Secrets: (&controlPlane{answer: harnessValue}).fetch})
	narrowed := strings.Replace(pushDoc, `"allow":["git.example"]`, `"allow":["other.example"]`, 1)
	d, err := reload(t, r, computed(t, narrowed, digest('2')))
	if err == nil {
		d.Discard()
		t.Fatal("the reload passed")
	}
	if !strings.Contains(err.Error(), "Add each push credential's host to the run's egress allow list.") {
		t.Errorf("the reload's error %v", err)
	}
	if got := r.Policy().Policy.Egress.Allow; !slices.Equal(got, []string{"git.example"}) {
		t.Errorf("the policy in force allows %v", got)
	}
}

// TestAPushValueIsRenewed pins the renewal of a push credential's value: it is renewed
// with the work credential's, in one secrets request, and the push proxy then sets the
// new value while the run's proxy sets work-1's new value.
func TestAPushValueIsRenewed(t *testing.T) {
	expiring := func(name string, call int) (answer, error) {
		return answer{value: name + "-" + string(rune('0'+call)), expires: start.Add(time.Hour + time.Duration(call)*time.Hour)}, nil
	}
	c := &fakeClock{now: start}
	s := &controlPlane{answer: expiring}
	r := renewRun(t, pushDoc, s, c, &reports{}, nil)
	if uses := r.PushUses(); len(uses) != 1 || uses[0].Rejected == nil {
		t.Fatalf("the push proxy's credentials %+v; want push-1 with a renewal on a 401", uses)
	}
	if pushValueOf(r, "push-1") != "push-1-0" || value(r, "work-1") != "work-1-0" {
		t.Fatalf("before the renewal: push-1 %s, work-1 %s", pushValueOf(r, "push-1"), value(r, "work-1"))
	}
	c.step(t, time.Hour-credential.RenewBefore)
	if got := s.called(); len(got) != 2 || !slices.Equal(got[1], []string{digest('c'), "work-1", "push-1"}) {
		t.Fatalf("the renewal's calls %v", got)
	}
	if pushValueOf(r, "push-1") != "push-1-1" || value(r, "work-1") != "work-1-1" {
		t.Errorf("after the renewal: push-1 %s, work-1 %s; want both renewed", pushValueOf(r, "push-1"), value(r, "work-1"))
	}
}

// TestThePushPlaceholdersFixtureIsRefused pins the contract's fixture of a push
// credential with placeholders, which run-configuration.schema.json accepts: the run is
// refused, run_configuration_invalid.
func TestThePushPlaceholdersFixtureIsRefused(t *testing.T) {
	b, err := fs.ReadFile(contracts.FS, "fixtures/invalid/run-configuration-beyond-schema-credentials-push-placeholders.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, string(b), digest('1')),
		Secrets: (&controlPlane{answer: harnessValue}).fetch})
	if code, names := refusalOf(err); code != refusal.RunConfigurationInvalid || !slices.Equal(names, []string{"push-1"}) ||
		!strings.HasPrefix(err.Error(), "Remove placeholders from push credentials") {
		t.Errorf("Open: %v; want the placeholders refused", err)
	}
}

// TestAReloadMustNotDenyThePushHosts pins the hold's check of the deny list at a
// reload: a policy whose deny list covers a host of push-1 fails the reload, and the
// policy in force stays.
func TestAReloadMustNotDenyThePushHosts(t *testing.T) {
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, pushDoc, digest('1')), Secrets: (&controlPlane{answer: harnessValue}).fetch})
	denying := strings.Replace(pushDoc, `"allow":["git.example"]`, `"allow":["git.example"],"deny":["git.example"]`, 1)
	d, err := reload(t, r, computed(t, denying, digest('2')))
	if err == nil {
		d.Discard()
		t.Fatal("the reload passed")
	}
	if !strings.Contains(err.Error(), "Remove each push credential's host from the egress deny lists.") {
		t.Errorf("the reload's error %v", err)
	}
	if got := r.Policy().Policy.Egress.Deny; len(got) != 0 {
		t.Errorf("the policy in force denies %v", got)
	}
}
