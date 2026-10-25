package run_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/sealed"
)

// storedDoc is a run configuration with a credential from the server for
// api.model.example, under a policy that allows it.
const storedDoc = `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}},"credentials":[{"name":"model","apply":[{"hosts":["api.model.example"],"scheme":"bearer"}],"placeholders":["MODEL_API_KEY"]}]}`

// computed is a document whose Computed is set, as the server package sets it on the
// document it reads.
func computed(t *testing.T, doc string, d string) *run.Fetched {
	t.Helper()
	f := document(t, doc, d)
	f.Document.Computed = digest('c')
	return f
}

// secrets is a Config.Secrets that opens value for every name asked, and records each
// call's digest and names.
type secrets struct {
	value string
	calls [][]string
	err   error
}

func (s *secrets) fetch(_ context.Context, digest string, names []string) (sealed.Values, error) {
	s.calls = append(s.calls, append([]string{digest}, names...))
	if s.err != nil {
		return sealed.Values{}, s.err
	}
	sl := sealed.Sealing{AccessKeyID: "ak_0123456789abcdef", RunID: runID, RunConfiguration: digest, Credentials: names, Exp: sealed.Expiry(time.Now())}
	for _, n := range names {
		sl.Values = append(sl.Values, sealed.NewValue(n, []byte(s.value)))
	}
	pt, err := sl.Plaintext()
	if err != nil {
		return sealed.Values{}, err
	}
	return sealed.Plaintext(pt, digest, names)
}

// TestARunOpensItsCredentialsOnceUnderTheComputedDigest pins the start: Secrets is
// called once, with the digest Forager computed and not the header's, and the names in
// the document's order; the use has the opened value; a reload with the same
// credentials and another policy calls it no more and keeps the value; one with other
// credentials is refused and the policy in force stays; Close clears the value. A run
// without a wall opens them as a walled run does, and has the run's authority.
func TestARunOpensItsCredentialsOnceUnderTheComputedDigest(t *testing.T) {
	for _, wall := range []bool{true, false} {
		t.Run(fmt.Sprintf("wall %v", wall), func(t *testing.T) { opensOnce(t, wall) })
	}
}

// opensOnce is TestARunOpensItsCredentialsOnceUnderTheComputedDigest for a run with a
// wall or without one.
func opensOnce(t *testing.T, wall bool) {
	s := &secrets{value: "opened-value"}
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: wall, Server: true, Fetched: computed(t, storedDoc, digest('1')), Secrets: s.fetch})
	if err != nil {
		t.Fatal(err)
	}
	if !r.NeedsCA() {
		t.Error("the run has no authority")
	}
	if len(s.calls) != 1 || !slices.Equal(s.calls[0], []string{digest('c'), "model"}) {
		t.Fatalf("Secrets calls %v", s.calls)
	}
	value := func() string {
		for _, u := range r.Uses() {
			if u.Name == "model" && u.Stored && u.Value != nil {
				return string(u.Value())
			}
		}
		return "(none)"
	}
	if got := value(); got != "opened-value" || !slices.Equal(r.Placeholders(), []string{"MODEL_API_KEY"}) {
		t.Errorf("the value %q, placeholders %v", got, r.Placeholders())
	}
	same := strings.Replace(storedDoc, `"allow":["api.model.example"]`, `"allow":["api.model.example","b.example"]`, 1)
	d, err := reload(t, r, computed(t, same, digest('2')))
	if err != nil {
		t.Fatal(err)
	}
	r.Commit(d)
	if len(s.calls) != 1 || value() != "opened-value" || r.RunConfiguration() != digest('2') {
		t.Errorf("after a reload: %d calls, the value %q, %s", len(s.calls), value(), r.RunConfiguration())
	}
	other := strings.Replace(same, `"scheme":"bearer"`, `"scheme":"basic","username":"x"`, 1)
	_, err = reload(t, r, computed(t, other, digest('3')))
	if err == nil || err.Error() != "run configuration "+runURL+": start a new run to use other credentials; a run's credentials from the control plane are fixed when it starts, and this run configuration has other credentials than the run started with; the policy in force stays" {
		t.Errorf("a reload with other credentials: %v", err)
	}
	none := `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}}}`
	if _, err := reload(t, r, computed(t, none, digest('4'))); err == nil {
		t.Error("a reload with no credentials was put in force")
	}
	if r.RunConfiguration() != digest('2') || value() != "opened-value" {
		t.Errorf("after refused reloads: %s, the value %q", r.RunConfiguration(), value())
	}
	uses := r.Uses()
	r.Close()
	for _, u := range uses {
		if u.Value != nil && len(u.Value()) != 0 {
			t.Errorf("after Close the value is %q", u.Value())
		}
	}
}

// TestCredentialsFromTheServerAreRefusedBeforeTheyOpen pins what refuses a run whose
// run configuration has credentials, before Secrets is called: no secrets endpoint, a
// name twice and a reserved header; and after it: an error of Secrets, a value a
// header cannot hold, and a model key's value that starts with none of its
// key_prefixes, whose messages have the name and not the value.
func TestCredentialsFromTheServerAreRefusedBeforeTheyOpen(t *testing.T) {
	twice := strings.Replace(storedDoc, `]}]}`, `]},{"name":"model","apply":[{"hosts":["b.example"],"scheme":"bearer"}]}]}`, 1)
	reserved := strings.Replace(storedDoc, `"scheme":"bearer"`, `"scheme":"header","header":"Proxy-Authorization"`, 1)
	prefixed := `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]}},"credentials":[` +
		`{"name":"model","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"header","header":"x-api-key"},"key_prefixes":["sk-ant-api","sk-ant-oat"]}]}`
	for name, c := range map[string]struct {
		doc    string
		wall   bool
		s      *secrets
		code   string
		want   string
		called bool
	}{
		"no secrets":        {storedDoc, true, nil, "run_configuration_invalid", "enrol an access key allowed stored secrets", false},
		"a name twice":      {twice, true, &secrets{value: "v"}, "run_configuration_invalid", `list the credential "model" once`, false},
		"a reserved header": {reserved, true, &secrets{value: "v"}, "run_configuration_invalid", `in another header than "Proxy-Authorization"`, false},
		"Secrets fails":     {storedDoc, true, &secrets{err: errors.New("secrets https://apiary.example/v1/secrets: the envelope is for another run configuration")}, "", "for another run configuration", true},
		"a carriage return": {storedDoc, true, &secrets{value: "opened\rvalue"}, "run_configuration_invalid", `store another value of the credential "model" in the control plane`, true},
		"a trailing tab":    {storedDoc, true, &secrets{value: "opened-value\t"}, "run_configuration_invalid", "which a header value cannot have", true},
		"a C1 control":      {storedDoc, true, &secrets{value: "opened\u0085value"}, "run_configuration_invalid", "which a header value cannot have", true},
		"not UTF-8":         {storedDoc, true, &secrets{value: "opened\xffvalue"}, "", "UTF-8", true},
		"an empty value":    {storedDoc, true, &secrets{value: ""}, "", "", true},
		"a value without a key prefix": {prefixed, true, &secrets{value: "opened-value"}, "run_configuration_invalid",
			`run configuration ` + runURL + `: store in the control plane a value of the credential "model" that starts with "sk-ant-api" or "sk-ant-oat": the stored value starts with none of its key_prefixes: run_configuration_invalid: model`, true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := run.Config{RunID: runID, Wall: c.wall, Server: true, Fetched: computed(t, c.doc, digest('1'))}
			if c.s != nil {
				cfg.Secrets = c.s.fetch
			}
			r, err := run.Open(context.Background(), cfg)
			if err == nil {
				r.Close()
				t.Fatal("the run opened")
			}
			if code, _ := refusalOf(err); (c.code != "" && code != c.code) || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "opened") {
				t.Errorf("%v (%s); want %s with %q", err, code, c.code, c.want)
			}
			if called := c.s != nil && len(c.s.calls) > 0; called != c.called {
				t.Errorf("Secrets called %v, want %v", called, c.called)
			}
		})
	}
}

// TestNoCredentialsCallNoSecrets pins a run configuration with no credentials: no
// Secrets call, as before.
func TestNoCredentialsCallNoSecrets(t *testing.T) {
	s := &secrets{value: "v"}
	r := open(t, run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, `{"version":1}`, digest('1')), Secrets: s.fetch})
	if len(s.calls) != 0 || len(r.Uses()) != 0 {
		t.Errorf("%d calls, uses %v", len(s.calls), r.Uses())
	}
}

// TestAHeaderValueIsTheContracts pins HeaderValue.
func TestAHeaderValueIsTheContracts(t *testing.T) {
	for v, want := range map[string]bool{
		"sk-test-0001": true, "a\tb": true, "ünïcode": true, "a b": true,
		"": false, " a": false, "a ": false, "\ta": false, "a\t": false, "a\nb": false, "a\rb": false, "a\x00b": false,
		"a\x7fb": false, "a\u0085b": false, "a\u009fb": false, "a\xffb": false,
	} {
		if got := run.HeaderValue([]byte(v)); got != want {
			t.Errorf("HeaderValue(%q) = %v, want %v", v, got, want)
		}
	}
}

// TestAValueIsNeverReadWhileTheRunClearsIt pins the end of a run while a request is
// still being served: a use's Value, read as the proxy reads it, and Close, which
// overwrites the values, never touch the bytes at once. Under -race a read of the
// bytes outside the run's lock fails this test.
func TestAValueIsNeverReadWhileTheRunClearsIt(t *testing.T) {
	for range 20 {
		s := &secrets{value: "opened-value"}
		r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, storedDoc, digest('1')), Secrets: s.fetch})
		if err != nil {
			t.Fatal(err)
		}
		uses := r.Uses()
		var wg sync.WaitGroup
		wg.Go(func() {
			for range 200 {
				v := uses[0].Value()
				if got := string(v); got != "" && got != "opened-value" {
					t.Errorf("a value read while it is cleared: %q", got)
				}
			}
		})
		r.Close()
		wg.Wait()
	}
}

// TestAValueRefusalShowsNoSecretInTheName pins the refusal of a value a header cannot
// hold for a credential whose name contains qak_: the phrase in the text and as the
// refusal's one name, which run.refused.schema.json's names accept.
func TestAValueRefusalShowsNoSecretInTheName(t *testing.T) {
	doc := strings.Replace(storedDoc, `"name":"model"`, `"name":"x-qak_not-a-real-secret"`, 1)
	s := &secrets{value: "opened\nvalue"}
	_, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, doc, digest('1')), Secrets: s.fetch})
	code, names := refusalOf(err)
	if code != "run_configuration_invalid" || !slices.Equal(names, []string{"(a name that contains an access key secret)"}) || strings.Contains(strings.ToLower(err.Error()), "qak_") || !strings.Contains(err.Error(), "(a name that contains an access key secret)") {
		t.Errorf("%v, names %v", err, names)
	}
	schema, err := contracts.Compile("events/run.refused.schema.json#/properties/names")
	if err != nil {
		t.Fatal(err)
	}
	listed := make([]any, len(names))
	for i, n := range names {
		listed[i] = n
	}
	if err := schema.Validate(listed); err != nil {
		t.Errorf("the names %q do not validate: %v", names, err)
	}
}

// TestARunConfigurationURLWithASecretIsAPhrase pins the four refusals of a run
// configuration with credentials whose URL contains qak_: no secrets endpoint, a value
// a header cannot hold, a credential twice, and a reload with other credentials. Each
// text has the value's phrase in place of the URL.
func TestARunConfigurationURLWithASecretIsAPhrase(t *testing.T) {
	const secretURL = "https://apiary.example/v1/qak_not-a-real-secret/run-configuration"
	const phrase = "run configuration (a value that contains an access key secret): "
	at := func(f *run.Fetched) *run.Fetched {
		f.URL = secretURL
		return f
	}
	check := func(want string, err error) {
		t.Helper()
		if err == nil || strings.Contains(strings.ToLower(err.Error()), "qak_") || !strings.HasPrefix(err.Error(), phrase) || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q: %v", want, err)
		}
	}
	_, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: at(computed(t, storedDoc, digest('1')))})
	check("enrol an access key allowed stored secrets", err)
	_, err = run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: at(computed(t, storedDoc, digest('1'))), Secrets: (&secrets{value: "opened\nvalue"}).fetch})
	check("which a header value cannot have", err)
	entry := `{"name":"model","apply":[{"hosts":["api.model.example"],"scheme":"bearer"}]}`
	twice := `{"version":1,"credentials":[` + entry + `,` + entry + `]}`
	_, err = run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: at(computed(t, twice, digest('1'))), Secrets: (&secrets{value: "opened-value"}).fetch})
	check(`list the credential "model" once`, err)
	r, err := run.Open(context.Background(), run.Config{RunID: runID, Wall: true, Server: true, Fetched: computed(t, storedDoc, digest('1')), Secrets: (&secrets{value: "opened-value"}).fetch})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	other := strings.Replace(storedDoc, `"scheme":"bearer"`, `"scheme":"basic","username":"x"`, 1)
	_, err = reload(t, r, at(computed(t, other, digest('2'))))
	check("start a new run to use other credentials", err)
}
