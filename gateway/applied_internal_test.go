package gateway

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/gateway/internal/tool"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/refusal"
)

// appliedCredentials are the credentials member appliedOf gives for one credential
// named name, from an adapter, that the policy passes argument, and the whole member
// map, which the test validates against run.policy_applied.schema.json.
func appliedCredentials(t *testing.T, name, argument string) ([]any, map[string]any) {
	t.Helper()
	adapter := filepath.Join(t.TempDir(), "adapter")
	answer := `echo '{"version":1,"token":"minted","expires_at":"2099-01-01T00:00:00Z","apply":[{"hosts":["git.example"],"scheme":"bearer"}]}'` + "\n"
	if err := os.WriteFile(adapter, []byte("#!/bin/sh\n"+answer), 0o755); err != nil {
		t.Fatal(err)
	}
	defs := []credential.Definition{{Name: name, Adapter: []string{adapter, "${argument}"}, Argument: `.+`}}
	held, err := credential.Resolve(context.Background(), defs, []policy.Selected{{Name: name, Argument: argument}}, policy.Observe, nil, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	pol := &policy.Loaded{Policy: policy.Policy{Version: 1, Egress: policy.Egress{Mode: policy.Observe}}, Source: "none"}
	a := appliedOf(pol, nil, held, nil, nil)
	schema, err := contracts.Compile("events/run.policy_applied.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(a); err != nil {
		t.Errorf("%s, %s: the members do not validate: %v", name, argument, err)
	}
	creds, _ := a["credentials"].([]any)
	return creds, a
}

// TestAppliedCredentialsSendAPhraseForASecret pins run.policy_applied's credentials:
// a name or an argument that contains qak_ or qrk_ in any case is sent as the name's
// phrase, the access key secret's when it contains both, the event validates against
// its schema, and a clean name and argument are sent as they are.
func TestAppliedCredentialsSendAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a name that contains an access key secret)", "(a name that contains a run key)"
	for _, c := range []struct {
		name, argument    string
		wantName, wantArg string
	}{
		{"qak_x", "acme/shop", ak, "acme/shop"},
		{"a.qrk_b", "acme/shop", rk, "acme/shop"},
		{"qrk_x.qak_y", "acme/shop", ak, "acme/shop"},
		{"github", "QAK_x", "github", ak},
		{"github", "acme/qRk_shop", "github", rk},
		{"github", "QRK_x/QAK_y", "github", ak},
		{"github", "acme/shop", "github", "acme/shop"},
	} {
		creds, a := appliedCredentials(t, c.name, c.argument)
		want := []any{map[string]any{"name": c.wantName, "argument": c.wantArg, "hosts": []any{"git.example"}, "scheme": "bearer"}}
		if !reflect.DeepEqual(creds, want) {
			t.Errorf("%s, %s: credentials %v, want %v", c.name, c.argument, creds, want)
		}
		if c.wantName != c.name || c.wantArg != c.argument {
			for k, v := range a {
				if s := strings.ToLower(stringOf(v)); strings.Contains(s, "qak_") || strings.Contains(s, "qrk_") || strings.Contains(s, "qecr_") {
					t.Errorf("%s, %s: a secret's prefix in %s: %v", c.name, c.argument, k, v)
				}
			}
		}
	}
}

// stringOf is v as the test looks for a prefix in it: its members' and items' strings
// joined.
func stringOf(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case []any:
		var b strings.Builder
		for _, e := range v {
			b.WriteString(stringOf(e) + " ")
		}
		return b.String()
	case map[string]any:
		var b strings.Builder
		for k, e := range v {
			b.WriteString(k + " " + stringOf(e) + " ")
		}
		return b.String()
	}
	return ""
}

// TestAppliedToolsSendAPhraseForASecret pins run.policy_applied's tools: a tool's name
// or argument that contains qak_ or qrk_ in any case is sent as the name's phrase, the
// access key secret's when it contains both, the members validate against the event's
// schema, and a clean name and argument are sent as they are.
func TestAppliedToolsSendAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a name that contains an access key secret)", "(a name that contains a run key)"
	schema, err := contracts.Compile("events/run.policy_applied.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	pol := &policy.Loaded{Policy: policy.Policy{Version: 1, Egress: policy.Egress{Mode: policy.Observe}}, Source: "none"}
	for _, c := range []struct {
		name, argument    string
		wantName, wantArg string
	}{
		{"qak_x", "acme/shop", ak, "acme/shop"},
		{"a.qrk_b", "acme/shop", rk, "acme/shop"},
		{"qrk_x.qak_y", "acme/shop", ak, "acme/shop"},
		{"files", "QAK_x", "files", ak},
		{"files", "acme/qRk_shop", "files", rk},
		{"files", "QRK_x/QAK_y", "files", ak},
		{"files", "acme/shop", "files", "acme/shop"},
	} {
		chosen := []tool.Chosen{{Definition: tool.Definition{Name: c.name, Serves: []string{"files.tools.internal"}}, Argument: c.argument}}
		a := appliedOf(pol, nil, nil, chosen, nil)
		if err := schema.Validate(a); err != nil {
			t.Errorf("%s, %s: the members do not validate: %v", c.name, c.argument, err)
		}
		want := []any{map[string]any{"name": c.wantName, "argument": c.wantArg, "hosts": []any{"files.tools.internal"}}}
		if !reflect.DeepEqual(a["tools"], want) {
			t.Errorf("%s, %s: tools %v, want %v", c.name, c.argument, a["tools"], want)
		}
		if c.wantName != c.name || c.wantArg != c.argument {
			if s := strings.ToLower(stringOf(a["tools"])); strings.Contains(s, "qak_") || strings.Contains(s, "qrk_") || strings.Contains(s, "qecr_") {
				t.Errorf("%s, %s: a secret's prefix in tools: %v", c.name, c.argument, a["tools"])
			}
		}
	}
}

// TestAppliedImageSendsAPhraseForASecret pins run.policy_applied's image: a name that
// contains qak_ or qrk_ in any case is sent as the name's phrase, the members validate
// against the event's schema, and a clean name is sent as it is.
func TestAppliedImageSendsAPhraseForASecret(t *testing.T) {
	schema, err := contracts.Compile("events/run.policy_applied.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for image, want := range map[string]string{
		"qak_base": "(a name that contains an access key secret)", "a.qrk_b": "(a name that contains a run key)",
		"qrk_x.qak_y": "(a name that contains an access key secret)", "base": "base",
	} {
		pol := &policy.Loaded{Policy: policy.Policy{Version: 1, Egress: policy.Egress{Mode: policy.Observe}, Image: image}, Source: "none"}
		a := appliedOf(pol, nil, nil, nil, nil)
		if a["image"] != want {
			t.Errorf("%s: image %v, want %s", image, a["image"], want)
		}
		if err := schema.Validate(a); err != nil {
			t.Errorf("%s: the members do not validate: %v", image, err)
		}
	}
}

// TestAppliedPathsAndHostsSendAPhraseForASecret pins run.policy_applied's paths, its
// ceiling_paths, a credential's hosts and the hosts the proxy terminates: a path or a
// host that contains qak_ or qrk_ in any case is sent as the value's phrase, the members
// validate against the event's schema, and a clean one is sent as it is.
func TestAppliedPathsAndHostsSendAPhraseForASecret(t *testing.T) {
	const ak, rk = "(a value that contains an access key secret)", "(a value that contains a run key)"
	t.Setenv("QORY_TEST_MODEL_TOKEN", "the-token")
	defs := []credential.Definition{{Name: "model", Env: "QORY_TEST_MODEL_TOKEN", Hosts: []string{"api.qrk_h.example", "api.example"}, Scheme: "bearer"}}
	held, err := credential.Resolve(context.Background(), defs, []policy.Selected{{Name: "model"}}, policy.Observe, nil, func(l string) { t.Log(l) })
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	pol := &policy.Loaded{Policy: policy.Policy{Version: 1, Egress: policy.Egress{Mode: policy.Observe, Paths: map[string][]string{"a.example": {"/QAK_x/*", "/ok"}}}}, Source: "none"}
	a := appliedOf(pol, []map[string][]string{{"b.example": {"/qrk_y"}}}, held, nil, []string{"qak_t.example", "ok.example"})
	schema, err := contracts.Compile("events/run.policy_applied.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(a); err != nil {
		t.Errorf("the members do not validate: %v", err)
	}
	want := map[string]any{
		"paths":         map[string]any{"a.example": []any{ak, "/ok"}},
		"ceiling_paths": []any{map[string]any{"b.example": []any{rk}}},
		"terminated":    []any{ak, "ok.example"},
		"hosts":         []any{rk, "api.example"},
	}
	creds, _ := a["credentials"].([]any)
	var hosts any
	if len(creds) == 1 {
		hosts = creds[0].(map[string]any)["hosts"]
	}
	got := map[string]any{"paths": a["paths"], "ceiling_paths": a["ceiling_paths"], "terminated": a["terminated"], "hosts": hosts}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("appliedOf %v, want %v", got, want)
	}
}

// TestARunStartedMayCarryPhrasedLabelKeys pins the gateway's check of a run.started's
// labels: the run's labels as they are, or as server.ShownLabels gives them, keys
// included, pass; other labels do not.
func TestARunStartedMayCarryPhrasedLabelKeys(t *testing.T) {
	labels := map[string]string{"qak_k": "v", "repository": "acme/qrk_x"}
	for what, c := range map[string]struct {
		got  any
		same bool
	}{
		"as they are":  {map[string]any{"qak_k": "v", "repository": "acme/qrk_x"}, true},
		"phrased":      {map[string]any{"(a name that contains an access key secret)": "v", "repository": "(a name that contains a run key)"}, true},
		"another":      {map[string]any{"(a name that contains an access key secret)": "w", "repository": "(a name that contains a run key)"}, false},
		"keys as they": {map[string]any{"qak_k": "v", "repository": "(a name that contains a run key)"}, false},
	} {
		if sameLabels(c.got, labels) != c.same {
			t.Errorf("%s: sameLabels = %v", what, !c.same)
		}
	}
}

// TestALinkRefusalSendsNoSecret pins the names of a refusal on the link, a
// wall_required's image=<name> and a refusal's names: a name that contains qak_ or
// qrk_ in any case is sent as the name's phrase.
func TestALinkRefusalSendsNoSecret(t *testing.T) {
	schema, err := contracts.Compile("link-refusal.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		err   error
		names []string
	}{
		{&refusal.NeedsWall{Names: []string{"image=qrk_FAKE"}}, []string{"image=(a name that contains a run key)"}},
		{&refusal.NeedsWall{Names: []string{"credentials", "image=QAK_FAKE"}}, []string{"credentials", "image=(a name that contains an access key secret)"}},
		{&accesskey.Refusal{Code: "image_unknown", Status: 422, From: accesskey.FromApiary, Names: []string{"qak_FAKE", "base"}}, []string{"(a name that contains an access key secret)", "base"}},
		{&accesskey.Refusal{Code: "image_unknown", Status: 422, Names: []string{"x.qrk_FAKE"}}, []string{"(a name that contains a run key)"}},
	} {
		w := httptest.NewRecorder()
		refuseOpen(w, c.err)
		var body linkRefusal
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(body.Names, c.names) {
			t.Errorf("%v: names %q, want %q", c.err, body.Names, c.names)
		}
		if accesskey.ContainsSecret(w.Body.String()) {
			t.Errorf("%v: a secret's prefix in %s", c.err, w.Body)
		}
		doc, err := contracts.Decode("link-refusal.json", w.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%v: link-refusal.schema.json refuses %s: %v", c.err, w.Body, err)
		}
	}
}
