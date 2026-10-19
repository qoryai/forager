package gateway

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/gateway/internal/credential"
	"github.com/qoryai/forager/policy"
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
				if s := strings.ToLower(stringOf(v)); strings.Contains(s, "qak_") || strings.Contains(s, "qrk_") {
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
