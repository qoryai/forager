package server_test

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// subscription is a model key with paths and an account header, as the contract's
// fixture model-keys-openai.json has it.
func subscription() server.RunCredential {
	return server.RunCredential{Name: "subscription", Format: "openai-responses", Endpoint: "https://chat.model.example/backend-api/codex",
		Auth:  server.Auth{Scheme: "bearer", OAuth: true, AccountHeader: "chatgpt-account-id", AccountClaim: "/https:~1~1auth.model.example~1auth/account_id"},
		Paths: []string{"/backend-api/codex/*"}}
}

// TestTheOpenAIFixtureDecodesPathsAndTheAccountHeader pins that a run configuration's
// API credential decodes paths, account_header and account_claim, that its Applies
// have the paths, and that CheckCredentials takes it.
func TestTheOpenAIFixtureDecodesPathsAndTheAccountHeader(t *testing.T) {
	b, err := fs.ReadFile(contracts.FS, "fixtures/run-configuration/model-keys-openai.json")
	if err != nil {
		t.Fatal(err)
	}
	var rc server.RunConfiguration
	if err := jsonv2.Unmarshal(b, &rc); err != nil {
		t.Fatal(err)
	}
	sub := rc.Credentials[0]
	if sub.Auth.AccountHeader != "chatgpt-account-id" || sub.Auth.AccountClaim != "/https:~1~1api.openai.com~1auth/chatgpt_account_id" || !slices.Equal(sub.Paths, []string{"/backend-api/codex/*"}) {
		t.Errorf("the subscription decodes as %+v", sub)
	}
	if a := sub.Applies(); len(a) != 1 || !slices.Equal(a[0].Paths, []string{"/backend-api/codex/*"}) || a[0].Hosts[0] != "chatgpt.example" {
		t.Errorf("Applies %+v", a)
	}
	if err := server.CheckCredentials(rc.Credentials, rc.ModelCredential); err != nil {
		t.Error(err)
	}
}

// TestAReservedAccountHeaderIsRefused pins CheckCredentials for a document not read
// from bytes, which no schema checked: an account_header that server.ReservedHeader
// reports, or Authorization, in any letter case and with _ for -, is
// run_configuration_invalid with the credential's name, and another header is taken.
func TestAReservedAccountHeaderIsRefused(t *testing.T) {
	for _, h := range []string{"Authorization", "authorization", "Host", "content_length", "Cookie", "Proxy-Authorization", "X-Qory-Run", "qory_key", "TE"} {
		c := subscription()
		c.Auth.AccountHeader = h
		err := server.CheckCredentials([]server.RunCredential{c}, "")
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !slices.Equal(r.Names, []string{"subscription"}) ||
			!strings.Contains(err.Error(), "set account_header of the credential \"subscription\" to another header") {
			t.Errorf("account_header %s: %v", h, err)
		}
	}
	for _, h := range []string{"chatgpt-account-id", "x-host", "authorization-id", "tea"} {
		c := subscription()
		c.Auth.AccountHeader = h
		if err := server.CheckCredentials([]server.RunCredential{c}, ""); err != nil {
			t.Errorf("account_header %s: %v", h, err)
		}
	}
}

// TestAModelKeyPathWithADotSegmentIsRefused pins that a path of an API credential with
// a . or .. segment, which the schema's grammar takes, is run_configuration_invalid,
// since the proxy denies every request path with one; a dot inside a name, or after the
// last slash of a path that ends in *, is no segment.
func TestAModelKeyPathWithADotSegmentIsRefused(t *testing.T) {
	for _, p := range []string{"/a/../b", "/a/./b", "/..", "/.", "/a/..", "/a/../*", "/a/./*", "/./*"} {
		c := subscription()
		c.Paths = []string{"/backend-api/codex/*", p}
		err := server.CheckCredentials([]server.RunCredential{c}, "")
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.Contains(err.Error(), "without a . or .. segment") {
			t.Errorf("path %s: %v", p, err)
		}
	}
	for _, p := range []string{"/a/.well-known", "/a/.*", "/a/..*", "/a/..b", "/a.b/c", "/backend-api/codex/*"} {
		c := subscription()
		c.Paths = []string{p}
		if err := server.CheckCredentials([]server.RunCredential{c}, ""); err != nil {
			t.Errorf("path %s: %v", p, err)
		}
	}
}
