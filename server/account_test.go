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
			!strings.Contains(err.Error(), "Set account_header of the credential \"subscription\" to another header") {
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

// TestAnUnclearModelKeyPathIsRefused pins that a path of an API credential that the
// schema's grammar takes but that has a part policy.CleanPath refuses in a request's
// path, a dot segment, an empty segment, a backslash or an encoded slash, backslash, dot
// or percent sign, is run_configuration_invalid, since the proxy denies every request
// path with one. A segment counts by its part before its first ; or %3B, as a server
// such as Tomcat reads it. A dot inside a name, or after the last slash of a path that
// ends in *, is no segment, and a ; after a name starts a parameter of a normal segment.
func TestAnUnclearModelKeyPathIsRefused(t *testing.T) {
	for _, p := range []string{"/a/../b", "/a/./b", "/..", "/.", "/a/..", "/a/../*", "/a/./*", "/./*", "/a//b", "//*",
		"/a/%2e%2e/b", "/a%2Fb", "/a%5cb", "/a%25b", `/a\b`, "/a/%2e*",
		"/a/..;/b", "/a/.;/b", "/a/..;x/b", "/a/..;", "/a/..;*", "/a/;x/b", "/a/..%3b/b", "/a/..%3B/b", "/a/%2e%2e;/b", "/a/%2e;/b"} {
		c := subscription()
		c.Paths = []string{"/backend-api/codex/*", p}
		err := server.CheckCredentials([]server.RunCredential{c}, "")
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.Contains(err.Error(), "the proxy denies every request whose path has one") {
			t.Errorf("path %s: %v", p, err)
		}
	}
	for _, p := range []string{"/a/.well-known", "/a/.*", "/a/..*", "/a/..b", "/a.b/c", "/backend-api/codex/*", "/a/", "/*",
		"/a/b;jsessionid=0123/c", "/a/b;jsessionid=0123", "/a/..b;x/c", "/a/b%3bx/c"} {
		c := subscription()
		c.Paths = []string{p}
		if err := server.CheckCredentials([]server.RunCredential{c}, ""); err != nil {
			t.Errorf("path %s: %v", p, err)
		}
	}
}

// TestAnUnclearHostCredentialPathIsRefused pins the same check for a host credential's
// apply paths: a dot segment, an empty segment, or a segment that is one before its
// first ;, is run_configuration_invalid with the credential's name, and a normal path,
// one with a parameter after a name among them, is taken.
func TestAnUnclearHostCredentialPathIsRefused(t *testing.T) {
	forge := func(paths ...string) server.RunCredential {
		return server.RunCredential{Name: "forge", Placeholders: []string{"FORGE_TOKEN"}, Apply: []server.Apply{
			{Hosts: []string{"api.git.example"}, Scheme: "bearer", Paths: []string{"/repos/example-org/app/*"}},
			{Hosts: []string{"git.example"}, Scheme: "basic", Username: "x-access-token", Paths: paths}}}
	}
	for _, p := range []string{"/example-org/app.git/..;/other", "/example-org/app.git/.;/x", "/example-org/..;x/*", "/example-org/../*",
		"/example-org//*", "/example-org/;x/*", "/example-org/%2e%2e;/*", "/example-org/..%3B/*"} {
		err := server.CheckCredentials([]server.RunCredential{forge("/example-org/app.git/*", p)}, "")
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !strings.Contains(err.Error(), `the credential "forge"`) ||
			!strings.Contains(err.Error(), "the proxy denies every request whose path has one") {
			t.Errorf("path %s: %v", p, err)
		}
	}
	for _, p := range []string{"/example-org/app.git/*", "/example-org/app;jsessionid=0123/*", "/example-org/app.git/info/refs", "/*"} {
		if err := server.CheckCredentials([]server.RunCredential{forge(p)}, ""); err != nil {
			t.Errorf("path %s: %v", p, err)
		}
	}
}

// TestAnAccountHeaderComesWithItsClaimAndOAuth pins CheckCredentials for a document not
// read from bytes: account_header without account_claim, account_claim without
// account_header, and both without oauth are run_configuration_invalid, as the schema
// has them.
func TestAnAccountHeaderComesWithItsClaimAndOAuth(t *testing.T) {
	for name, change := range map[string]func(*server.Auth){
		"no claim":  func(a *server.Auth) { a.AccountClaim = "" },
		"no header": func(a *server.Auth) { a.AccountHeader = "" },
		"no oauth":  func(a *server.Auth) { a.OAuth = false },
	} {
		c := subscription()
		change(&c.Auth)
		err := server.CheckCredentials([]server.RunCredential{c}, "")
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != refusal.RunConfigurationInvalid || !slices.Equal(r.Names, []string{"subscription"}) ||
			!strings.Contains(err.Error(), "Give the credential \"subscription\" both account_header and account_claim, with oauth, or neither") {
			t.Errorf("%s: %v", name, err)
		}
	}
	c := subscription()
	c.Auth.AccountHeader, c.Auth.AccountClaim, c.Auth.OAuth = "", "", false
	if err := server.CheckCredentials([]server.RunCredential{c}, ""); err != nil {
		t.Errorf("neither: %v", err)
	}
}
