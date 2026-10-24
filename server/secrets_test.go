package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

// credentialDoc is a run configuration with two credentials: an API credential and a
// host credential.
const credentialDoc = `{"version":1,"credentials":[{"name":"model","format":"anthropic-messages","endpoint":"https://api.model.example/anthropic","auth":{"scheme":"bearer","oauth":true},"key_prefixes":["sk-ant-"]},{"name":"forge","apply":[{"hosts":["git.example"],"scheme":"basic","username":"x-access-token"}],"placeholders":["FORGE_TOKEN"]}],"model_credential":"model"}`

// TestARunConfigurationsCredentialsAndItsComputedDigest pins the reading of
// credentials: each entry decoded, and Computed the SHA-256 of the bytes as they came,
// whatever the header's digest is.
func TestARunConfigurationsCredentialsAndItsComputedDigest(t *testing.T) {
	v := newVerified(t)
	v.runDoc = credentialDoc
	rc, d, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(credentialDoc))
	want := []server.RunCredential{
		{Name: "model", Format: "anthropic-messages", Endpoint: "https://api.model.example/anthropic", Auth: server.Auth{Scheme: "bearer", OAuth: true}, KeyPrefixes: []string{"sk-ant-"}},
		{Name: "forge", Apply: []server.Apply{{Hosts: []string{"git.example"}, Scheme: "basic", Username: "x-access-token"}}, Placeholders: []string{"FORGE_TOKEN"}},
	}
	if !reflect.DeepEqual(rc.Credentials, want) || rc.ModelCredential != "model" {
		t.Errorf("credentials %+v, model_credential %q", rc.Credentials, rc.ModelCredential)
	}
	for i, w := range [][]server.Apply{
		{{Hosts: []string{"api.model.example"}, Scheme: "bearer"}},
		{{Hosts: []string{"git.example"}, Scheme: "basic", Username: "x-access-token"}},
	} {
		if got := rc.Credentials[i].Applies(); !reflect.DeepEqual(got, w) {
			t.Errorf("%s applies to %+v; want %+v", rc.Credentials[i].Name, got, w)
		}
	}
	if rc.Computed != "sha256="+hex.EncodeToString(sum[:]) || rc.Computed == d {
		t.Errorf("computed %s, the header's %s", rc.Computed, d)
	}
	if b, _ := json.Marshal(rc); strings.Contains(string(b), "Computed") || strings.Contains(string(b), rc.Computed) {
		t.Errorf("the digest is written with the document: %s", b)
	}
}

// TestARunConfigurationsCredentialsAreRefused pins what Forager refuses of
// credentials, beside the schema, each run_configuration_invalid with the name: a name
// twice, a header that frames the request or that the proxy sets, in any case and
// with underscores for dashes, an endpoint whose host Forager does not read, and a
// model_credential that names a host credential. Two API credentials without a
// model_credential are refused with no name.
func TestARunConfigurationsCredentialsAreRefused(t *testing.T) {
	entry := func(name, header string) string {
		return `{"name":"` + name + `","apply":[{"hosts":["api.model.example"],"scheme":"header","header":"` + header + `"}]}`
	}
	cases := map[string]struct{ doc, want string }{
		"a name twice": {`{"version":1,"credentials":[` + entry("model", "x-api-key") + `,` + entry("model", "x-other-key") + `]}`, `list the credential "model" once; the document lists it twice`},
		"an endpoint's host": {`{"version":1,"credentials":[{"name":"model","format":"openai-chat","endpoint":"https://bad_host.example/v1","auth":{"scheme":"bearer"}}]}`,
			`give the credential "model" an endpoint whose host is a DNS name or an IP address, port 1 to 65535: Forager reads no host from its endpoint`},
		"an endpoint's port": {`{"version":1,"credentials":[{"name":"model","format":"openai-chat","endpoint":"https://api.model.example:99999","auth":{"scheme":"bearer"}}]}`,
			`give the credential "model" an endpoint whose host is a DNS name or an IP address, port 1 to 65535`},
		"a host credential as the start key": {`{"version":1,"credentials":[` + entry("model", "x-api-key") + `],"model_credential":"model"}`,
			`set model_credential to an API credential, one with format: the credential "model" has none, so it is no model key`},
	}
	for _, h := range []string{"Host", "content-length", "Transfer-Encoding", "Connection", "TE", "Trailer", "Upgrade", "Keep-Alive", "Cookie", "Proxy-Authorization", "proxy_authorization", "X-Qory-Credential-Set", "x_qory_credential_set", "Qory-Anything"} {
		cases["the header "+h] = struct{ doc, want string }{`{"version":1,"credentials":[` + entry("model", h) + `]}`, `set the credential "model" in another header than "` + h + `"; that header frames the request, or the proxy sets it`}
	}
	v := newVerified(t)
	for name, c := range cases {
		v.runDoc = c.doc
		_, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || len(r.Names) != 1 || r.Names[0] != "model" || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	api := func(name string) string {
		return `{"name":"` + name + `","format":"anthropic-messages","endpoint":"https://api.model.example","auth":{"scheme":"header","header":"x-api-key"}}`
	}
	v.runDoc = `{"version":1,"credentials":[` + api("model") + `,` + api("backup") + `]}`
	_, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
	if want := "set model_credential to the model key the runtime starts with: the document lists the model keys model, backup"; code(err) != "run_configuration_invalid" || !strings.Contains(err.Error(), want) {
		t.Errorf("two model keys without model_credential: %v; want %q", err, want)
	}
	for _, doc := range []string{
		`{"version":1,"credentials":[` + api("model") + `,` + api("backup") + `],"model_credential":"backup"}`,
		`{"version":1,"credentials":[` + api("model") + `]}`,
		`{"version":1,"credentials":[` + api("model") + `],"model_credential":"machine-model"}`,
	} {
		v.runDoc = doc
		if _, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID); err != nil {
			t.Errorf("%s: %v", doc, err)
		}
	}
	for _, h := range []string{"x-api-key", "Authorization", "X-Model-Key", "api_key"} {
		v.runDoc = `{"version":1,"credentials":[` + entry("model", h) + `]}`
		if _, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID); err != nil {
			t.Errorf("the header %s: %v", h, err)
		}
	}
}

// TestTheSecretsRequestIsSignedAndItsAnswerVerified pins Secrets: a signed POST of the
// body as given, the body of a signed 200 returned as it came, a signed refusal its
// code, an answer under another key answer_unsigned, and an answer over
// sealed.MaxAnswer refused.
func TestTheSecretsRequestIsSignedAndItsAnswerVerified(t *testing.T) {
	v := newVerified(t)
	body, err := server.SecretsRequest{Version: 1, RunID: runID, RunConfiguration: "sha256=" + strings.Repeat("a", 64), Credentials: []string{"model"}, Timestamp: 1}.Body()
	if err != nil {
		t.Fatal(err)
	}
	url := v.srv.URL + "/v1/secrets"
	v.secretsBody = `{"version":1}`
	got, err := v.client().Secrets(context.Background(), url, body)
	if err != nil || string(got) != `{"version":1}` || string(v.body) != string(body) {
		t.Errorf("%q %v; the request %s", got, err, v.body)
	}
	v.secretsStatus, v.secretsBody = 409, `{"error":"secrets_not_allowed"}`
	if _, err := v.client().Secrets(context.Background(), url, body); code(err) != "secrets_not_allowed" || !strings.Contains(err.Error(), "secrets "+url) {
		t.Errorf("a refusal: %v", err)
	}
	v.secretsStatus, v.secretsBody, v.sign = 0, `{"version":1}`, "other"
	if _, err := v.client().Secrets(context.Background(), url, body); code(err) != "answer_unsigned" {
		t.Errorf("another key: %v", err)
	}
	v.sign, v.secretsBody = "", strings.Repeat("x", sealed.MaxAnswer+1)
	if _, err := v.client().Secrets(context.Background(), url, body); err == nil {
		t.Error("an answer over the bound was read")
	}
}

// TestASecretsRequestOutsideItsFormIsNotSent pins Body's checks.
func TestASecretsRequestOutsideItsFormIsNotSent(t *testing.T) {
	ok := server.SecretsRequest{Version: 1, RunID: runID, RunConfiguration: "sha256=" + strings.Repeat("a", 64), Credentials: []string{"model"}}
	for name, c := range map[string]struct {
		change func(r *server.SecretsRequest)
		want   string
	}{
		"another run id": {func(r *server.SecretsRequest) { r.RunID = "not-a-run" },
			"report this bug in the gateway's secrets request to the Forager maintainers; the run id is not a UUID in the canonical lower-case form"},
		"another digest": {func(r *server.SecretsRequest) { r.RunConfiguration = "" },
			"report this bug in the gateway's secrets request to the Forager maintainers; the digest is not sha256= and 64 hex digits"},
		"no credential": {func(r *server.SecretsRequest) { r.Credentials = nil },
			"report this bug in the gateway's secrets request to the Forager maintainers; the request lists 0 credentials, and a request lists 1 to 8"},
		"nine": {func(r *server.SecretsRequest) { r.Credentials = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} },
			"report this bug in the gateway's secrets request to the Forager maintainers; the request lists 9 credentials, and a request lists 1 to 8"},
		"a name twice": {func(r *server.SecretsRequest) { r.Credentials = []string{"a", "a"} },
			"report this bug in the gateway's secrets request to the Forager maintainers; the request lists a credential twice"},
		"before 1970": {func(r *server.SecretsRequest) { r.Timestamp = -1 },
			"the secrets request: set this machine's clock to the right time; the timestamp is before 1970"},
	} {
		r := ok
		c.change(&r)
		if _, err := r.Body(); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if _, err := ok.Body(); err != nil {
		t.Error(err)
	}
}

// TestARefusedCredentialShowsNoSecretInItsName pins a refusal of a credential whose
// name contains qak_: the phrase in the text, and the phrase as the refusal's one name,
// which run.refused.schema.json's names accept.
func TestARefusedCredentialShowsNoSecretInItsName(t *testing.T) {
	const name = "x-qak_not-a-real-secret"
	entry := `{"name":"` + name + `","apply":[{"hosts":["api.model.example"],"scheme":"header","header":"Host"}]}`
	v := newVerified(t)
	for what, doc := range map[string]string{
		"a name twice":      `{"version":1,"credentials":[` + strings.Replace(entry, "Host", "x-api-key", 1) + `,` + strings.Replace(entry, "Host", "x-other", 1) + `]}`,
		"a reserved header": `{"version":1,"credentials":[` + entry + `]}`,
		"a placeholder":     `{"version":1,"credentials":[` + strings.Replace(entry, `"header":"Host"}]`, `"header":"x-api-key"}],"placeholders":["SSL_CERT_FILE"]`, 1) + `]}`,
	} {
		v.runDoc = doc
		_, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || !slices.Equal(r.Names, []string{"(a name that contains an access key secret)"}) ||
			strings.Contains(strings.ToLower(err.Error()), "qak_") || !strings.Contains(err.Error(), "(a name that contains an access key secret)") {
			t.Errorf("%s: %v, names %v", what, err, r)
			continue
		}
		validNames(t, r.Names)
	}
}

// TestAPlaceholderTheDenyListCoversIsRefused pins the placeholders of a credential from
// the server: one that an entry of denied-variables.json covers, a name or a pattern,
// case ignored, Forager's QORY_ names among them, is run_configuration_invalid with the
// credential's name; another is read. The header Expect is reserved as well.
func TestAPlaceholderTheDenyListCoversIsRefused(t *testing.T) {
	doc := func(placeholder string) string {
		return `{"version":1,"credentials":[{"name":"model","apply":[{"hosts":["api.model.example"],"scheme":"bearer"}],"placeholders":["MODEL_API_KEY","` + placeholder + `"]}]}`
	}
	v := newVerified(t)
	for _, p := range []string{"GIT_SSL_CAINFO", "git_ssl_cainfo", "HTTPS_PROXY", "no_proxy", "QORY_RUN_ID", "PATH", "NODE_OPTIONS", "ld_preload", "BASH_ENV", "HOME"} {
		v.runDoc = doc(p)
		_, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID)
		want := `the document is refused: give the credential "model" another placeholder than "` + p + `"; the built-in deny list, denied-variables.json, covers that variable`
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != "run_configuration_invalid" || len(r.Names) != 1 || r.Names[0] != "model" || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", p, err)
		}
	}
	for _, p := range []string{"ANTHROPIC_API_KEY", "PROXY_KEY", "MY_PATH"} {
		v.runDoc = doc(p)
		if _, _, err := v.client().RunConfiguration(context.Background(), v.srv.URL+"/v1/runs", runID); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if !server.ReservedHeader("Expect") || !server.ReservedHeader("expect") {
		t.Error("Expect is not reserved")
	}
}

// validNames fails the test unless names validate against run.refused.schema.json's
// names, which a link refusal's names refer to.
func validNames(t *testing.T, names []string) {
	t.Helper()
	schema, err := contracts.Compile("events/run.refused.schema.json#/properties/names")
	if err != nil {
		t.Fatal(err)
	}
	doc := make([]any, len(names))
	for i, n := range names {
		doc[i] = n
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("the names %q do not validate: %v", names, err)
	}
}

// TestASecretsURLWithASecretIsAPhrase pins Secrets' error for a secrets URL that
// contains qak_, a refusal and a failed transport: the value's phrase after "secrets"
// in place of the URL.
func TestASecretsURLWithASecretIsAPhrase(t *testing.T) {
	v := newVerified(t)
	body, err := server.SecretsRequest{Version: 1, RunID: runID, RunConfiguration: "sha256=" + strings.Repeat("a", 64), Credentials: []string{"model"}, Timestamp: 1}.Body()
	if err != nil {
		t.Fatal(err)
	}
	v.secretsStatus, v.secretsBody = 409, `{"error":"secrets_not_allowed"}`
	for what, url := range map[string]string{
		"a refusal":          v.srv.URL + "/v1/secrets?for=qak_not-a-real-secret",
		"a failed transport": "http://127.0.0.1:1/v1/secrets?for=qak_not-a-real-secret",
	} {
		_, err := v.client().Secrets(context.Background(), url, body)
		if err == nil || strings.Contains(strings.ToLower(err.Error()), "qak_") || !strings.HasPrefix(err.Error(), "secrets (a value that contains an access key secret)") {
			t.Errorf("%s: %v", what, err)
		}
	}
}
