package gateway_test

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/sealed"
	"github.com/qoryai/forager/server"
)

// The run configuration of these tests: the server's policy selects the machine's
// credential machine-model, and its credentials have model, on the same host, whose
// value Qory Apiary seals.
const (
	sealedPolicy = `{"version":1,"egress":{"mode":"enforce","allow":["api.model.example"]},"credentials":[{"name":"machine-model"}]}`
	modelEntry   = `{"name":"model","hosts":["api.model.example"],"paths":["/v1/*"],"auth":{"scheme":"header","header":"x-api-key"},"key_form":"api_key","placeholders":["MODEL_API_KEY"]}`
	sealedDoc    = `{"version":1,"security_policy":` + sealedPolicy + `,"credentials":[` + modelEntry + `]}`
	sealedValue  = "sealed-value-of-the-test"
	machineValue = "machine-value-of-the-test"
)

// machineModel is the machine's credential, forager.yaml's key, for the same host.
var machineModel = gateway.Credential{Name: "machine-model", Env: "GATEWAY_TEST_MODEL_KEY", Hosts: []string{"api.model.example"}, Scheme: "header", Header: "x-api-key", Placeholders: []string{"MACHINE_KEY"}}

// sealedGateway is a gateway on the local link whose control serves doc and seals the
// values, values nil leaving the secrets endpoint out of discovery.
func sealedGateway(t *testing.T, doc string, values map[string]string) (*control, *harness) {
	t.Helper()
	t.Setenv("GATEWAY_TEST_MODEL_KEY", machineValue)
	c := newControl(t)
	c.serveDocument(doc, 'a')
	c.mu.Lock()
	c.secrets = values
	c.mu.Unlock()
	h := start(t, gateway.Config{Server: c.server(), Credentials: []gateway.Credential{machineModel}})
	h.secrets = append(h.secrets, sealedValue, machineValue)
	return c, h
}

// digestOf is sha256= and the hex SHA-256 of doc.
func digestOf(doc string) string {
	sum := sha256.Sum256([]byte(doc))
	return "sha256=" + hex.EncodeToString(sum[:])
}

// requests are the secrets requests the control was sent, decoded.
func (c *control) requests(t *testing.T) []server.SecretsRequest {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []server.SecretsRequest
	for _, b := range c.secretsRequests {
		var r server.SecretsRequest
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// TestASealedCredentialTakesThePlaceOfTheMachinesKey pins the start of a walled run
// whose run configuration has credentials: the gateway sends one secrets request, for
// the run, the digest it computed of the document's bytes, not the header's, and the
// credentials' names; the proxy sets the opened value in place of forager.yaml's key,
// whose credential claims the same host; and the run answer has model's hosts and
// placeholder, its key_form and its auth, and applied.credentials its key_form.
func TestASealedCredentialTakesThePlaceOfTheMachinesKey(t *testing.T) {
	c, h := sealedGateway(t, sealedDoc, map[string]string{"model": sealedValue})
	a := h.open(server.LinkRunRequest{Wall: true})
	if got, want := gateway.Tokens(h.g, a.RunID), map[string]string{"model": sealedValue}; !reflect.DeepEqual(got, want) {
		t.Errorf("the proxy sets %v, want %v", got, want)
	}
	reqs := c.requests(t)
	if len(reqs) != 1 {
		t.Fatalf("%d secrets requests, want 1", len(reqs))
	}
	c.mu.Lock()
	raw := c.secretsRequests[0]
	c.mu.Unlock()
	validDocument(t, "secrets-request.schema.json", raw)
	if r := reqs[0]; r.Version != 1 || r.RunID != a.RunID || r.RunConfiguration != digestOf(sealedDoc) || !slices.Equal(r.Credentials, []string{"model"}) {
		t.Errorf("the secrets request %+v; want the run, %s and model", r, digestOf(sealedDoc))
	}
	want := []server.LinkCredentialHosts{{Name: "model", Hosts: []string{"api.model.example"}, Placeholders: []string{"MODEL_API_KEY"},
		KeyForm: "api_key", Auth: &server.Auth{Scheme: "header", Header: "x-api-key"}}}
	if !reflect.DeepEqual(a.CredentialHosts, want) || !slices.Equal(a.Placeholders, []string{"MODEL_API_KEY"}) {
		t.Errorf("credential hosts %+v, placeholders %v; want %+v", a.CredentialHosts, a.Placeholders, want)
	}
	if got := members(a.Applied)["credentials"]; !reflect.DeepEqual(got, []any{map[string]any{"name": "model", "hosts": []any{"api.model.example"}, "scheme": "header", "paths": []any{"/v1/*"}, "key_form": "api_key"}}) {
		t.Errorf("applied credentials %v", got)
	}
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), exited(a.RunID))
	h.close()
}

// TestTheSessionsCredentialVariablesAreItsOwn pins that the gateway matches the
// session's policy_applied by the members the gateway decides alone: the session's
// variables, harness_hosts and credential_variables are left out of the comparison.
func TestTheSessionsCredentialVariablesAreItsOwn(t *testing.T) {
	decided := map[string]any{"mode": "observe", "allow": []any{}, "deny": []any{}, "source": "none"}
	data := map[string]any{"mode": "observe", "allow": []any{}, "deny": []any{}, "source": "none", "variables": []any{},
		"harness_hosts": []any{"harness.example"}, "credential_variables": []any{map[string]any{"credential": "model", "name": "ANTHROPIC_API_KEY"}}}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if !gateway.AppliedIs(decided)(&event.Event{Type: event.PolicyApplied, Data: json.RawMessage(raw)}) {
		t.Error("the gateway does not match a policy_applied with credential_variables")
	}
}

// TestARunConfigurationWithoutCredentialsIsUnchanged pins a run configuration with no
// credentials on a server that offers stored secrets: no secrets request, and the
// proxy sets forager.yaml's key as before.
func TestARunConfigurationWithoutCredentialsIsUnchanged(t *testing.T) {
	c, h := sealedGateway(t, `{"version":1,"security_policy":`+sealedPolicy+`}`, map[string]string{"model": sealedValue})
	a := h.open(server.LinkRunRequest{Wall: true})
	if got, want := gateway.Tokens(h.g, a.RunID), map[string]string{"machine-model": machineValue}; !reflect.DeepEqual(got, want) {
		t.Errorf("the proxy sets %v, want %v", got, want)
	}
	if reqs := c.requests(t); len(reqs) != 0 {
		t.Errorf("%d secrets requests, want none", len(reqs))
	}
	h.post(exited(a.RunID))
	h.close()
}

// TestCredentialsNeedAWall pins an unwalled run whose run configuration has
// credentials: wall_required with server_credentials, its text, and no secrets
// request.
func TestCredentialsNeedAWall(t *testing.T) {
	c, h := sealedGateway(t, sealedDoc, map[string]string{"model": sealedValue})
	var r *accesskey.Refusal
	if _, err := h.tryOpen(server.LinkRunRequest{}); !errors.As(err, &r) || r.Code != "wall_required" || r.Status != http.StatusForbidden || !slices.Equal(r.Names, []string{"server_credentials", "credentials"}) && !slices.Equal(r.Names, []string{"credentials", "server_credentials"}) {
		t.Errorf("no wall: %v", err)
	}
	want := "run it with a wall: the run configuration from Qory Apiary has credentials, and the gateway sets their values only for a run behind a wall"
	if _, got := h.refusalOf("/v1/run-configuration", openBody(event.NewRunID())); got["message"] != want {
		t.Errorf("wall_required's message %q", got["message"])
	}
	if reqs := c.requests(t); len(reqs) != 0 {
		t.Errorf("%d secrets requests, want none", len(reqs))
	}
}

// walledBody is a walled run request of a new run id.
func walledBody() string {
	return `{"version":1,"run_id":"` + event.NewRunID() + `","wall":true}`
}

// TestCredentialsNeedTheSecretsEndpoint pins a run configuration with credentials from
// a server whose discovery lists no secrets endpoint: run_configuration_invalid, a 403
// from the gateway, its text, and no secrets request.
func TestCredentialsNeedTheSecretsEndpoint(t *testing.T) {
	c, h := sealedGateway(t, sealedDoc, nil)
	status, got := h.refusalOf("/v1/run-configuration", walledBody())
	want := "run configuration " + c.srv.URL + runsPath + ": enrol an access key allowed stored secrets: the document has credentials, and Qory Apiary's configuration document lists no secrets endpoint for this access key: run_configuration_invalid"
	if status != http.StatusForbidden || got["error"] != "run_configuration_invalid" || got["message"] != want {
		t.Errorf("%d %v", status, got)
	}
	if reqs := c.requests(t); len(reqs) != 0 {
		t.Errorf("%d secrets requests, want none", len(reqs))
	}
}

// TestARefusedDocumentOpensNoRun pins the run configurations the gateway refuses as it
// reads them: a credential's name twice, and a header that frames the request or that
// the proxy sets; each run_configuration_invalid with the name, and no secrets request.
func TestARefusedDocumentOpensNoRun(t *testing.T) {
	for name, c := range map[string]struct{ doc, message string }{
		"a name twice": {`{"version":1,"credentials":[` + modelEntry + `,` + modelEntry + `]}`,
			`the document is refused: list the credential "model" once; the document lists it twice`},
		"Host": {`{"version":1,"credentials":[{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"header","header":"Host"}}]}`,
			`the document is refused: set the credential "model" in another header than "Host"; that header frames the request, or the proxy sets it`},
		"X-Qory-": {`{"version":1,"credentials":[{"name":"model","hosts":["api.model.example"],"auth":{"scheme":"header","header":"x_qory_credential_set"}}]}`,
			`the document is refused: set the credential "model" in another header than "x_qory_credential_set"; that header frames the request, or the proxy sets it`},
	} {
		t.Run(name, func(t *testing.T) {
			ctl, h := sealedGateway(t, c.doc, map[string]string{"model": sealedValue})
			status, got := h.refusalOf("/v1/run-configuration", walledBody())
			if status != http.StatusForbidden || got["error"] != "run_configuration_invalid" || !slices.Equal(anyStrings(got["names"]), []string{"model"}) ||
				!strings.Contains(got["message"].(string), c.message) {
				t.Errorf("%d %v; want the message %q", status, got, c.message)
			}
			if reqs := ctl.requests(t); len(reqs) != 0 {
				t.Errorf("%d secrets requests, want none", len(reqs))
			}
		})
	}
}

// TestASealedAnswerThatDoesNotOpenIsNoRun pins each refusal of the secrets answer: one
// that does not open, as sealed.Open refuses it, is run_configuration_invalid, one
// whose envelope is signed under another key answer_unsigned, the server's refusal
// passes on with its code, and a value a header cannot hold is
// run_configuration_invalid; each opens no run, and no message holds a value.
func TestASealedAnswerThatDoesNotOpenIsNoRun(t *testing.T) {
	other := mustGenerate()
	for name, c := range map[string]struct {
		answer  func(c *control, req server.SecretsRequest) (int, []byte)
		values  map[string]string
		status  int
		code    string
		message string
	}{
		"expired": {answer: func(c *control, req server.SecretsRequest) (int, []byte) {
			return http.StatusOK, c.seal(req, map[string]string{"model": sealedValue}, uint64(time.Now().Unix())-1000)
		}, status: http.StatusForbidden, code: "run_configuration_invalid", message: "set this machine's clock to the right time; the answer does not open: the envelope's exp is more than 300 seconds past"},
		"another digest": {answer: func(c *control, req server.SecretsRequest) (int, []byte) {
			req.RunConfiguration = "sha256=" + strings.Repeat("b", 64)
			return http.StatusOK, c.seal(req, map[string]string{"model": sealedValue}, sealed.Expiry(time.Now()))
		}, status: http.StatusForbidden, code: "run_configuration_invalid", message: "report this answer to whoever runs Qory Apiary; the answer does not open: the envelope is for another run configuration"},
		"other credentials": {answer: func(c *control, req server.SecretsRequest) (int, []byte) {
			req.Credentials = []string{"other"}
			return http.StatusOK, c.seal(req, map[string]string{"other": sealedValue}, sealed.Expiry(time.Now()))
		}, status: http.StatusForbidden, code: "run_configuration_invalid", message: "the plaintext lists other credentials than the request"},
		"another signer": {answer: func(c *control, req server.SecretsRequest) (int, []byte) {
			b, err := sealed.Seal(sealed.Sealing{AccessKeyID: testKey, PublicKey: c.accessKey.PublicKey(), RunID: req.RunID, RunConfiguration: req.RunConfiguration,
				Credentials: req.Credentials, Values: []sealed.Value{sealed.NewValue("model", []byte(sealedValue))}, Exp: sealed.Expiry(time.Now())}, other)
			if err != nil {
				panic(err)
			}
			return http.StatusOK, b
		}, status: http.StatusBadGateway, code: "answer_unsigned", message: "pin Qory Apiary's current signing key in apiary_public_key; the answer does not open: the envelope's sig does not verify under the pinned apiary_public_key"},
		"secrets_not_allowed": {answer: func(*control, server.SecretsRequest) (int, []byte) {
			return http.StatusConflict, []byte(`{"error":"secrets_not_allowed"}`)
		}, status: http.StatusConflict, code: "secrets_not_allowed", message: "secrets "},
		"a line feed": {values: map[string]string{"model": "a\nvalue"}, status: http.StatusForbidden, code: "run_configuration_invalid",
			message: `store another value of the credential "model" in Qory Apiary: its value has a control character, or a space or tab at its start or end, which a header value cannot have`},
		"a leading space": {values: map[string]string{"model": " " + sealedValue}, status: http.StatusForbidden, code: "run_configuration_invalid",
			message: "which a header value cannot have"},
	} {
		t.Run(name, func(t *testing.T) {
			values := c.values
			if values == nil {
				values = map[string]string{"model": sealedValue}
			}
			ctl, h := sealedGateway(t, sealedDoc, values)
			if c.answer != nil {
				ctl.mu.Lock()
				ctl.secretsAnswer = func(req server.SecretsRequest, _ string) (int, []byte) { return c.answer(ctl, req) }
				ctl.mu.Unlock()
			}
			status, got := h.refusalOf("/v1/run-configuration", walledBody())
			msg, _ := got["message"].(string)
			if status != c.status || got["error"] != c.code || !strings.Contains(msg, c.message) {
				t.Errorf("%d %v; want %d %s with %q", status, got, c.status, c.code, c.message)
			}
			for _, v := range values {
				if strings.Contains(msg, strings.TrimSpace(v)) {
					t.Errorf("the message holds a value: %s", msg)
				}
			}
			if n, _ := gateway.Held(h.g); n != 0 {
				t.Errorf("%d runs held", n)
			}
		})
	}
}

// TestAFixtureKeyGetsNoValue pins a pin, or an access key, that is a published fixture
// key: no secrets request, and run_configuration_invalid.
func TestAFixtureKeyGetsNoValue(t *testing.T) {
	keys := fixtureKeys(t)
	for name, c := range map[string]struct {
		accessKey, signer *accesskey.Key
		message           string
	}{
		"the pin":        {testAccessKey, keys.signer, "pin Qory Apiary's signing key: the server document's apiary_public_key lists a published fixture key, under which anyone can sign"},
		"the access key": {keys.accessKey, testSigner, "enrol another access key: this access key is a published fixture key, and anyone can open what is sealed to it"},
	} {
		t.Run(name, func(t *testing.T) {
			ctl := newControlWith(t, c.accessKey, c.signer)
			ctl.serveDocument(sealedDoc, 'a')
			ctl.mu.Lock()
			ctl.secrets = map[string]string{"model": sealedValue}
			ctl.mu.Unlock()
			t.Setenv("GATEWAY_TEST_MODEL_KEY", machineValue)
			h := start(t, gateway.Config{Server: ctl.server(), Credentials: []gateway.Credential{machineModel}})
			status, got := h.refusalOf("/v1/run-configuration", walledBody())
			if msg, _ := got["message"].(string); status != http.StatusForbidden || got["error"] != "run_configuration_invalid" || !strings.Contains(msg, c.message) {
				t.Errorf("%d %v", status, got)
			}
			if reqs := ctl.requests(t); len(reqs) != 0 {
				t.Errorf("%d secrets requests, want none", len(reqs))
			}
		})
	}
}

// fixture are the contract's published fixture keys: its access key and its signing
// key.
type fixture struct{ accessKey, signer *accesskey.Key }

func fixtureKeys(t *testing.T) fixture {
	t.Helper()
	var keys struct {
		AccessKey struct {
			Secret string `json:"secret"`
		} `json:"access_key"`
		SigningKey struct {
			Seed string `json:"seed"`
		} `json:"signing_key"`
	}
	b, err := fs.ReadFile(contracts.FS, "fixtures/known-answers/keys.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	access, err := accesskey.ParseSecret(keys.AccessKey.Secret)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base64.RawURLEncoding.DecodeString(keys.SigningKey.Seed)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := accesskey.NewKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{access, signer}
}

// TestAReloadKeepsTheCredentialsFixed pins a reload: one with the same credentials and
// another policy is put in force, and the proxy still sets the value opened at the
// start, with no second secrets request; one with other credentials fails, the user
// is told, and the policy and the value in force stay.
func TestAReloadKeepsTheCredentialsFixed(t *testing.T) {
	c, h := sealedGateway(t, sealedDoc, map[string]string{"model": sealedValue})
	a := h.open(server.LinkRunRequest{Wall: true})
	runID := a.RunID
	first := a.Digest
	if d := h.post(started(runID, nil), applied(runID, a.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}
	// The same credentials, and the policy allows one more host.
	c.serveDocument(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.model.example","b.example"]}},"credentials":[`+modelEntry+`]}`, 'b')
	h.post(logged(runID))
	var reloaded *server.LinkReloadAnswer
	eventually(t, "the reload", func() bool {
		h.post(heartbeat(runID))
		r, err := h.linkOf(runID).Reload(t.Context(), server.LocalOrigin+"/v1/run-configuration", runID)
		if err == nil && r.Digest != first {
			reloaded = r
			return true
		}
		return false
	})
	if got, want := gateway.Tokens(h.g, runID), map[string]string{"model": sealedValue}; !reflect.DeepEqual(got, want) {
		t.Errorf("after the reload the proxy sets %v, want %v", got, want)
	}
	if d := h.post(applied(runID, reloaded.Applied)); !d.Accepted() {
		t.Errorf("the reload's policy_applied: %+v", d)
	}
	// Other credentials: the hosts differ.
	c.serveDocument(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.model.example","c.example"]}},"credentials":[{"name":"model","hosts":["c.example"],"auth":{"scheme":"bearer"}}]}`, 'c')
	h.post(logged(runID))
	line := "start a new run to use other credentials; a run's credentials from Qory Apiary are fixed when it starts, and this run configuration has other credentials than the run started with; the policy in force stays"
	eventually(t, "the failed reload's report", func() bool {
		h.post(heartbeat(runID))
		return h.reported(line)
	})
	again, err := h.linkOf(runID).Reload(t.Context(), server.LocalOrigin+"/v1/run-configuration", runID)
	if err != nil || again.Digest != reloaded.Digest {
		t.Errorf("after a refused reload: %v %+v", err, again)
	}
	if got, want := gateway.Tokens(h.g, runID), map[string]string{"model": sealedValue}; !reflect.DeepEqual(got, want) {
		t.Errorf("after a refused reload the proxy sets %v, want %v", got, want)
	}
	if reqs := c.requests(t); len(reqs) != 1 {
		t.Errorf("%d secrets requests, want 1", len(reqs))
	}
	h.post(exited(runID))
	h.close()
}

// TestAnAttachedRunTakesItsCredentialsFromAReload pins a run behind a separate gateway:
// the attach answer's body has labels, so the gateway reloads the run configuration
// and sends the digest of the reload's bytes, and the proxy sets the opened value.
func TestAnAttachedRunTakesItsCredentialsFromAReload(t *testing.T) {
	t.Setenv("GATEWAY_TEST_MODEL_KEY", machineValue)
	c := gatewayControl(t)
	c.serveDocument(sealedDoc, 'a')
	c.mu.Lock()
	c.secrets = map[string]string{"model": sealedValue}
	c.attachLabels = map[string]string{"repository": "example/repo"}
	c.mu.Unlock()
	r := startRemote(t, c, gateway.Config{Credentials: []gateway.Credential{machineModel}})
	runID := event.NewRunID()
	before := c.fetches.Load()
	e := r.open(t, runKeyFor(t, runID, nil), server.LinkRunRequest{Wall: true})
	if got, want := gateway.Tokens(r.g, runID), map[string]string{"model": sealedValue}; !reflect.DeepEqual(got, want) {
		t.Errorf("the proxy sets %v, want %v", got, want)
	}
	reqs := c.requests(t)
	if len(reqs) != 1 || reqs[0].RunConfiguration != digestOf(sealedDoc) || reqs[0].RunID != runID {
		t.Errorf("the secrets requests %+v; want one for %s", reqs, digestOf(sealedDoc))
	}
	if n := c.fetches.Load() - before; n != 2 {
		t.Errorf("%d requests to the run endpoint, want the attach and one reload", n)
	}
	if got := e.post(t, exited(runID)); got.status != http.StatusAccepted {
		t.Errorf("the last batch: %d %s", got.status, got.body)
	}
}

// TestASealedKeyReachesATLSOrigin pins the value on the wire: through the run's proxy,
// a request to an HTTPS origin on this machine, whose certificate the proxy verifies,
// reaches it with the opened value in the credential's header, the session's stand-in
// replaced, when the node's policy names the origin's host; a TRACE gets the gateway's
// 403 and never reaches it. Without the node's policy, a name on this machine is not the
// server's to open, sealed credential or not: the dial is refused and the origin gets
// nothing.
func TestASealedKeyReachesATLSOrigin(t *testing.T) {
	for name, c := range map[string]struct {
		node    *gateway.Policy
		reached bool
	}{
		"the node's policy names localhost": {&gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"localhost"}}}, true},
		"no node's policy":                  {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			certFile, keyFile, roots := testCertificate(t, t.TempDir())
			pair, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var got []string
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				got = append(got, r.Method+" "+r.Header.Get("X-Api-Key"))
				mu.Unlock()
				io.WriteString(w, "origin")
			}))
			origin.Config.ErrorLog = log.New(io.Discard, "", 0)
			origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
			origin.StartTLS()
			defer origin.Close()
			_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())

			doc := `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["localhost"]}},"credentials":[{"name":"model","hosts":["localhost"],"auth":{"scheme":"header","header":"x-api-key"}}]}`
			ctl := newControl(t)
			ctl.serveDocument(doc, 'a')
			ctl.mu.Lock()
			ctl.secrets = map[string]string{"model": sealedValue}
			ctl.mu.Unlock()
			cfg := gateway.Config{Server: ctl.server(), Policy: c.node}
			gateway.SetUpstreamRoots(&cfg, roots)
			h := start(t, cfg)
			h.secrets = append(h.secrets, sealedValue)
			a := h.open(server.LinkRunRequest{Wall: true})

			trusted := x509.NewCertPool()
			trusted.AppendCertsFromPEM([]byte(a.CertificateAuthority))
			client := relay(h.g.Addr(), a.ProxySecret)
			client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: trusted}
			target := "https://localhost:" + port + "/v1/models"
			req, _ := http.NewRequest(http.MethodGet, target, nil)
			req.Header.Set("X-Api-Key", "stand-in")
			resp, err := client.Do(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			trace, _ := http.NewRequest("TRACE", target, nil)
			var traced *http.Response
			var traceBody []byte
			if c.reached {
				if traced, err = client.Do(trace); err != nil {
					t.Fatal(err)
				}
				traceBody, _ = io.ReadAll(traced.Body)
				traced.Body.Close()
			}
			mu.Lock()
			defer mu.Unlock()
			if c.reached {
				if resp == nil || resp.StatusCode != http.StatusOK || !slices.Equal(got, []string{"GET " + sealedValue}) {
					t.Errorf("the origin got %q; want the GET with the opened value once", got)
				}
				want := "qory: TRACE localhost/v1/models denied by the gateway: use another method; TRACE and TRACK send the request's headers back, and this host gets a credential from Qory Apiary\n"
				if traced.StatusCode != http.StatusForbidden || string(traceBody) != want {
					t.Errorf("the TRACE: %d %q", traced.StatusCode, traceBody)
				}
				return
			}
			if len(got) != 0 || (err == nil && resp.StatusCode == http.StatusOK) {
				t.Errorf("the origin got %q, the client %v", got, err)
			}
		})
	}
}

// TestARefusalAnswerShowsNoSecretInAName pins the gateway's answer to a run whose run
// configuration lists a credential whose name contains qak_ twice: no qak_ anywhere in
// the answer's body, its names included.
func TestARefusalAnswerShowsNoSecretInAName(t *testing.T) {
	entry := strings.Replace(modelEntry, `"name":"model"`, `"name":"x-qak_not-a-real-secret"`, 1)
	_, h := sealedGateway(t, `{"version":1,"credentials":[`+entry+`,`+entry+`]}`, map[string]string{"model": sealedValue})
	status, got := h.refusalOf("/v1/run-configuration", walledBody())
	b, _ := json.Marshal(got)
	if status != http.StatusForbidden || got["error"] != "run_configuration_invalid" || strings.Contains(strings.ToLower(string(b)), "qak_") {
		t.Errorf("%d %s", status, b)
	}
}

// TestASealedModelReplacesForagerYamlsModel pins the plan's case through the gateway:
// forager.yaml defines model on api.anthropic.com, the server's policy selects it, and
// the run configuration has its own model on the same host. The run opens, and the
// proxy sets the sealed value under the name model.
func TestASealedModelReplacesForagerYamlsModel(t *testing.T) {
	t.Setenv("GATEWAY_TEST_MODEL_KEY", machineValue)
	doc := `{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.anthropic.com"]},"credentials":[{"name":"model"}]},` +
		`"credentials":[{"name":"model","hosts":["api.anthropic.com"],"auth":{"scheme":"header","header":"x-api-key"},"placeholders":["ANTHROPIC_API_KEY"]}]}`
	c := newControl(t)
	c.serveDocument(doc, 'a')
	c.mu.Lock()
	c.secrets = map[string]string{"model": sealedValue}
	c.mu.Unlock()
	machine := gateway.Credential{Name: "model", Env: "GATEWAY_TEST_MODEL_KEY", Hosts: []string{"api.anthropic.com"}, Scheme: "header", Header: "x-api-key", Placeholders: []string{"ANTHROPIC_API_KEY"}}
	h := start(t, gateway.Config{Server: c.server(), Credentials: []gateway.Credential{machine}})
	h.secrets = append(h.secrets, sealedValue, machineValue)
	a := h.open(server.LinkRunRequest{Wall: true})
	if got, want := gateway.Tokens(h.g, a.RunID), map[string]string{"model": sealedValue}; !reflect.DeepEqual(got, want) {
		t.Errorf("the proxy sets %v, want %v", got, want)
	}
	h.post(started(a.RunID, nil), applied(a.RunID, a.Applied), exited(a.RunID))
	h.close()
}
