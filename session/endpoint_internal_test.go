package session

import (
	"testing"

	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/runtimes"
)

// TestAnEndpointSettingSetsNoVariable pins that the start key of a runtime whose
// descriptor has its model endpoint in a setting sets no endpoint variable: the key's
// variable gets its placeholder, and keyed.Endpoint stays empty, where a runtime whose
// endpoint is a variable gets VARIABLE=<endpoint>.
func TestAnEndpointSettingSetsNoVariable(t *testing.T) {
	described := func(endpoint string) runtimes.Runtime {
		t.Helper()
		d := "version: 1\nruntime: r\nruntime_version: \"1\"\nsources:\n  output: {format: jsonl}\n" +
			"model:\n  formats: [openai-responses]\n  model: {flag: --model}\n  endpoint: " + endpoint + "\n" +
			"  keys: [{format: openai-responses, auth: {scheme: bearer}, variable: R_API_KEY}]\n" +
			"rules:\n  - source: output\n    match: {type: start}\n    type: dev.qory.runtime.started\n    data: {session_id: session_id}\n"
		rt, err := runtimes.Described("r.yaml", []byte(d), nil)
		if err != nil {
			t.Fatal(err)
		}
		return rt
	}
	creds := []server.LinkCredentialHosts{{Name: "model", Hosts: []string{"api.model.example"},
		Auth: &server.Auth{Scheme: "bearer"}, Format: "openai-responses", Endpoint: "https://api.model.example/v1"}}
	for _, c := range []struct{ endpoint, want string }{
		{"{setting: providers.r.base_url}", ""},
		{"{variable: R_BASE_URL}", "R_BASE_URL=https://api.model.example/v1"},
	} {
		_, _, key, err := chosen(described(c.endpoint), false, creds, nil, "")
		if err != nil {
			t.Fatalf("%s: %v", c.endpoint, err)
		}
		if key.Endpoint != c.want || key.Variable == "" || key.endpointName() != (map[bool]string{true: "R_BASE_URL"})[c.want != ""] {
			t.Errorf("%s: key %+v; want Endpoint %q and a Variable", c.endpoint, key, c.want)
		}
	}
}
