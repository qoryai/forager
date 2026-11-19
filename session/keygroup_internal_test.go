package session

import (
	"testing"

	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session/runtimes/claude"
)

// TestTheDefaultCredentialSetsItsGroupsPlaceholder pins the placeholder the session
// gives the runtime for the default model provider credential, from a run answer's
// credential_hosts of a model key of the machine's, in no group, and two key groups
// whose keys alternate: a with a-1 and a-2, b with b-1 and b-2. A key of a group sets
// the placeholder of the group's first key in that list, which is the one the proxy
// reads, and the machine's key sets its name's.
func TestTheDefaultCredentialSetsItsGroupsPlaceholder(t *testing.T) {
	rt, err := claude.New()
	if err != nil {
		t.Fatal(err)
	}
	key := func(name, group string) server.LinkCredentialHosts {
		return server.LinkCredentialHosts{Name: name, Hosts: []string{"api.model.example"}, Auth: &server.Auth{Scheme: "header", Header: "x-api-key"},
			Format: "anthropic-messages", Endpoint: "https://api.model.example/v1", Group: group}
	}
	creds := []server.LinkCredentialHosts{key("machine", ""), key("a-1", "a"), key("b-1", "b"), key("a-2", "a"), key("b-2", "b")}
	for model, first := range map[string]string{"machine": "machine", "a-1": "a-1", "a-2": "a-1", "b-1": "b-1", "b-2": "b-1"} {
		_, _, k, err := chosen(rt, false, creds, nil, model)
		if err != nil {
			t.Fatalf("%s: %v", model, err)
		}
		if want := "ANTHROPIC_API_KEY=" + link.KeyPlaceholder(first); k.Variable != want {
			t.Errorf("default model provider credential %s: the variable %q; want %q", model, k.Variable, want)
		}
	}
}
