package gateway_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// shell writes a program of the test's, a shell script with body, into dir.
func shell(t *testing.T, dir, name, body string) string {
	t.Helper()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return file
}

// through is the status and the body of a GET of target through the run's proxy.
func through(t *testing.T, h *harness, a *server.LinkRunAnswer, target string) (int, string) {
	t.Helper()
	resp, err := relay(h.g.Addr(), a.ProxySecret).Get(target)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// members are the credentials, the tools and the terminated hosts of a run's applied.
func members(raw json.RawMessage) map[string]any {
	var all map[string]any
	json.Unmarshal(raw, &all)
	return map[string]any{"credentials": all["credentials"], "tools": all["tools"], "terminated": all["terminated"]}
}

// TestTheGatewayHoldsItsCopyOfTheCredentialsAndTools pins that the gateway holds the
// credentials and the tools of its Config as they are at Start: a change to the
// caller's definitions after Start, a host and a path replaced, a path appended, an
// adapter's program replaced, a tool's argument and host replaced, leaves a run that
// opened first, its reload after the change and a run that opens after the change as
// they are without the change. The adapter Start was given is the one asked, and its answer is
// held to the hosts and paths Start was given; the proxy refuses the paths those do
// not cover and hands the tool's host to the tool, started with its arguments; and
// applied and the record list the credentials and the tool as Start was given them.
func TestTheGatewayHoldsItsCopyOfTheCredentialsAndTools(t *testing.T) {
	t.Setenv("GATEWAY_TEST_SECRET", "s3cret-value-of-the-test")
	t.Setenv(envTool, "serve")
	dir := t.TempDir()
	marker := filepath.Join(dir, "other-ran")
	const answer = `echo '{"version":1,"token":"adapter-value-of-the-test","expires_at":"2099-01-01T00:00:00Z","apply":[{"hosts":["git.example"],"scheme":"bearer","paths":["/acme/*"]}]}'` + "\n"
	adapter := shell(t, dir, "adapter", answer)
	other := shell(t, dir, "other", "touch '"+marker+"'\n"+answer)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	creds := []gateway.Credential{
		{Name: "api", Env: "GATEWAY_TEST_SECRET", Hosts: []string{"api.example"}, Scheme: "bearer", Paths: []string{"/v1/*"}},
		{Name: "repo", Adapter: []string{adapter}, Hosts: []string{"git.example"}, Paths: []string{"/acme/*"}},
	}
	tools := []gateway.Tool{{Name: "svc", Command: []string{exe, "first"}, Serves: []string{"svc.example"}}}
	const selects = `"credentials":[{"name":"api"},{"name":"repo"}],"tools":[{"name":"svc"}]`
	c := newControl(t)
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["*.example"]},`+selects+`}`, 'a')
	h := start(t, gateway.Config{Server: c.server(), Credentials: creds, Tools: tools})
	h.secrets = append(h.secrets, "s3cret-value-of-the-test", "adapter-value-of-the-test")
	earlier := h.open(server.LinkRunRequest{Wall: true})
	h.mu.Lock()
	first := h.digests[len(h.digests)-1].RunConfiguration
	h.mu.Unlock()
	if d := h.post(started(earlier.RunID, nil), applied(earlier.RunID, earlier.Applied)); !d.Accepted() {
		t.Fatalf("the first batch: %+v", d)
	}

	creds[0].Hosts[0] = "other.example"
	creds[0].Paths[0] = "/x/*"
	creds[0].Paths = append(creds[0].Paths, "/y/*")
	creds[1].Adapter[0] = other
	creds[1].Hosts[0] = "elsewhere.example"
	creds[1].Paths = append(creds[1].Paths, "/other/*")
	tools[0].Command[1] = "moved"
	tools[0].Serves[0] = "moved.example"

	later := h.open(server.LinkRunRequest{Wall: true})
	if d := h.post(started(later.RunID, nil), applied(later.RunID, later.Applied)); !d.Accepted() {
		t.Fatalf("the later run's batch: %+v", d)
	}
	c.serve(`{"version":1,"egress":{"mode":"enforce","allow":["*.example","b.example"]},`+selects+`}`, 'b')
	eventually(t, "the reload", func() bool {
		d := h.post(heartbeat(earlier.RunID))
		return d.Accepted() && d.Digests.RunConfiguration != first
	})
	reloaded, err := h.linkOf(earlier.RunID).Reload(context.Background(), server.LocalOrigin+"/v1/run-configuration", earlier.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if d := h.post(applied(earlier.RunID, reloaded.Applied)); !d.Accepted() {
		t.Errorf("the reload's policy_applied: %+v", d)
	}

	want := map[string]any{
		"credentials": []any{
			map[string]any{"name": "api", "hosts": []any{"api.example"}, "scheme": "bearer", "paths": []any{"/v1/*"}},
			map[string]any{"name": "repo", "hosts": []any{"git.example"}, "scheme": "bearer", "paths": []any{"/acme/*"}},
		},
		"tools":      []any{map[string]any{"name": "svc", "hosts": []any{"svc.example"}}},
		"terminated": []any{"api.example", "git.example", "svc.example"},
	}
	for name, raw := range map[string]json.RawMessage{"the earlier run": earlier.Applied, "its reload": reloaded.Applied, "the later run": later.Applied} {
		if got := members(raw); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: applied %v, want %v", name, got, want)
		}
	}
	for name, a := range map[string]*server.LinkRunAnswer{"the earlier run": earlier, "the later run": later} {
		if code, body := through(t, h, a, "http://svc.example/p"); code != http.StatusOK || body != "first /p" {
			t.Errorf("%s: the tool's host answered %d %q, want the tool started with its first argument", name, code, body)
		}
		for _, target := range []string{"http://api.example/x/1", "http://api.example/y/1", "http://git.example/other/1"} {
			if code, body := through(t, h, a, target); code != http.StatusForbidden {
				t.Errorf("%s: %s answered %d %q, want the proxy's refusal", name, target, code, body)
			}
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Errorf("the program the caller put in place of the adapter ran: %v", err)
	}

	h.post(exited(earlier.RunID))
	h.post(exited(later.RunID))
	h.close()
	for name, runID := range map[string]string{"the earlier run": earlier.RunID, "the later run": later.RunID} {
		n := 0
		refused := map[string]bool{}
		for _, ev := range h.record(runID) {
			if ev.Type == event.RunEgress && ev.Data["decision"] == "denied" && ev.Data["path"] != nil {
				refused[fmt.Sprint(ev.Data["host"], ev.Data["path"])] = true
			}
			if ev.Type == event.PolicyApplied {
				n++
				if got := map[string]any{"credentials": ev.Data["credentials"], "tools": ev.Data["tools"], "terminated": ev.Data["terminated"]}; !reflect.DeepEqual(got, want) {
					t.Errorf("%s: the record's policy_applied %d: %v", name, n, ev.Data)
				}
			}
		}
		if n == 0 {
			t.Errorf("%s: the record holds no policy_applied", name)
		}
		// Each refusal is a path's: the host's path rules decided it.
		for _, path := range []string{"api.example/x/1", "api.example/y/1", "git.example/other/1"} {
			if !refused[path] {
				t.Errorf("%s: the record holds no path refusal of %s, but %v", name, path, refused)
			}
		}
	}
}

// TestARunHoldsTheCredentialsAndToolsStartChecked pins that a run holds the definitions
// Start checked: the caller's change after Start of a credential's scheme and
// placeholder and a tool's program and host to values the check refuses leaves the run
// with the scheme, the placeholder, the program and the host Start checked.
func TestARunHoldsTheCredentialsAndToolsStartChecked(t *testing.T) {
	t.Setenv("GATEWAY_TEST_SECRET", "s3cret-value-of-the-test")
	t.Setenv(envTool, "serve")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	creds := []gateway.Credential{{Name: "api", Env: "GATEWAY_TEST_SECRET", Hosts: []string{"api.example"}, Scheme: "bearer", Placeholders: []string{"API_TOKEN"}}}
	tools := []gateway.Tool{{Name: "svc", Command: []string{exe, "first"}, Serves: []string{"svc.example"}}}
	h := start(t, gateway.Config{
		Credentials: creds, Tools: tools,
		Policy: &gateway.Policy{Version: 1, Egress: gateway.PolicyEgress{Mode: "enforce", Allow: []string{"api.example", "svc.example"}},
			Credentials: []gateway.PolicyCredential{{Name: "api"}}, Tools: []gateway.PolicyTool{{Name: "svc"}}},
	})
	h.secrets = append(h.secrets, "s3cret-value-of-the-test")

	creds[0].Scheme = "digest"
	creds[0].Placeholders[0] = "not a variable"
	tools[0].Command[0] = ""
	tools[0].Serves[0] = "Not A Host"
	if creds[0].Check() == nil || tools[0].Check() == nil {
		t.Fatal("the check takes the caller's changed definitions")
	}

	a := h.open(server.LinkRunRequest{Wall: true})
	if !slices.Equal(a.Placeholders, []string{"API_TOKEN"}) {
		t.Errorf("placeholders %v", a.Placeholders)
	}
	want := map[string]any{
		"credentials": []any{map[string]any{"name": "api", "hosts": []any{"api.example"}, "scheme": "bearer"}},
		"tools":       []any{map[string]any{"name": "svc", "hosts": []any{"svc.example"}}},
		"terminated":  []any{"api.example", "svc.example"},
	}
	if got := members(a.Applied); !reflect.DeepEqual(got, want) {
		t.Errorf("applied %v, want %v", got, want)
	}
	if code, body := through(t, h, a, "http://svc.example/p"); code != http.StatusOK || body != "first /p" {
		t.Errorf("the tool's host answered %d %q, want the tool Start checked", code, body)
	}
	h.post(exited(a.RunID))
	h.close()
}
