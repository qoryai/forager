package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session"
)

// modeStep is the program of a step container, [stepProbe].
const modeStep = "step"

// stepReport is what the program of a step container found: the status of its request
// inside the suite's credential's paths, and the status and the body of its POST of
// artifacts to the run API.
type stepReport struct {
	Credential    int    `json:"credential"`
	CredentialErr string `json:"credential_err"`
	Push          int    `json:"push"`
	PushBody      string `json:"push_body"`
	PushErr       string `json:"push_err"`
}

// stepProbe requests the suite's credential's host inside its paths, trusting the run's
// bundle, and posts artifacts to the run API at its argument, both through the proxy of
// HTTP_PROXY, and prints a [stepReport] after probePrefix.
func stepProbe(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "step: give the run API's URL")
		return 2
	}
	proxyURL, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || proxyURL.Host == "" {
		fmt.Fprintln(os.Stderr, "step: HTTP_PROXY is", os.Getenv("HTTP_PROXY"))
		return 2
	}
	// The system's roots on Linux include the file of SSL_CERT_FILE, the run's bundle.
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: 30 * time.Second}
	var r stepReport
	if resp, err := client.Get("https://" + credentialHost + credentialPath); err != nil {
		r.CredentialErr = err.Error()
	} else {
		resp.Body.Close()
		r.Credential = resp.StatusCode
	}
	if resp, err := client.Post(args[0]+"/artifacts", "application/json", strings.NewReader(`{"artifacts":[]}`)); err != nil {
		r.PushErr = err.Error()
	} else {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		r.Push, r.PushBody = resp.StatusCode, string(b)
	}
	b, _ := json.Marshal(r)
	fmt.Println(probePrefix + string(b))
	return 0
}

// stepContainer checks a step container of a run with a control plane, before the join:
// it runs in the run's image; its request inside the suite's credential's paths is
// recorded with no credential; its POST of artifacts to the run API gets 403 with the
// code unprivileged; and the join after it runs.
func stepContainer(t *testing.T, o Options, h hosts, outside string) {
	const name = "a step container gets no credential and no run API"
	if !o.Setup {
		t.Run(name, func(t *testing.T) { t.Skip("the adapter starts no step container") })
		return
	}
	t.Run(name, func(t *testing.T) {
		runID := event.NewRunID()
		var res *session.StepResult
		var stepErr error
		step := func(run *session.Run, workspace string) {
			res, stepErr = run.RunStep(context.Background(), session.StepSpec{
				Name: "step probe/1", Command: []string{o.Probe, modeStep, link.RunAPIURL(runID)}, Dir: workspace, Timeout: time.Minute,
			})
		}
		r, err := runIn(t, o, variant{runID: runID, server: startRunAPIControl(t), beforeJoin: step}, false, h, outside)
		if err != nil || stepErr != nil {
			t.Fatalf("the step: %v; the run: %v", stepErr, err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("the step exited %d:\n%s", res.ExitCode, res.Output)
		}
		var p stepReport
		_, report, _ := strings.Cut(string(res.Output), probePrefix)
		if err := json.Unmarshal([]byte(strings.TrimSpace(report)), &p); err != nil {
			t.Fatalf("the step's report %q: %v", res.Output, err)
		}
		if p.Push != http.StatusForbidden || !strings.Contains(p.PushBody, `"unprivileged"`) {
			t.Errorf("the step's POST of artifacts: %d %s %s; want 403 unprivileged", p.Push, p.PushBody, p.PushErr)
		}
		var credential []string
		for _, e := range r.events {
			if d, _ := e["data"].(map[string]any); e["type"] == event.RunEgress && d["path"] == credentialPath {
				credential = append(credential, fmt.Sprint(d["credential"]))
			}
		}
		// The probe of the session after the step sends one request there too, with
		// the credential.
		if len(credential) != 2 || credential[0] != "<nil>" || credential[1] != "suite" {
			t.Errorf("the requests inside the credential's paths have the credentials %v; want none for the step's, then the session's; the step got %d (%s)", credential, p.Credential, p.CredentialErr)
		}
	})
}
