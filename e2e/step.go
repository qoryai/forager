package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// modeStep is the program of a step container, [stepProbe], modeStepBinds the program
// of one with binds below its working folder, [stepBindsProbe], and stepProbeDir the
// path in the step container of the folder with a copy of the helper.
const (
	modeStep      = "step"
	modeStepBinds = "step-binds"
	stepProbeDir  = "/opt/step-probe"
)

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

// stepBindsReport is what the program of a step container found of the folder at its
// argument, a writable mount below the working folder with the read-only mount
// check.txt in it: the error of a write to check.txt, of a write of other.txt beside
// it, and of the rename of the folder, empty for none.
type stepBindsReport struct {
	WriteLocked string `json:"write_locked"`
	WriteOther  string `json:"write_other"`
	Rename      string `json:"rename"`
}

// stepBindsProbe writes check.txt and other.txt in the folder at its argument, renames
// the folder, and prints a [stepBindsReport] after probePrefix.
func stepBindsProbe(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "step-binds: give the folder")
		return 2
	}
	text := func(err error) string {
		if err == nil {
			return ""
		}
		return err.Error()
	}
	dir := args[0]
	r := stepBindsReport{
		WriteLocked: text(os.WriteFile(filepath.Join(dir, "check.txt"), []byte("changed\n"), 0o666)),
		WriteOther:  text(os.WriteFile(filepath.Join(dir, "other.txt"), []byte("written\n"), 0o666)),
		Rename:      text(os.Rename(dir, dir+"-moved")),
	}
	b, _ := json.Marshal(r)
	fmt.Println(probePrefix + string(b))
	return 0
}

// stepContainer checks a step container of a run with a control plane, before the join:
// it runs in the run's image; its request inside the suite's credential's paths is
// recorded with no credential; its POST of artifacts to the run API gets 403 with the
// code unprivileged; and the join after it runs. The wall mounts no helper in a step
// container, so the step mounts o.Install, which has a copy of the helper at
// bin/claude, read-only at stepProbeDir, as a caller mounts a program of its own. A
// second step mounts the folder checks below its working folder, writable, and
// checks/check.txt read-only: the step cannot write check.txt or rename checks, and
// writes other.txt beside them.
func stepContainer(t *testing.T, o Options, h hosts, outside string) {
	const name = "a step container gets no credential and no run API"
	if !o.Setup {
		t.Run(name, func(t *testing.T) { t.Skip("the adapter starts no step container") })
		return
	}
	t.Run(name, func(t *testing.T) {
		runID := event.NewRunID()
		var res, binds *session.StepResult
		var stepErr, bindsErr error
		var checks string
		step := func(run *session.Run, workspace string) {
			probe := wall.Mount{Path: o.Install, ReadOnly: true, Target: stepProbeDir}
			res, stepErr = run.RunStep(context.Background(), session.StepSpec{
				Name: "step probe/1", Command: []string{stepProbeDir + "/bin/claude", modeStep, link.RunAPIURL(runID)}, Dir: workspace, Timeout: time.Minute,
				Mounts: []wall.Mount{probe},
			})
			// The modes leave the read-only bind as the one reason a write of check.txt
			// can fail.
			checks = filepath.Join(workspace, "checks")
			if err := os.Mkdir(checks, 0o777); err != nil {
				bindsErr = err
				return
			}
			if err := os.Chmod(checks, 0o777); err != nil {
				bindsErr = err
				return
			}
			if err := os.WriteFile(filepath.Join(checks, "check.txt"), []byte("locked\n"), 0o666); err != nil {
				bindsErr = err
				return
			}
			if err := os.Chmod(filepath.Join(checks, "check.txt"), 0o666); err != nil {
				bindsErr = err
				return
			}
			binds, bindsErr = run.RunStep(context.Background(), session.StepSpec{
				Name: "step probe/2", Command: []string{stepProbeDir + "/bin/claude", modeStepBinds, "checks"}, Dir: workspace, Timeout: time.Minute,
				Mounts: []wall.Mount{probe, {Path: checks}, {Path: filepath.Join(checks, "check.txt"), ReadOnly: true}},
			})
		}
		r, err := runIn(t, o, variant{runID: runID, server: startRunAPIControl(t), beforeJoin: step}, false, h, outside)
		if err != nil || stepErr != nil {
			t.Fatalf("the step: %v; the run: %v", stepErr, err)
		}
		t.Run("a read-only mount below the working folder stays read-only", func(t *testing.T) {
			if bindsErr != nil {
				t.Fatalf("the step: %v", bindsErr)
			}
			if binds.ExitCode != 0 {
				t.Fatalf("the step exited %d:\n%s", binds.ExitCode, binds.Output)
			}
			var p stepBindsReport
			_, report, _ := strings.Cut(string(binds.Output), probePrefix)
			if err := json.Unmarshal([]byte(strings.TrimSpace(report)), &p); err != nil {
				t.Fatalf("the step's report %q: %v", binds.Output, err)
			}
			if p.WriteLocked == "" || p.WriteOther != "" || p.Rename == "" {
				t.Errorf("the step's writes: %+v; want check.txt and the rename refused, other.txt written", p)
			}
			if b, err := os.ReadFile(filepath.Join(checks, "check.txt")); err != nil || string(b) != "locked\n" {
				t.Errorf("check.txt after the step: %q, %v", b, err)
			}
			if b, err := os.ReadFile(filepath.Join(checks, "other.txt")); err != nil || string(b) != "written\n" {
				t.Errorf("other.txt after the step: %q, %v", b, err)
			}
		})
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
