package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
)

// homePlants are the files the probe writes in its HOME when PROBE_PLANT_HOME is 1, by
// their paths below HOME: a git configuration that runs programs of the agent's, a
// login shell's profile and a Python file under ~/.local that Python reads at its
// start.
var homePlants = map[string]string{
	".gitconfig": "[core]\n\tfsmonitor = /tmp/planted-fsmonitor\n\tsshCommand = /tmp/planted-ssh\n",
	".profile":   "/tmp/planted-profile\n",
	".local/lib/python3/site-packages/planted.pth": "import planted\n",
}

// agentHome is the HOME of both sessions of afterJoinFreshHome: /tmp, which every
// user can write in the images of the suite. In the suite's image HOME is / for the
// agent's user, and the engine makes a HOME the image lacks owned by root.
// plantedFile is the file the probe writes in the workspace when PROBE_PLANT_HOME is
// 1, with plantedLine in it. afterFile is the file the after join, a session with no
// runtime that joins after the last session, writes there.
const (
	agentHome   = "/tmp"
	plantedFile = "planted.txt"
	plantedLine = "session 1\n"
	afterFile   = "after.txt"
)

// plantReport is what the probe planted when PROBE_PLANT_HOME is 1: the home, the
// paths of homePlants that it then finds there, and the first write that failed.
type plantReport struct {
	Home  string   `json:"home"`
	Found []string `json:"found"`
	Err   string   `json:"err"`
}

// afterReport is what the after join finds: the paths of homePlants in its HOME, what
// plantedFile contains or why it could not be read, why the write of afterFile failed,
// and the status of a request through the run's proxy to PROBE_ALLOWED.
type afterReport struct {
	Home       string   `json:"home"`
	Found      []string `json:"found"`
	Planted    string   `json:"planted"`
	PlantedErr string   `json:"planted_err"`
	WriteErr   string   `json:"write_err"`
	Allowed    int      `json:"allowed"`
	AllowedErr string   `json:"allowed_err"`
}

// plantHome writes homePlants in HOME and plantedFile in the working directory, the
// workspace, then looks for homePlants as the after join does.
func plantHome() *plantReport {
	r := &plantReport{Home: os.Getenv("HOME")}
	if r.Home == "" {
		r.Err = "no HOME"
		return r
	}
	for p, content := range homePlants {
		at := filepath.Join(r.Home, p)
		if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
			r.Err = err.Error()
			return r
		}
		if err := os.WriteFile(at, []byte(content), 0o644); err != nil {
			r.Err = err.Error()
			return r
		}
	}
	if err := os.WriteFile(plantedFile, []byte(plantedLine), 0o644); err != nil {
		r.Err = err.Error()
		return r
	}
	r.Found = foundInHome(r.Home)
	return r
}

// foundInHome is the paths of homePlants that exist below home, sorted.
func foundInHome(home string) []string {
	var found []string
	for p := range homePlants {
		if _, err := os.Lstat(filepath.Join(home, p)); !errors.Is(err, fs.ErrNotExist) {
			found = append(found, p)
		}
	}
	slices.Sort(found)
	return found
}

// afterJoin is the program of the after join, a session with no runtime: it looks for
// homePlants in its HOME, reads plantedFile and writes afterFile in its working
// directory, the workspace, reaches PROBE_ALLOWED through the run's proxy, and prints
// its report.
func afterJoin() int {
	r := afterReport{Home: os.Getenv("HOME")}
	if r.Home != "" {
		r.Found = foundInHome(r.Home)
	}
	if b, err := os.ReadFile(plantedFile); err != nil {
		r.PlantedErr = err.Error()
	} else {
		r.Planted = string(b)
	}
	if err := os.WriteFile(afterFile, []byte("after\n"), 0o644); err != nil {
		r.WriteErr = err.Error()
	}
	r.Allowed, r.AllowedErr = get(os.Getenv("PROBE_ALLOWED"))
	b, _ := json.Marshal(r)
	fmt.Println(probePrefix + string(b))
	return 0
}

// afterJoinFreshHome checks a session with no runtime that joins after the last
// session, outside every step, as the step that sends a run's work does: the first
// session plants homePlants in its HOME and plantedFile in the workspace, and the
// session with no runtime finds none of homePlants in its HOME, reads plantedFile,
// writes afterFile and reaches the origin through the run's proxy. Both sessions have
// agentHome as HOME.
func afterJoinFreshHome(t *testing.T, o Options, h hosts, outside string) {
	t.Run("a session with no runtime after the last session has none of its HOME", func(t *testing.T) {
		runID := event.NewRunID()
		var after *session.Result
		var afterErr error
		var out, errs bytes.Buffer
		afterSession := func(run *session.Run, workspace string) {
			after, afterErr = run.Join(t.Context(), session.SessionSpec{
				Command: o.Probe,
				Args:    []string{modeAfterJoin},
				Env:     []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "PROBE_ALLOWED=" + h.origin, "HOME=" + agentHome},
				Dir:     workspace,
				Stdin:   strings.NewReader(""),
				Stdout:  &out,
				Stderr:  &errs,
				Exec:    o.Exec,
			})
		}
		r, err := runIn(t, o, variant{runID: runID, env: []string{"PROBE_PLANT_HOME=1", "HOME=" + agentHome}, afterSession: afterSession}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		all := slices.Sorted(maps.Keys(homePlants))
		if p := r.probe.Planted; p == nil || p.Err != "" || strings.Join(p.Found, " ") != strings.Join(all, " ") {
			t.Fatalf("the first session planted %+v; want %q found in its HOME", p, all)
		}
		if afterErr != nil || after == nil || after.ExitCode != 0 {
			t.Fatalf("the session with no runtime: %v, %+v\nstdout:\n%s\nstderr:\n%s", afterErr, after, out.String(), errs.String())
		}
		var a afterReport
		found := false
		for _, line := range strings.Split(out.String(), "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(line), probePrefix); ok {
				if err := json.Unmarshal([]byte(rest), &a); err != nil {
					t.Fatalf("the report of the session with no runtime: %v\n%s", err, rest)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("the session with no runtime reported nothing\nstdout:\n%s\nstderr:\n%s", out.String(), errs.String())
		}
		t.Logf("the session with no runtime: %+v", a)
		if a.Home != r.probe.Planted.Home || len(a.Found) != 0 {
			t.Errorf("the session with no runtime found %q in its HOME %s; want none in %s", a.Found, a.Home, r.probe.Planted.Home)
		}
		if a.Planted != plantedLine || a.PlantedErr != "" {
			t.Errorf("the session with no runtime read %q from %s (%s); want %q", a.Planted, plantedFile, a.PlantedErr, plantedLine)
		}
		if a.WriteErr != "" {
			t.Errorf("the write of %s in the workspace: %s", afterFile, a.WriteErr)
		}
		if b, err := os.ReadFile(filepath.Join(r.dir, afterFile)); err != nil || string(b) != "after\n" {
			t.Errorf("%s on this machine: %q, %v", afterFile, b, err)
		}
		if a.Allowed != 200 {
			t.Errorf("the origin through the run's proxy answered %d (%s); want 200", a.Allowed, a.AllowedErr)
		}
		// The sessions, and every host step: the session with no runtime joins outside
		// every step.
		hostKinds := []string{event.StepFetch, event.StepCompose, event.StepBuild, event.StepPush, event.StepMachine, event.StepCopy}
		var order []string
		for _, e := range r.events {
			d, _ := e["data"].(map[string]any)
			switch e["type"] {
			case event.SessionStarted:
				order = append(order, fmt.Sprintf("session %v started bare %v", d["session"], d["bare"]))
			case event.SessionExited:
				order = append(order, fmt.Sprintf("session %v exited", d["session"]))
			case event.StepStarted:
				if k, _ := d["kind"].(string); slices.Contains(hostKinds, k) {
					order = append(order, "step "+k)
				}
			}
		}
		want := []string{"session 1 started bare <nil>", "session 1 exited", "session 2 started bare true", "session 2 exited"}
		if !slices.Equal(order, want) {
			t.Errorf("the record has %q; want %q", order, want)
		}
		if o.Leftovers != nil {
			if left, err := o.Leftovers(runID); err != nil || len(left) != 0 {
				t.Errorf("the run left %v (%v)", left, err)
			}
		}
	})
}
