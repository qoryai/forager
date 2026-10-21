package session_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/wall"
)

// prepared is what the fake preparation writes into its working directory.
type prepared struct {
	Args     []string `json:"args"`
	Dir      string   `json:"dir"`
	RunID    string   `json:"run_id"`
	Variable string   `json:"variable"`
	Status   int      `json:"status"`
	Input    string   `json:"input"`
}

// fakePreparation is a run's preparation: it reaches FAKE_PREPARATION_URL through the
// proxy, writes what it was given and what it saw to prepared.json in its working
// directory, and exits with FAKE_PREPARATION_EXIT.
func fakePreparation() int {
	var p prepared
	p.Args = os.Args[1:]
	p.Dir, _ = os.Getwd()
	p.RunID = os.Getenv(session.EnvRunID)
	p.Variable = os.Getenv("PREP_VARIABLE")
	in, _ := io.ReadAll(os.Stdin)
	p.Input = string(in)
	if u := os.Getenv("FAKE_PREPARATION_URL"); u != "" {
		proxyURL, _ := url.Parse(os.Getenv("HTTP_PROXY"))
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
		if resp, err := client.Get(u); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			p.Status = resp.StatusCode
		}
	}
	b, _ := json.Marshal(p)
	if err := os.WriteFile("prepared.json", b, 0o644); err != nil {
		return 80
	}
	if os.Getenv("FAKE_PREPARATION_EXIT") == "6" {
		return 6
	}
	return 0
}

// preparedSpec is spec behind an open wall, with the workspace as its mount, and the
// runtime a shell line.
func preparedSpec(t *testing.T, line string, env ...string) runSpec {
	t.Helper()
	sp := spec(t, env...)
	sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", line}
	return sp
}

// awkward are words a shell would read otherwise if they were written into a script as
// they are.
var awkward = []string{"two words", "it's", `"double"`, "$HOME", "`touch backtick`", "$(touch dollar)", "a\nb", "'; touch quoted; '", "", "\\", "*"}

// TestThePreparationRunsBeforeTheRuntime pins a run's preparation: it runs before the
// runtime and after the runtime's preparation, in the run's working directory, with the
// runtime's environment and no input, through the run's proxy, with every word as
// given; the runtime then starts as it was prepared, with the run's input, and its exit
// is the run's. run.started has the preparation as given and the script as its command.
func TestThePreparationRunsBeforeTheRuntime(t *testing.T) {
	sp, g := specGateway(t, "FAKE_PREPARATION_URL=http://api.example/prepare")
	sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `cp prepared.json runtime-saw.json && cat > runtime-input; exit 5`}
	sp.Stdin = strings.NewReader("for the runtime\n")
	sp.Variables.Run = []string{"PREP_VARIABLE=from the run"}
	sp.Preparation = append([]string{"env", "FAKE_PREPARATION=1", os.Args[0]}, awkward...)
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 5 || res.State != "failed" {
		t.Errorf("result %+v", res)
	}
	b, err := os.ReadFile(filepath.Join(sp.Dir, "runtime-saw.json"))
	if err != nil {
		t.Fatalf("the runtime found no preparation: %v", err)
	}
	var p prepared
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Args, awkward) {
		t.Errorf("the preparation's words %q, want %q", p.Args, awkward)
	}
	dir, _ := filepath.EvalSymlinks(sp.Dir)
	if got, _ := filepath.EvalSymlinks(p.Dir); got != dir || p.RunID != res.RunID || p.Variable != "from the run" || p.Input != "" || p.Status != 200 {
		t.Errorf("the preparation saw %+v; the workspace is %s and the run %s", p, dir, res.RunID)
	}
	for _, name := range []string{"backtick", "dollar", "quoted"} {
		if _, err := os.Stat(filepath.Join(sp.Dir, name)); err == nil {
			t.Errorf("a word of the preparation ran as a command: %s", name)
		}
	}
	if in, _ := os.ReadFile(filepath.Join(sp.Dir, "runtime-input")); string(in) != "for the runtime\n" {
		t.Errorf("the runtime's input %q", in)
	}
	if got := g.Proxied(); len(got) == 0 || !strings.HasPrefix(got[0], "GET http://api.example/prepare ") {
		t.Errorf("the gateway's proxy saw %q", got)
	}
	evs := events(t, res)
	started := sessionStarted(t, evs)
	script := filepath.Join(res.Dir, session.PreparationScript)
	if started["command"] != "/bin/sh" || started["args"].([]any)[0] != script || started["args"].([]any)[1] != "/bin/sh" {
		t.Errorf("session.started command %v args %v", started["command"], started["args"])
	}
	want := make([]any, len(sp.Preparation))
	for i, w := range sp.Preparation {
		want[i] = w
	}
	if got, _ := started["preparation"].([]any); !slices.Equal(got, want) {
		t.Errorf("run.started preparation %q, want %q", started["preparation"], sp.Preparation)
	}
	if exited := ofType(evs, "dev.qory.run.exited"); len(exited) != 1 || data(exited[0])["exit_code"] != 5.0 {
		t.Errorf("run.exited %v", exited)
	}
}

// TestAFailedPreparationEndsTheRun pins that a preparation that exits otherwise than 0
// is the run's exit status, and the runtime never starts.
func TestAFailedPreparationEndsTheRun(t *testing.T) {
	sp := preparedSpec(t, "touch runtime-ran", "FAKE_PREPARATION_EXIT=6")
	sp.Preparation = []string{"env", "FAKE_PREPARATION=1", os.Args[0]}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 6 || res.State != "failed" || res.Reason != "" {
		t.Errorf("result %+v", res)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, "prepared.json")); err != nil {
		t.Errorf("the preparation did not run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, "runtime-ran")); err == nil {
		t.Error("the runtime started after a failed preparation")
	}
	exited := ofType(events(t, res), "dev.qory.run.exited")
	if len(exited) != 1 || data(exited[0])["exit_code"] != 6.0 || data(exited[0])["state"] != "failed" {
		t.Errorf("run.exited %v", exited)
	}
}

// TestAStopDuringThePreparationEndsTheRun pins that the session's stop reaches a
// preparation, as SIGTERM whatever the stop signal, well within a grace it would
// otherwise wait out, and that the runtime never starts.
func TestAStopDuringThePreparationEndsTheRun(t *testing.T) {
	for _, signal := range []string{"SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT", "SIGUSR1", "SIGUSR2"} {
		t.Run(signal, func(t *testing.T) {
			sp := preparedSpec(t, "touch runtime-ran")
			sp.Preparation = []string{"sleep", "30"}
			sp.Timeout = 300 * time.Millisecond
			sp.StopSignal = signal
			sp.StopGrace = 20 * time.Second
			start := time.Now()
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if took := time.Since(start); took > 10*time.Second {
				t.Errorf("the run took %s; the stop did not reach the preparation", took)
			}
			if !res.TimedOut || res.State != "cancelled" || res.Reason != "timeout" || res.ExitCode != 128+15 || res.Signal != "" {
				t.Errorf("result %+v", res)
			}
			if _, err := os.Stat(filepath.Join(sp.Dir, "runtime-ran")); err == nil {
				t.Error("the runtime started after a stop during the preparation")
			}
		})
	}
	// A preparation that ignores SIGTERM is killed at the end of the grace.
	sp := preparedSpec(t, "touch runtime-ran")
	sp.Preparation = []string{"/bin/sh", "-c", "trap '' TERM; sleep 30"}
	sp.Timeout = 200 * time.Millisecond
	sp.StopGrace = 300 * time.Millisecond
	start := time.Now()
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second || !res.TimedOut {
		t.Errorf("a preparation that ignores SIGTERM: result %+v after %s", res, took)
	}
}

// TestAPreparationNeedsAWallAndAProgram pins the specs of a preparation that are no run.
func TestAPreparationNeedsAWallAndAProgram(t *testing.T) {
	for name, c := range map[string]struct {
		walled      bool
		preparation []string
		want        string
	}{
		"no wall":       {false, []string{"true"}, "a preparation runs inside the wall, and the spec has no Wall"},
		"empty program": {true, []string{"", "x"}, "the preparation's program is empty"},
		"a NUL":         {true, []string{"true", "a\x00b"}, "the preparation holds a NUL, which no argument does"},
	} {
		t.Run(name, func(t *testing.T) {
			sp := preparedSpec(t, "touch runtime-ran")
			if !c.walled {
				sp.Wall, sp.Image, sp.Mounts = nil, "", nil
			}
			sp.Preparation = c.preparation
			if _, err := run(context.Background(), sp); err == nil || err.Error() != c.want {
				t.Errorf("error %v, want %q", err, c.want)
			}
			if _, err := os.Stat(filepath.Join(sp.Dir, "runtime-ran")); err == nil {
				t.Error("the runtime started")
			}
		})
	}
	// No preparation is no script.
	sp := preparedSpec(t, "exit 0")
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	started := sessionStarted(t, events(t, res))
	if _, ok := started["preparation"]; ok || started["command"] != "/bin/sh" || started["args"].([]any)[0] != "-c" {
		t.Errorf("session.started %v", started)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, session.PreparationScript)); err == nil {
		t.Error("a run without a preparation has its script")
	}
}
