package session_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/session/internal/socket"
	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/wall"
)

// prepared is what the fake setup command writes into its working directory.
type prepared struct {
	Args     []string `json:"args"`
	Dir      string   `json:"dir"`
	RunID    string   `json:"run_id"`
	Variable string   `json:"variable"`
	Status   int      `json:"status"`
	Input    string   `json:"input"`
}

// fakePreparation is a setup command: it reaches FAKE_PREPARATION_URL through the
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

// fakeSetupRecords is a setup command that writes the records of FAKE_SETUP_RECORDS,
// one JSON object per line, each the record member of a record of the setup source,
// to the socket, as code in the working folder can, and exits 0.
func fakeSetupRecords() int {
	var recs []runtimes.Record
	for _, line := range strings.Split(strings.TrimSpace(os.Getenv("FAKE_SETUP_RECORDS")), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 81
		}
		recs = append(recs, runtimes.Record{Source: runtimes.SourceSetup, Record: m})
	}
	if err := socket.Send(context.Background(), os.Getenv(session.EnvSocket), recs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 82
	}
	return 0
}

// setupRunner is the test binary as the setup runner.
var setupRunner = []string{os.Args[0], "setup-command"}

// preparedSpec is spec behind an open wall, with the workspace as its mount, the
// runtime a shell line, and the test binary as the setup runner.
func preparedSpec(t *testing.T, line string, env ...string) runSpec {
	t.Helper()
	sp := spec(t, env...)
	sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", line}
	sp.SetupRunner = setupRunner
	return sp
}

// awkward are words a shell would read otherwise if they were written into a script as
// they are.
var awkward = []string{"two words", "it's", `"double"`, "$HOME", "`touch backtick`", "$(touch dollar)", "a\nb", "'; touch quoted; '", "", "\\", "*"}

// step is one step of a run's record: its started and exited data, and the bytes of
// its run.log chunks by stream.
type step struct {
	started, exited map[string]any
	logs            map[string]string
	sessions        []any
}

// steps are the steps of evs by number, in the order they start.
func steps(t *testing.T, evs []map[string]any) []*step {
	t.Helper()
	var out []*step
	byNumber := map[float64]*step{}
	for _, e := range evs {
		d := data(e)
		switch e["type"] {
		case "dev.qory.run.step_started":
			s := &step{started: d, logs: map[string]string{}}
			byNumber[d["step"].(float64)] = s
			out = append(out, s)
		case "dev.qory.run.step_exited":
			byNumber[d["step"].(float64)].exited = d
		case "dev.qory.run.log":
			if n, ok := d["step"].(float64); ok {
				b, err := base64.StdEncoding.DecodeString(d["bytes"].(string))
				if err != nil {
					t.Fatal(err)
				}
				s := byNumber[n]
				s.logs[d["stream"].(string)] += string(b)
				s.sessions = append(s.sessions, d["session"])
			}
		}
	}
	return out
}

// TestSetupCommandsRunBeforeTheRuntime pins a session's setup commands: they run one
// after another before the runtime and after the runtime's preparation, in the run's
// working directory, with the runtime's environment and no input, through the run's
// proxy, with every word as given, each as one setup step after the wall step, named
// after the command, with its output as its lines and its exit status; the runtime then
// starts as it was prepared, with the run's input, and its exit is the run's.
// session.started has the commands' names and the script as its command.
func TestSetupCommandsRunBeforeTheRuntime(t *testing.T) {
	sp, g := specGateway(t, "FAKE_PREPARATION_URL=http://api.example/prepare")
	sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	sp.Forwarder = nil
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `cp prepared.json runtime-saw.json && cat > runtime-input; exit 5`}
	sp.Stdin = strings.NewReader("for the runtime\n")
	sp.Variables.Run = []string{"PREP_VARIABLE=from the run"}
	sp.SetupRunner = setupRunner
	sp.SessionSpec.Setup = []session.SetupCommand{
		{Name: "install", Args: append([]string{"env", "FAKE_PREPARATION=1", os.Args[0]}, awkward...)},
		{Name: "start services", Args: []string{"/bin/sh", "-c", `echo services started; printf 'a warning' >&2`}},
	}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 5 || res.State != "failed" {
		t.Errorf("result %+v", res)
	}
	b, err := os.ReadFile(filepath.Join(sp.Dir, "runtime-saw.json"))
	if err != nil {
		t.Fatalf("the runtime found nothing of the setup: %v", err)
	}
	var p prepared
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Args, awkward) {
		t.Errorf("the setup command's words %q, want %q", p.Args, awkward)
	}
	dir, _ := filepath.EvalSymlinks(sp.Dir)
	if got, _ := filepath.EvalSymlinks(p.Dir); got != dir || p.RunID != res.RunID || p.Variable != "from the run" || p.Input != "" || p.Status != 200 {
		t.Errorf("the setup command saw %+v; the workspace is %s and the run %s", p, dir, res.RunID)
	}
	for _, name := range []string{"backtick", "dollar", "quoted"} {
		if _, err := os.Stat(filepath.Join(sp.Dir, name)); err == nil {
			t.Errorf("a word of the setup command ran as a command: %s", name)
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
	script := filepath.Join(res.SessionDir, session.PreparationScript)
	if started["command"] != "/bin/sh" || started["args"].([]any)[0] != script || started["args"].([]any)[1] != "/bin/sh" {
		t.Errorf("session.started command %v args %v", started["command"], started["args"])
	}
	if got, _ := started["setup_commands"].([]any); !slices.Equal(got, []any{"install", "start services"}) {
		t.Errorf("session.started setup_commands %v, want install and start services", started["setup_commands"])
	}
	if _, ok := started["preparation"]; ok {
		t.Errorf("session.started has preparation: %v", started)
	}
	all := steps(t, evs)
	var kinds []string
	for i, s := range all {
		kinds = append(kinds, fmt.Sprint(s.started["kind"], " ", s.started["name"]))
		if s.started["step"] != float64(i+1) || s.exited == nil {
			t.Errorf("step %d: %+v", i+1, s)
		}
	}
	if want := []string{"join join session 1", "wall start the wall", "setup install", "setup start services"}; !slices.Equal(kinds, want) {
		t.Fatalf("the steps %q, want %q", kinds, want)
	}
	for _, s := range all[2:] {
		if s.exited["state"] != "succeeded" || s.exited["exit_code"] != 0.0 {
			t.Errorf("setup step %v exited %v", s.started["name"], s.exited)
		}
		for _, n := range s.sessions {
			if n != 1.0 {
				t.Errorf("a line of setup step %v has session %v", s.started["name"], n)
			}
		}
	}
	if all[2].logs["stdout"] != "" || all[2].logs["stderr"] != "" {
		t.Errorf("the install step's lines %q", all[2].logs)
	}
	if all[3].logs["stdout"] != "services started\n" || all[3].logs["stderr"] != "a warning" {
		t.Errorf("the start services step's lines %q", all[3].logs)
	}
	if exited := ofType(evs, "dev.qory.run.exited"); len(exited) != 1 || data(exited[0])["exit_code"] != 5.0 {
		t.Errorf("run.exited %v", exited)
	}
}

// TestASetupCommandsLinesReachTheTerminalOnceMasked pins that the run's masker replaces
// a forwarder's password in a setup command's lines, as in the runtime's output, and
// that each line reaches the user's terminal once, masked, and the session's and the
// run's output.log once: on pipes on the line's stream, and on a pseudo-terminal on
// stdout, each line break as \r\n.
func TestASetupCommandsLinesReachTheTerminalOnceMasked(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(fmt.Sprint("interactive ", interactive), func(t *testing.T) {
			sp := preparedSpec(t, "exit 0")
			var stdout, stderr syncBuffer
			sp.Stdout, sp.Stderr, sp.Interactive = &stdout, &stderr, interactive
			ctx := context.Background()
			r, err := session.Open(ctx, opened(sp))
			if err != nil {
				t.Fatal(err)
			}
			hp, err := r.HostProxy()
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(hp.ProxyURL)
			if err != nil {
				t.Fatal(err)
			}
			password, _ := u.User.Password()
			sp.SessionSpec.Setup = []session.SetupCommand{{Name: "install", Args: []string{"/bin/sh", "-c", `echo "the password is $0"; printf 'a warning\n' >&2`, password}}}
			res, err := r.Join(ctx, sp.SessionSpec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Close(ctx, session.Outcome{State: "succeeded"}); err != nil {
				t.Fatal(err)
			}
			line, warning := "the password is "+mask.ProxyPassword+"\n", "a warning\n"
			all := steps(t, events(t, res))
			if len(all) != 3 || all[2].logs["stdout"] != line || all[2].logs["stderr"] != warning {
				t.Errorf("the setup step's lines %+v", all[len(all)-1])
			}
			if interactive {
				if out := stdout.String(); strings.Count(out, "the password is "+mask.ProxyPassword+"\r\n") != 1 || strings.Count(out, "a warning\r\n") != 1 || stderr.String() != "" {
					t.Errorf("the terminal got %q on stdout and %q on stderr", out, stderr.String())
				}
			} else if stdout.String() != line || stderr.String() != warning {
				t.Errorf("the terminal got %q on stdout and %q on stderr", stdout.String(), stderr.String())
			}
			for _, f := range []string{filepath.Join(res.SessionDir, "output.log"), filepath.Join(res.Dir, "output.log")} {
				b, err := os.ReadFile(f)
				if err != nil || strings.Count(string(b), line) != 1 || strings.Count(string(b), warning) != 1 {
					t.Errorf("%s contains %q, %v; want each setup line once", f, b, err)
				}
			}
			for _, f := range []string{"session.jsonl", "output.log"} {
				if b, _ := os.ReadFile(filepath.Join(res.Dir, f)); strings.Contains(string(b), password) {
					t.Errorf("%s contains the host proxy's password", f)
				}
			}
			if strings.Contains(stdout.String()+stderr.String(), password) {
				t.Error("the terminal got the host proxy's password")
			}
		})
	}
}

// TestAFailedSetupCommandEndsTheRun pins that a setup command that exits otherwise than
// 0 ends its step failed with its exit status, and is the run's exit status: no later
// command and no runtime starts.
func TestAFailedSetupCommandEndsTheRun(t *testing.T) {
	sp := preparedSpec(t, "touch runtime-ran", "FAKE_PREPARATION_EXIT=6")
	sp.SessionSpec.Setup = []session.SetupCommand{
		{Name: "install", Args: []string{"env", "FAKE_PREPARATION=1", os.Args[0]}},
		{Name: "start services", Args: []string{"touch", "services-started"}},
	}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 6 || res.State != "failed" || res.Reason != "" {
		t.Errorf("result %+v", res)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, "prepared.json")); err != nil {
		t.Errorf("the setup command did not run: %v", err)
	}
	for _, name := range []string{"runtime-ran", "services-started"} {
		if _, err := os.Stat(filepath.Join(sp.Dir, name)); err == nil {
			t.Errorf("%s after a failed setup command", name)
		}
	}
	evs := events(t, res)
	all := steps(t, evs)
	if len(all) != 3 || all[2].started["name"] != "install" || all[2].exited["state"] != "failed" || all[2].exited["exit_code"] != 6.0 {
		t.Errorf("the steps %+v", all)
	}
	exited := ofType(evs, "dev.qory.run.exited")
	if len(exited) != 1 || data(exited[0])["exit_code"] != 6.0 || data(exited[0])["state"] != "failed" {
		t.Errorf("run.exited %v", exited)
	}
}

// TestASetupCommandThatIsNotFoundIsExitStatus127 pins that a setup command whose
// program the runner does not find ends its step failed with 127, the reason in its
// lines.
func TestASetupCommandThatIsNotFoundIsExitStatus127(t *testing.T) {
	sp := preparedSpec(t, "touch runtime-ran")
	sp.SessionSpec.Setup = []session.SetupCommand{{Name: "install", Args: []string{"no-such-program-anywhere"}}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	all := steps(t, events(t, res))
	if res.ExitCode != 127 || len(all) != 3 || all[2].exited["state"] != "failed" || all[2].exited["exit_code"] != 127.0 || !strings.Contains(all[2].logs["stderr"], "no-such-program-anywhere") {
		t.Errorf("result %+v; the setup step %+v", res, all[len(all)-1])
	}
}

// TestAStopDuringASetupCommandEndsTheRun pins that the session's stop reaches a setup
// command, as SIGTERM whatever the stop signal, well within a grace it would otherwise
// wait out, that its step ends cancelled, and that the runtime never starts.
func TestAStopDuringASetupCommandEndsTheRun(t *testing.T) {
	for _, signal := range []string{"SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT", "SIGUSR1", "SIGUSR2"} {
		t.Run(signal, func(t *testing.T) {
			sp := preparedSpec(t, "touch runtime-ran")
			sp.SessionSpec.Setup = []session.SetupCommand{{Name: "install", Args: []string{"sleep", "30"}}}
			sp.Timeout = 300 * time.Millisecond
			sp.StopSignal = signal
			sp.StopGrace = 20 * time.Second
			start := time.Now()
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			if took := time.Since(start); took > 10*time.Second {
				t.Errorf("the run took %s; the stop did not reach the setup command", took)
			}
			if !res.TimedOut || res.State != "cancelled" || res.Reason != "timeout" || res.ExitCode != 128+15 || res.Signal != "" {
				t.Errorf("result %+v", res)
			}
			if _, err := os.Stat(filepath.Join(sp.Dir, "runtime-ran")); err == nil {
				t.Error("the runtime started after a stop during the setup")
			}
			all := steps(t, events(t, res))
			if len(all) != 3 || all[2].exited["state"] != "cancelled" || all[2].exited["exit_code"] != float64(128+15) {
				t.Errorf("the steps %+v", all)
			}
		})
	}
	// A setup command that ignores SIGTERM is killed at the end of the grace, with its
	// runner: its step ends cancelled with -1.
	sp := preparedSpec(t, "touch runtime-ran")
	sp.SessionSpec.Setup = []session.SetupCommand{{Name: "install", Args: []string{"/bin/sh", "-c", "trap '' TERM; sleep 30"}}}
	sp.Timeout = 200 * time.Millisecond
	sp.StopGrace = 300 * time.Millisecond
	start := time.Now()
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second || !res.TimedOut {
		t.Errorf("a setup command that ignores SIGTERM: result %+v after %s", res, took)
	}
	all := steps(t, events(t, res))
	if len(all) != 3 || all[2].exited["state"] != "cancelled" || all[2].exited["exit_code"] != -1.0 {
		t.Errorf("the steps %+v", all)
	}
}

// TestSetupRecordsOutOfOrderAreNotRecorded pins that the session writes the setup steps
// only from records in order: a record for a command that is not the next, a second
// start while its step is open, a start of a command that exited with no step open,
// one that is not a setup record, and one after the setup ended are reported and
// change no step, as code in the working folder that writes them can.
func TestSetupRecordsOutOfOrderAreNotRecorded(t *testing.T) {
	forged := strings.Join([]string{
		`{"command": 1, "event": "started"}`,
		`{"command": 3, "event": "started"}`,
		`{"command": 2, "event": "exited", "exit_code": 0}`,
		`{"command": 9, "event": "line", "stream": "stdout", "bytes": "Zm9yZ2Vk"}`,
		`{"command": "one", "event": "started"}`,
		`{"command": 1, "event": "line", "stream": "terminal", "bytes": "Zm9yZ2Vk"}`,
		// With no step open: the exit closes command 1's step, a second start of
		// command 1 is out of order, and so is the runner's exit after it.
		`{"command": 1, "event": "exited", "exit_code": 0}`,
		`{"command": 1, "event": "started"}`,
	}, "\n")
	sp := preparedSpec(t, `FAKE_SETUP_RECORDS='{"command": 2, "event": "started"}' "$0"`, "FAKE_SETUP_RECORDS="+forged)
	sp.Args = append(sp.Args, os.Args[0])
	var reports []string
	var mu sync.Mutex
	sp.Report = func(l string) {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, l)
	}
	sp.SessionSpec.Setup = []session.SetupCommand{
		{Name: "install", Args: []string{os.Args[0]}},
		{Name: "start services", Args: []string{"true"}},
	}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Errorf("result %+v", res)
	}
	all := steps(t, events(t, res))
	var kinds []string
	for _, s := range all {
		kinds = append(kinds, fmt.Sprint(s.started["kind"], " ", s.started["name"], " ", s.exited["state"], " ", s.exited["exit_code"], " ", s.logs))
	}
	if want := []string{"join join session 1 succeeded -1 map[]", "wall start the wall succeeded -1 map[]", "setup install succeeded 0 map[]", "setup start services succeeded 0 map[]"}; !slices.Equal(kinds, want) {
		t.Errorf("the steps %q, want %q", kinds, want)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"a setup record for step 3 arrived out of order and is not recorded",
		"a setup record for step 5 arrived out of order and is not recorded",
		"a setup record for step 4 arrived out of order and is not recorded",
		"a setup record for step 11 arrived out of order and is not recorded",
		"socket: not a setup record: its command is not a number from 1",
		"socket: not a setup record: a line has stream stdout or stderr and its bytes in base64",
		"a setup record for step 3 arrived out of order and is not recorded",
		"a setup record for step 3 arrived out of order and is not recorded",
		"a setup record arrived after the setup ended and is not recorded",
	}
	var got []string
	for _, l := range reports {
		if strings.Contains(l, "setup record") {
			got = append(got, l)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("the reports %q, want %q", got, want)
	}
}

// TestSetupCommandsNeedAWallARunnerANameAndAProgram pins the specs of setup commands
// that are no run.
func TestSetupCommandsNeedAWallARunnerANameAndAProgram(t *testing.T) {
	for name, c := range map[string]struct {
		walled bool
		runner []string
		setup  []session.SetupCommand
		want   string
	}{
		"no wall":       {false, setupRunner, []session.SetupCommand{{Name: "install", Args: []string{"true"}}}, "Open the run with a wall to run its setup: setup runs in a container of the run's image."},
		"no runner":     {true, nil, []session.SetupCommand{{Name: "install", Args: []string{"true"}}}, "Set SessionSpec.SetupRunner to the command that runs one setup command, such as the helper's setup-command verb: SessionSpec.Setup runs each command through it."},
		"empty runner":  {true, []string{"", "x"}, []session.SetupCommand{{Name: "install", Args: []string{"true"}}}, "Set SessionSpec.SetupRunner to the command that runs one setup command, such as the helper's setup-command verb: SessionSpec.Setup runs each command through it."},
		"a NUL, runner": {true, []string{"runner", "a\x00b"}, []session.SetupCommand{{Name: "install", Args: []string{"true"}}}, "Remove the NUL from SessionSpec.SetupRunner: no argument contains one."},
		"no name":       {true, setupRunner, []session.SetupCommand{{Name: "install", Args: []string{"true"}}, {Args: []string{"true"}}}, `Give setup command 2 a name, such as "install".`},
		"no program":    {true, setupRunner, []session.SetupCommand{{Name: "install"}}, "Give setup command 1 a program: its first word is empty."},
		"empty program": {true, setupRunner, []session.SetupCommand{{Name: "install", Args: []string{"", "x"}}}, "Give setup command 1 a program: its first word is empty."},
		"a NUL":         {true, setupRunner, []session.SetupCommand{{Name: "install", Args: []string{"true", "a\x00b"}}}, "Remove the NUL from setup command 1: no argument contains one."},
		"a NUL, name":   {true, setupRunner, []session.SetupCommand{{Name: "in\x00stall", Args: []string{"true"}}}, "Remove the NUL from setup command 1: no argument contains one."},
	} {
		t.Run(name, func(t *testing.T) {
			sp := preparedSpec(t, "touch runtime-ran")
			if !c.walled {
				sp.Wall, sp.Image, sp.Mounts = nil, "", nil
			}
			sp.SetupRunner, sp.SessionSpec.Setup = c.runner, c.setup
			if _, err := run(context.Background(), sp); err == nil || err.Error() != c.want {
				t.Errorf("error %v, want %q", err, c.want)
			}
			if _, err := os.Stat(filepath.Join(sp.Dir, "runtime-ran")); err == nil {
				t.Error("the runtime started")
			}
		})
	}
	// No setup commands is no script, and no setup_commands.
	sp := preparedSpec(t, "exit 0")
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	started := sessionStarted(t, events(t, res))
	if _, ok := started["setup_commands"]; ok || started["command"] != "/bin/sh" || started["args"].([]any)[0] != "-c" {
		t.Errorf("session.started %v", started)
	}
	if _, err := os.Stat(filepath.Join(res.SessionDir, session.PreparationScript)); err == nil {
		t.Error("a run without setup commands has its script")
	}
}
