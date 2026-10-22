package session_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/session"
	"github.com/qoryai/forager/sink"
)

// implementSkill, reviewSkill and implementPlan are the texts of the example
// harness's three files, at skills/implement/SKILL.md, skills/review/SKILL.md and
// skills/implement/plan.md in its home. implementPlan is one line of 280 characters,
// which the session keeps back at the end of a stream.
const (
	implementSkill = `# Implement

1. Read the work item and list each thing to build.
2. Write a test for each item on the list.
3. Change the code until every test passes.
4. Run the checks the workspace defines.
`
	reviewSkill = `# Review

- Read the diff from its first line to its last.
- Run each test the change adds, and the suite.
- List each defect with its file and line.
`
	implementPlan = "Plan: read the work item, list each thing to build, write a test for each item on the list, change the code until every test passes, run the checks the workspace defines, write what changed in the change log, and ask a second reader for a review of the change before it is merged.\n"
	implementPut  = "[harness text: skills/implement/SKILL.md]"
	reviewPut     = "[harness text: skills/review/SKILL.md]"
	planPut       = "[harness text: skills/implement/plan.md]"
)

// harnessLines are lines of the example harness that no event and no output.log of a
// run whose harness is hidden contains.
var harnessLines = []string{"Change the code until every test passes.", "Run each test the change adds, and the suite.", "ask a second reader for a review"}

// harnessHome writes the example harness into a temporary directory and returns it.
func harnessHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for p, text := range map[string]string{"skills/implement/SKILL.md": implementSkill, "skills/review/SKILL.md": reviewSkill, "skills/implement/plan.md": implementPlan} {
		f := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// harnessScript is the runtime's script of the tests of this file: it prints the
// implement skill as cat does, a result record whose result is the review skill, the
// review skill in two writes apart by a pause, writes changed text into the implement
// skill and prints it, and prints the plan last.
const harnessScript = `cat "$QORY_HARNESS_HOME/skills/implement/SKILL.md"
printf '{"type":"result","subtype":"success","session_id":"fake","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.01,"result":"%s"}\n' "$(awk '{printf "%s\\n", $0}' "$QORY_HARNESS_HOME/skills/review/SKILL.md")"
head -c 70 "$QORY_HARNESS_HOME/skills/review/SKILL.md"
sleep 0.3
tail -c +71 "$QORY_HARNESS_HOME/skills/review/SKILL.md"
printf 'Changed line one of the skill.\nChanged line two of the skill.\nChanged line three of the skill.\n' > "$QORY_HARNESS_HOME/skills/implement/SKILL.md"
cat "$QORY_HARNESS_HOME/skills/implement/SKILL.md"
cat "$QORY_HARNESS_HOME/skills/implement/plan.md"
`

// harnessRun runs the script of the tests of this file with the example harness's
// home, hidden or not, and returns the result, output.log and the run.log chunks.
func harnessRun(t *testing.T, hidden bool) (*session.Result, string, []string) {
	t.Helper()
	sp := spec(t)
	sp.Forwarder = nil
	sp.HarnessHome, sp.HarnessHidden = harnessHome(t), hidden
	sp.Command, sp.Args = "/bin/sh", []string{"-c", harnessScript}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(filepath.Join(res.Dir, sink.OutputFile))
	var chunks []string
	for _, l := range ofType(events(t, res), event.RunLog) {
		b, err := base64.StdEncoding.DecodeString(data(l)["bytes"].(string))
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, string(b))
	}
	return res, string(out), chunks
}

// TestAHiddenHarnessIsMaskedInWhatTheRunReports pins a run whose harness is hidden:
// output.log, the session's output.log, every run.log chunk and session.jsonl contain
// no line of the harness. Its files' text is [harness text: <path>] in their places:
// as cat prints it, inside the JSON of a result record on stdout, and in the result
// event, and the review skill printed in two writes on either side of a pause is one
// replacement. Text written into the home after the session started is no harness
// text and is shown. The plan, at the end of the stream, is masked when the stream
// ends.
func TestAHiddenHarnessIsMaskedInWhatTheRunReports(t *testing.T) {
	res, out, chunks := harnessRun(t, true)
	session, _ := os.ReadFile(filepath.Join(res.Dir, sink.SessionFile))
	sessionOut, _ := os.ReadFile(filepath.Join(res.SessionDir, sink.OutputFile))
	for _, line := range harnessLines {
		for name, text := range map[string]string{"output.log": out, "session.jsonl": string(session), "the session's output.log": string(sessionOut), "the run.log chunks": strings.Join(chunks, "")} {
			if strings.Contains(text, line) {
				t.Errorf("%s contains %q:\n%s", name, line, text)
			}
		}
	}
	want := implementPut + "\n" +
		`{"type":"result","subtype":"success","session_id":"fake","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.01,"result":"` + reviewPut + `\n"}` + "\n" +
		reviewPut + "\n" +
		"Changed line one of the skill.\nChanged line two of the skill.\nChanged line three of the skill.\n" +
		planPut + "\n"
	if out != want {
		t.Errorf("output.log:\n%s\nwant:\n%s", out, want)
	}
	if got := strings.Join(chunks, ""); got != want {
		t.Errorf("the run.log chunks:\n%s\nwant:\n%s", got, want)
	}
	r := ofType(events(t, res), "dev.qory.runtime.result")
	if len(r) != 1 {
		t.Fatalf("runtime.result %v", r)
	}
	if got := data(r[0])["result"]; got != reviewPut+"\n" {
		t.Errorf("runtime.result's result %q", got)
	}
}

// TestAHarnessNotHiddenIsShown pins a run with a harness home whose harness is not
// hidden, the default: output.log is what the runtime printed, and the result event
// has the review skill as the runtime printed it.
func TestAHarnessNotHiddenIsShown(t *testing.T) {
	res, out, _ := harnessRun(t, false)
	result, _ := json.Marshal(reviewSkill)
	want := implementSkill +
		`{"type":"result","subtype":"success","session_id":"fake","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.01,"result":` + string(result) + `}` + "\n" +
		reviewSkill +
		"Changed line one of the skill.\nChanged line two of the skill.\nChanged line three of the skill.\n" +
		implementPlan
	if out != want {
		t.Errorf("output.log:\n%s\nwant:\n%s", out, want)
	}
	if strings.Contains(out, "[harness text:") {
		t.Errorf("output.log has a replacement:\n%s", out)
	}
	r := ofType(events(t, res), "dev.qory.runtime.result")
	if len(r) != 1 || data(r[0])["result"] != reviewSkill {
		t.Errorf("runtime.result %v", r)
	}
}

// TestAHiddenHarnessIsNotReadThroughALink pins a link in the home to a file outside
// it: the file is not read, so its text, printed through the link, is shown.
func TestAHiddenHarnessIsNotReadThroughALink(t *testing.T) {
	sp := spec(t)
	sp.Forwarder = nil
	home := harnessHome(t)
	outside := filepath.Join(t.TempDir(), "notes.md")
	text := "Outside line one of the notes.\nOutside line two of the notes.\nOutside line three of the notes.\n"
	if err := os.WriteFile(outside, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "skills", "notes.md")); err != nil {
		t.Fatal(err)
	}
	sp.HarnessHome, sp.HarnessHidden = home, true
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `cat "$QORY_HARNESS_HOME/skills/notes.md" "$QORY_HARNESS_HOME/skills/review/SKILL.md"`}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := os.ReadFile(filepath.Join(res.Dir, sink.OutputFile)); string(out) != text+reviewPut+"\n" {
		t.Errorf("output.log:\n%s", out)
	}
}

// TestAHiddenHarnessWhoseHomeCannotBeReadFailsTheJoin pins a home that does not exist
// in a run whose harness is hidden: the join fails, and no runtime starts.
func TestAHiddenHarnessWhoseHomeCannotBeReadFailsTheJoin(t *testing.T) {
	sp := spec(t)
	sp.Forwarder = nil
	sp.HarnessHome, sp.HarnessHidden = filepath.Join(t.TempDir(), "missing"), true
	marker := filepath.Join(t.TempDir(), "started")
	sp.Command, sp.Args = "/bin/sh", []string{"-c", `touch "$0"`, marker}
	_, err := run(context.Background(), sp)
	if err == nil || !strings.HasPrefix(err.Error(), "give the session a harness home it can read: ") {
		t.Fatalf("the join's error %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the runtime started")
	}
}

// TestAHiddenHarnessIsMaskedInASetupStep pins a setup command that prints a skill, and
// the plan last: the setup step's lines have the replacements in their places, and the
// terminal has the same.
func TestAHiddenHarnessIsMaskedInASetupStep(t *testing.T) {
	sp := preparedSpec(t, "true")
	sp.HarnessHome, sp.HarnessHidden = harnessHome(t), true
	var terminal bytes.Buffer
	sp.Stdout = &terminal
	sp.SessionSpec.Setup = []session.SetupCommand{{Name: "show", Args: []string{"/bin/sh", "-c", `echo before; cat "$QORY_HARNESS_HOME/skills/implement/SKILL.md"; echo after; cat "$QORY_HARNESS_HOME/skills/implement/plan.md"`}}}
	res, err := run(context.Background(), sp)
	if err != nil {
		t.Fatal(err)
	}
	all := steps(t, events(t, res))
	if len(all) != 3 || all[2].started["kind"] != event.StepSetup {
		t.Fatalf("the steps %v", all)
	}
	want := "before\n" + implementPut + "\nafter\n" + planPut + "\n"
	if got := all[2].logs["stdout"]; got != want {
		t.Errorf("the setup step's lines %q, want %q", got, want)
	}
	if terminal.String() != want {
		t.Errorf("the terminal %q, want %q", terminal.String(), want)
	}
}

// TestAHiddenHarnessIsMaskedInAFailureOfTheStart pins a wall whose wrap of the launch
// fails with an error that quotes a path whose names contain three lines of the
// implement skill: the session's stderr line of the failure has the replacement in
// their place.
func TestAHiddenHarnessIsMaskedInAFailureOfTheStart(t *testing.T) {
	lines := strings.Split(implementSkill, "\n")
	path := "/opt/notes\n" + strings.Join(lines[2:5], "\n") + "\nenv"
	sp := walledSpec(t, &wrapFails{err: &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}})
	sp.HarnessHome, sp.HarnessHidden = harnessHome(t), true
	ctx := context.Background()
	r, err := session.Open(ctx, opened(sp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(ctx, sp.SessionSpec); err == nil {
		t.Fatal("the session started")
	}
	if _, err := r.Close(ctx, session.Outcome{State: event.StateFailed, ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	var stderr string
	for _, l := range ofType(events(t, &session.Result{Dir: r.Dir()}), event.RunLog) {
		if d := data(l); d["stream"] == "stderr" && d["session"] != nil {
			b, _ := base64.StdEncoding.DecodeString(d["bytes"].(string))
			stderr += string(b)
		}
	}
	if want := "open /opt/notes\n" + implementPut + "\nenv: file does not exist\n"; !strings.HasSuffix(stderr, want) {
		t.Errorf("the session's stderr %q, want it to end %q", stderr, want)
	}
}
