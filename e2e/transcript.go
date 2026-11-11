package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/qoryai/forager/event"
)

// transcriptID is the session id the probe gives in its SessionStart hook when
// PROBE_TRANSCRIPT is set: a UUID in lower case, the shape the session reads a walled
// transcript under.
const transcriptID = "5d0c6a51-3b2e-4f7a-9c1d-8e6f4a2b0c37"

// transcriptMaxBytes is the largest walled transcript the session reads, 64 MiB.
const transcriptMaxBytes = 64 << 20

// The files the probe plants at its transcript's path, by the value of
// PROBE_TRANSCRIPT, and the cause each line of the session gives.
var transcriptPlants = []struct{ kind, name, why string }{
	{"symlink", "a planted symbolic link", "a name on its path is a symbolic link or no directory"},
	{"fifo", "a FIFO", "it is no regular file"},
	{"big", "a file over 64 MiB", fmt.Sprintf("it is over %d bytes (64 MiB)", transcriptMaxBytes)},
	{"hardlink", "a hard link out of the bind", "it has 2 hard links, and the session reads a file with one"},
}

// transcriptReport is what the probe planted, when PROBE_TRANSCRIPT is set: the path,
// how a hard link from the workspace into the transcript's directory failed, and each
// error on the way.
type transcriptReport struct {
	Path    string `json:"path"`
	Linked  string `json:"linked,omitempty"`
	Err     string `json:"err,omitempty"`
	HookErr string `json:"hook_err,omitempty"`
}

// transcriptLine is what the probe writes at its transcript's path for
// PROBE_TRANSCRIPT=plain: one line, which the session sends.
const transcriptLine = "{\"probe\":1}\n"

// noResumeLine is the part of each line of the session that says a continuation
// starts the runtime without a resume; the fix comes before it.
const noResumeLine = ". A continuation of this run starts the runtime without a resume: "

// probeTranscript plants kind at the runtime's transcript path, ~/.claude/projects/
// <slug of the working directory>/<transcriptID>.jsonl, then gives the session that
// session id through the SessionStart hooks the settings name, as Claude Code does. A
// symbolic link leads to hostFile, a path of the host's; a hard link is made from the
// workspace first and, when the kernel refuses a link across binds, from a file beside
// the transcript.
func probeTranscript(kind, hostFile string, settings []string) *transcriptReport {
	r := &transcriptReport{}
	home, cwd := os.Getenv("HOME"), "/"
	if wd, err := os.Getwd(); err == nil {
		cwd = wd
	}
	slug := strings.Map(func(c rune) rune {
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' {
			return c
		}
		return '-'
	}, cwd)
	dir := filepath.Join(home, ".claude", "projects", slug)
	r.Path = filepath.Join(dir, transcriptID+".jsonl")
	plant := func() error {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		switch kind {
		case "plain":
			return os.WriteFile(r.Path, []byte(transcriptLine), 0o600)
		case "symlink":
			return os.Symlink(hostFile, r.Path)
		case "fifo":
			return syscall.Mkfifo(r.Path, 0o600)
		case "big":
			f, err := os.Create(r.Path)
			if err != nil {
				return err
			}
			defer f.Close()
			return f.Truncate(transcriptMaxBytes + 1)
		case "hardlink":
			inWorkspace := filepath.Join(cwd, "transcript-outside")
			if err := os.WriteFile(inWorkspace, []byte("{\"outside\":1}\n"), 0o600); err != nil {
				return err
			}
			err := os.Link(inWorkspace, r.Path)
			if err == nil {
				return nil
			}
			r.Linked = err.Error()
			beside := filepath.Join(dir, "beside.jsonl")
			if err := os.WriteFile(beside, []byte("{\"beside\":1}\n"), 0o600); err != nil {
				return err
			}
			return os.Link(beside, r.Path)
		}
		return fmt.Errorf("no plant %q", kind)
	}
	if err := plant(); err != nil {
		r.Err = err.Error()
	}
	input := fmt.Sprintf(`{"session_id":%q,"hook_event_name":"SessionStart","source":"startup","cwd":%q,"transcript_path":%q}`, transcriptID, cwd, r.Path)
	for _, s := range settings {
		if err := callHooks(s, "SessionStart", input); err != "" {
			r.HookErr += err
		}
	}
	return r
}

// callHooks calls the hooks of event the settings name with input, as the runtime
// would, and returns what failed.
func callHooks(settings, event, input string) string {
	b, err := os.ReadFile(settings)
	if err != nil {
		return err.Error()
	}
	var s struct {
		Hooks map[string][]struct {
			Hooks []struct{ Command string } `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return err.Error()
	}
	var failed strings.Builder
	for _, group := range s.Hooks[event] {
		for _, h := range group.Hooks {
			cmd := exec.Command("sh", "-c", h.Command)
			cmd.Stdin = strings.NewReader(input)
			if out, err := cmd.CombinedOutput(); err != nil {
				fmt.Fprintf(&failed, "%s: %v; ", out, err)
			}
		}
	}
	return failed.String()
}

// transcriptPlanted checks what the session does with a file a walled agent plants at
// its transcript's path in the session's transcript directory: a symbolic link to a
// file of the host's, a FIFO, a file over 64 MiB and a hard link. In each the session
// reads nothing of it, does not block, writes one line of the session on stderr with
// the cause, and the run otherwise proceeds: the probe reports and exits 0.
//
// With nested Docker the cases run in Options.HomeImage.
func transcriptPlanted(t *testing.T, o Options, h hosts, outside string) {
	for _, c := range transcriptPlants {
		t.Run("the session reads nothing of "+c.name+" in the transcript directory", func(t *testing.T) {
			skipTranscript(t, o)
			r, err := runIn(t, o, variant{env: []string{"PROBE_TRANSCRIPT=" + c.kind}, home: true}, false, h, outside)
			if err != nil {
				t.Fatal(err)
			}
			p := r.probe.Transcript
			if p == nil || p.Err != "" || p.HookErr != "" {
				t.Fatalf("the probe planted %+v", p)
			}
			if r.res.ExitCode != 0 {
				t.Errorf("the run's exit code %d; want the probe's 0", r.res.ExitCode)
			}
			var lines []string
			for _, e := range r.events {
				d, _ := e["data"].(map[string]any)
				switch e["type"] {
				case event.SessionTranscript:
					b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(d["bytes"]))
					t.Errorf("the session sent %d bytes of the transcript: %.80q", len(b), b)
				case event.RunLog:
					if d["stream"] != "stderr" || d["session"] == nil {
						continue
					}
					b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(d["bytes"]))
					lines = append(lines, noResumeLines(b)...)
				}
			}
			want := noResumeLine + "the session reads no transcript at ~/.claude/projects/"
			if len(lines) != 1 || !strings.Contains(lines[0], want) || strings.HasPrefix(lines[0], ".") || !strings.HasSuffix(lines[0], "/"+transcriptID+".jsonl: "+c.why) {
				t.Errorf("the session's lines %q; want one that ends with %q", lines, c.why)
			}
			if c.kind == "hardlink" {
				t.Logf("a hard link from the workspace: %s", orNil(p.Linked))
			}
		})
	}
}

// skipTranscript skips a transcript case where the session gets no transcript to read:
// with no hook socket across, and with nested Docker and no Options.HomeImage.
func skipTranscript(t *testing.T, o Options) {
	t.Helper()
	if !o.Hooks {
		t.Skip("the adapter carries no hook socket across on this machine, so the session gets no session id to read a transcript under")
	}
	if o.Docker && o.HomeImage == "" {
		t.Skip("with nested Docker the transcript cases need Options.HomeImage, a home the agent's user can reach")
	}
}

// noResumeLines are the lines of b, a chunk of the session's stderr, that say a
// continuation starts the runtime without a resume.
func noResumeLines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, noResumeLine) {
			out = append(out, l)
		}
	}
	return out
}

// transcriptOf is the bytes of the dev.qory.session.transcript events of a run, joined
// in order, and the session's stderr lines that say a continuation starts the runtime
// without a resume.
func transcriptOf(events []map[string]any) ([]byte, []string) {
	var sent []byte
	var lines []string
	for _, e := range events {
		d, _ := e["data"].(map[string]any)
		b, _ := base64.StdEncoding.DecodeString(fmt.Sprint(d["bytes"]))
		switch e["type"] {
		case event.SessionTranscript:
			sent = append(sent, b...)
		case event.RunLog:
			if d["stream"] == "stderr" && d["session"] != nil {
				lines = append(lines, noResumeLines(b)...)
			}
		}
	}
	return sent, lines
}

// transcriptSent checks the transcript of a walled session: the probe writes one line
// at its transcript's path, and the session sends it, with no line on stderr. With
// nested Docker the probe runs in Options.HomeImage; in Options.Image, under the home of
// the enclosure's root, which the agent's user cannot reach, the session binds no
// transcript directory, sends nothing and writes one line that starts with the fix.
func transcriptSent(t *testing.T, o Options, h hosts, outside string) {
	t.Run("the session sends the transcript the runtime writes", func(t *testing.T) {
		skipTranscript(t, o)
		r, err := runIn(t, o, variant{env: []string{"PROBE_TRANSCRIPT=plain"}, home: true}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if p := r.probe.Transcript; p == nil || p.Err != "" || p.HookErr != "" {
			t.Fatalf("the probe wrote %+v", p)
		}
		if sent, lines := transcriptOf(r.events); string(sent) != transcriptLine || len(lines) != 0 {
			t.Errorf("the session sent %q and the lines %q; want %q and none", sent, lines, transcriptLine)
		}
	})
	if !o.Docker {
		return
	}
	t.Run("with nested Docker under root's home the session binds no transcript directory", func(t *testing.T) {
		if !o.Hooks {
			t.Skip("the adapter carries no hook socket across on this machine")
		}
		r, err := runIn(t, o, variant{env: []string{"PROBE_TRANSCRIPT=plain"}}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		if p := r.probe.Transcript; p == nil || p.Err == "" {
			t.Errorf("the probe wrote %+v; want its write under root's home to fail", p)
		}
		sent, lines := transcriptOf(r.events)
		if len(sent) != 0 || len(lines) != 1 || !strings.HasPrefix(lines[0], "Set HOME in the image to a directory that uid ") || !strings.Contains(lines[0], "cannot reach the transcript directory below it") {
			t.Errorf("the session sent %q and the lines %q; want nothing and one line with the fix", sent, lines)
		}
	})
}
