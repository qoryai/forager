package claude_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
	"github.com/qoryai/forager/session/runtimes/claude"
)

// TestSettingsWritesPrintAPhraseForASecretInTheRunDirectory pins the errors of the
// settings file's and the approval script's writes in a run directory whose path
// contains qak_: a phrase, the error each wraps still found by errors.Is.
func TestSettingsWritesPrintAPhraseForASecretInTheRunDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "qak_FAKE", "run")
	_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{RunDir: missing, Forwarder: []string{"q"}})
	if err == nil {
		t.Fatal("settings were written in a missing directory")
	}
	if strings.Contains(strings.ToLower(err.Error()), "qak_") {
		t.Errorf("the settings write's error %v contains the prefix", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the settings write's error %v does not wrap fs.ErrNotExist", err)
	}
	dir := filepath.Join(t.TempDir(), "qak_FAKE")
	if err := os.MkdirAll(filepath.Join(dir, claude.ApproveScript), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = claude.Settings([]string{"Stop"}, runtimes.Attach{RunDir: dir, Forwarder: []string{"q"}, Interactive: true, Walled: true, Placeholders: []string{"ANTHROPIC_API_KEY"}})
	if err == nil {
		t.Fatal("the approval script was written over a directory")
	}
	if strings.Contains(strings.ToLower(err.Error()), "qak_") {
		t.Errorf("the script write's error %v contains the prefix", err)
	}
	if !errors.Is(err, syscall.EEXIST) {
		t.Errorf("the script write's error %v does not wrap EEXIST", err)
	}
}

// runFiles are the files Settings writes into the run directory of a walled,
// interactive launch with the API key's stand-in and a file for --mcp-config, --agents
// and --system-prompt-file.
var runFiles = []string{"settings.json", claude.ApproveScript, "mcp-config-1.json", "agents-1.json", "system-prompt-file-1.md"}

// settingsWithFiles calls Settings for that launch in run, with its files in a new
// directory, and returns the files' content by the name of their copy.
func settingsWithFiles(t *testing.T, run string) (map[string]string, error) {
	t.Helper()
	dir := t.TempDir()
	from := map[string]string{
		"mcp-config-1.json":       writeFile(t, filepath.Join(dir, "mcp.json"), `{"mcpServers":{}}`),
		"agents-1.json":           writeFile(t, filepath.Join(dir, "agents.json"), `{"r":{"description":"d","prompt":"p"}}`),
		"system-prompt-file-1.md": writeFile(t, filepath.Join(dir, "prompt.md"), "the prompt\n"),
	}
	f := &fakeWritten{written: t.TempDir()}
	_, err := claude.Settings([]string{"Stop"}, runtimes.Attach{
		Launch: runtimes.Launch{Command: "claude", Args: []string{
			"--mcp-config", from["mcp-config-1.json"], "--agents", from["agents-1.json"],
			"--system-prompt-file", from["system-prompt-file-1.md"]}},
		RunDir: run, Forwarder: []string{"q"}, Walled: true, Interactive: true,
		Placeholders: []string{"ANTHROPIC_API_KEY"}, Readable: f.readable,
	})
	content := map[string]string{}
	for copied, p := range from {
		b, _ := os.ReadFile(p)
		content[copied] = string(b)
	}
	return content, err
}

// TestSettingsReplacesALinkAtEachRunFile pins that a link at the path of each file
// Settings writes into the run directory is replaced, not followed: the file the link
// points at keeps its content, and the run directory has a regular file of mode 0644
// with the run's content.
func TestSettingsReplacesALinkAtEachRunFile(t *testing.T) {
	run, scratch := t.TempDir(), t.TempDir()
	for _, name := range runFiles {
		target := writeFile(t, filepath.Join(scratch, name), "the target's content")
		if err := os.Symlink(target, filepath.Join(run, name)); err != nil {
			t.Fatal(err)
		}
	}
	content, err := settingsWithFiles(t, run)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range runFiles {
		if b, err := os.ReadFile(filepath.Join(scratch, name)); err != nil || string(b) != "the target's content" {
			t.Errorf("the target of the link at %s contains %q, %v; want its content kept", name, b, err)
		}
		p := filepath.Join(run, name)
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
			t.Errorf("%s is %v, %v; want a regular file of mode 0644", name, fi, err)
			continue
		}
		b, _ := os.ReadFile(p)
		switch want, copied := content[name]; {
		case copied && string(b) != want:
			t.Errorf("%s contains %q, want %q", name, b, want)
		case name == "settings.json" && !strings.Contains(string(b), `"hooks"`):
			t.Errorf("%s contains %q, want the hooks", name, b)
		case name == claude.ApproveScript && !strings.Contains(string(b), `exec "$@"`):
			t.Errorf("%s contains %q, want the script", name, b)
		}
	}
}

// TestSettingsLeavesNoNewFileOnAFailedWrite pins that a run file Settings cannot write,
// because a directory is at its path, leaves no new file in the run directory.
func TestSettingsLeavesNoNewFileOnAFailedWrite(t *testing.T) {
	for _, name := range runFiles {
		run := t.TempDir()
		if err := os.Mkdir(filepath.Join(run, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := settingsWithFiles(t, run); !errors.Is(err, syscall.EEXIST) {
			t.Errorf("a directory at %s: Settings returned %v; want EEXIST", name, err)
		}
		entries, err := os.ReadDir(run)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				t.Errorf("a directory at %s: the run directory contains %s", name, e.Name())
			}
		}
	}
}
