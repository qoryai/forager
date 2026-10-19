package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/qoryai/forager/session/runtimes"
)

// TestThePreparationScriptReplacesALinkAtItsPath pins that a link at the path of
// [PreparationScript] in the run directory is replaced, not followed: the file the link
// points at keeps its content, and the run directory has the script as a regular file
// of mode 0644.
func TestThePreparationScriptReplacesALinkAtItsPath(t *testing.T) {
	run := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("the target's content"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(run, PreparationScript)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := withPreparation(run, []string{"make", "deps"}, runtimes.Launch{Command: "agent"}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "the target's content" {
		t.Errorf("the link's target contains %q, %v; want its content kept", b, err)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Fatalf("the script is %v, %v; want a regular file of mode 0644", fi, err)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "'make' 'deps'") {
		t.Errorf("the script contains %q; want the preparation", b)
	}
}

// TestAFailedPreparationScriptLeavesNoNewFile pins that a script the session cannot
// write, because a directory is at its path, leaves no new file in the run directory.
func TestAFailedPreparationScriptLeavesNoNewFile(t *testing.T) {
	run := t.TempDir()
	if err := os.Mkdir(filepath.Join(run, PreparationScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := withPreparation(run, []string{"true"}, runtimes.Launch{Command: "agent"}); !errors.Is(err, syscall.EEXIST) {
		t.Errorf("withPreparation returned %v; want EEXIST", err)
	}
	entries, err := os.ReadDir(run)
	if err != nil || len(entries) != 1 {
		t.Errorf("the run directory contains %v, %v; want the directory alone", entries, err)
	}
}
