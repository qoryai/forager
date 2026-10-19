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
	_, err = claude.Settings([]string{"Stop"}, runtimes.Attach{RunDir: dir, Forwarder: []string{"q"}, Interactive: true, Placeholders: []string{"ANTHROPIC_API_KEY"}})
	if err == nil {
		t.Fatal("the approval script was written over a directory")
	}
	if strings.Contains(strings.ToLower(err.Error()), "qak_") {
		t.Errorf("the script write's error %v contains the prefix", err)
	}
	if !errors.Is(err, syscall.EISDIR) {
		t.Errorf("the script write's error %v does not wrap EISDIR", err)
	}
}
