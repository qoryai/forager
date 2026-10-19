package session

import (
	"errors"
	"io/fs"
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
// of mode 0644, 0600 under umask 077.
func TestThePreparationScriptReplacesALinkAtItsPath(t *testing.T) {
	for mask, perm := range map[int]os.FileMode{0o022: 0o644, 0o077: 0o600} {
		func() {
			defer syscall.Umask(syscall.Umask(mask))
			preparationReplacesALink(t, perm)
		}()
	}
}

// preparationReplacesALink is the check of TestThePreparationScriptReplacesALinkAtItsPath,
// for a script of mode perm.
func preparationReplacesALink(t *testing.T, perm os.FileMode) {
	t.Helper()
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
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != perm {
		t.Fatalf("the script is %v, %v; want a regular file of mode %v", fi, err, perm)
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

// TestALockThatIsALinkIsNotOpened pins that the run directory's lock and the lock of
// the registry of walled runs are not opened through a symbolic link: the file the
// link points at is neither made nor changed, and the error is the fix first.
func TestALockThatIsALinkIsNotOpened(t *testing.T) {
	for _, c := range []struct {
		name string
		take func(dir string) (func(), error)
		want string
	}{
		{lockFile, lock, "the run directory's lock"},
		{walledLock, lockRegistry, "the lock of the registry of walled runs"},
	} {
		for _, exists := range []bool{false, true} {
			dir, scratch := t.TempDir(), t.TempDir()
			target := filepath.Join(scratch, "target")
			if exists {
				if err := os.WriteFile(target, []byte("the target's content"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(dir, c.name)
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			unlock, err := c.take(dir)
			if err == nil {
				unlock()
				t.Fatalf("%s: a lock that is a link was taken", c.want)
			}
			want := "Remove the symbolic link at " + link + ". The session opens " + c.want +
				" only as a regular file, not through a link."
			if err.Error() != want || !errors.Is(err, syscall.ELOOP) {
				t.Errorf("%s: the error is %q, ELOOP %v; want %q", c.want, err, errors.Is(err, syscall.ELOOP), want)
			}
			b, err := os.ReadFile(target)
			switch {
			case exists && (err != nil || string(b) != "the target's content"):
				t.Errorf("%s: the target contains %q, %v; want its content kept", c.want, b, err)
			case !exists && !errors.Is(err, fs.ErrNotExist):
				t.Errorf("%s: the target was made: %q, %v", c.want, b, err)
			}
		}
	}
}
