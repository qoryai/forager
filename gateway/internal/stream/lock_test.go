package stream

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestALockThatIsALinkIsNotOpened pins that a run directory's lock is not opened
// through a symbolic link: the file the link points at keeps its content, and the
// error is the fix first.
func TestALockThatIsALinkIsNotOpened(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("the target's content"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, lockFile)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	unlock, err := lock(dir, lockFile)
	if err == nil {
		unlock()
		t.Fatal("a lock that is a link was taken")
	}
	want := "Remove the symbolic link at " + link +
		". The gateway opens a run directory's lock only as a regular file, not through a link."
	if err.Error() != want || !errors.Is(err, syscall.ELOOP) {
		t.Errorf("the error is %q, ELOOP %v; want %q", err, errors.Is(err, syscall.ELOOP), want)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "the target's content" {
		t.Errorf("the target contains %q, %v; want its content kept", b, err)
	}
}
