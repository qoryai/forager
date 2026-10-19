package runfile_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/qoryai/forager/session/internal/runfile"
)

// TestReplaceReplacesALinkAtThePath pins that a link at the path is replaced, not
// followed: the file the link points at keeps its content and mode, and the path is a
// regular file with the content and the mode given, 0644 or 0600.
func TestReplaceReplacesALinkAtThePath(t *testing.T) {
	for _, perm := range []os.FileMode{0o644, 0o600} {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("the target's content"), 0o640); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "file")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := runfile.Replace(path, []byte("the run's content"), perm); err != nil {
			t.Fatal(err)
		}
		unchanged(t, target, "the target's content", 0o640)
		regular(t, path, "the run's content", perm)
		alone(t, dir, "file")
	}
}

// TestReplaceReplacesAFile pins that a regular file at the path is replaced with the
// content and the mode given.
func TestReplaceReplacesAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("an older and longer content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runfile.Replace(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	regular(t, path, "new", 0o644)
	alone(t, dir, "file")
}

// TestReplaceLeavesNoNewFileOnAnError pins that a failed write leaves the directory as
// it was: a directory at the path is not replaced, which os.Rename returns as EEXIST,
// and a missing directory has no file made in it.
func TestReplaceLeavesNoNewFileOnAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runfile.Replace(path, []byte("content"), 0o644); !errors.Is(err, syscall.EEXIST) {
		t.Errorf("a write over a directory returned %v; want EEXIST", err)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.IsDir() {
		t.Errorf("the directory is %v, %v after the write; want it kept", fi, err)
	}
	alone(t, dir, "file")

	missing := filepath.Join(t.TempDir(), "missing", "file")
	if err := runfile.Replace(missing, []byte("content"), 0o644); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a write in a missing directory returned %v; want fs.ErrNotExist", err)
	}
}

// unchanged fails the test unless path is a file with content and mode perm.
func unchanged(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode() != perm {
		t.Errorf("%s is %v, %v; want mode %v", path, fi, err, perm)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != content {
		t.Errorf("%s contains %q, %v; want %q", path, b, err, content)
	}
}

// regular fails the test unless path is a regular file, not a link, with content and
// mode perm.
func regular(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != perm {
		t.Fatalf("%s is %v, %v; want a regular file of mode %v", path, fi, err, perm)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != content {
		t.Errorf("%s contains %q, %v; want %q", path, b, err, content)
	}
}

// alone fails the test unless dir contains the names given and no other.
func alone(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	for _, n := range names {
		if !got[n] {
			t.Errorf("%s has no %s", dir, n)
		}
		delete(got, n)
	}
	for n := range got {
		t.Errorf("%s contains %s; want no other file", dir, n)
	}
}
