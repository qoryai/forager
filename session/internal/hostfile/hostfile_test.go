package hostfile_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/qoryai/forager/session/internal/hostfile"
)

// TestReadReadsOnlyARegularFileWithinTheBound pins what Read reads: a regular file of
// at most the bound, never a link as its last part, a directory, a FIFO or a device,
// and, when it is told one, only the file it is told.
func TestReadReadsOnlyARegularFileWithinTheBound(t *testing.T) {
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	for name, body := range map[string]string{"plain": "abcd", "edge": "abcdefgh", "over": "abcdefghi"} {
		if err := os.WriteFile(p(name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(p("plain"), p("link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p("dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p("fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	other, err := os.Stat(p("edge"))
	if err != nil {
		t.Fatal(err)
	}
	same, err := os.Stat(p("plain"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, path string
		want       fs.FileInfo
		body, err  string
	}{
		{"a regular file", p("plain"), nil, "abcd", ""},
		{"the file it is told", p("plain"), same, "abcd", ""},
		{"a file of the bound", p("edge"), nil, "abcdefgh", ""},
		{"a file over the bound", p("over"), nil, "", "it is larger than 8 bytes"},
		{"a link as its last part", p("link"), nil, "", "it is a link"},
		{"a directory", p("dir"), nil, "", "it is not a regular file"},
		{"a FIFO", p("fifo"), nil, "", "it is not a regular file"},
		{"a device", "/dev/null", nil, "", "it is not a regular file"},
		{"another file than it is told", p("plain"), other, "", "it changed while it was checked"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, err := hostfile.Read(c.path, 8, c.want)
			switch {
			case c.err == "" && (err != nil || string(b) != c.body):
				t.Errorf("%q, %v, want %q", b, err, c.body)
			case c.err != "" && (err == nil || err.Error() != c.err):
				t.Errorf("%v, want %q", err, c.err)
			}
		})
	}
	if _, err := hostfile.Read(p("absent"), 8, nil); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a file that does not exist: %v", err)
	}
}

// TestDotDotIsAnyDotDotName pins which paths have a ".." name: by whole names, as
// written, before any cleaning.
func TestDotDotIsAnyDotDotName(t *testing.T) {
	for path, want := range map[string]bool{
		"/a/../b": true, "../b": true, "a/..": true, "..": true, "/a/b/../../c": true,
		"/a/b": false, "/a/..b/c": false, "/a/b../c": false, "/a/./b": false, "...": false,
	} {
		if got := hostfile.DotDot(path); got != want {
			t.Errorf("DotDot(%q) = %v, want %v", path, got, want)
		}
	}
	if !strings.Contains(hostfile.ErrDotDot.Error(), `".."`) {
		t.Errorf("the refusal: %v", hostfile.ErrDotDot)
	}
}
