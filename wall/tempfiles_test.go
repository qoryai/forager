package wall

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestTheEnclosuresFileErrorsPrintAPhraseForASecretInAPath pins the errors of the
// private directory's making, writing and removal when its path contains qak_: a
// phrase, the error it wraps still found by errors.Is.
func TestTheEnclosuresFileErrorsPrintAPhraseForASecretInAPath(t *testing.T) {
	base := t.TempDir()
	t.Setenv("TMPDIR", "/nonexistent/qak_FAKE")
	e := &dockerEnclosure{d: &Docker{Helper: "/bin/true"}, sys: hostSystem{}}
	_, err := e.Binds(Launch{})
	if err == nil {
		t.Fatal("a temporary directory under a missing TMPDIR was made")
	}
	noPrefix(t, "the making", err.Error())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the making's error %v does not wrap fs.ErrNotExist", err)
	}
	e.temp = filepath.Join(base, "qak_FAKE", "missing")
	_, err = e.envFile("relay.env", []string{"A=1"})
	if err == nil {
		t.Fatal("an environment file in a missing directory was written")
	}
	noPrefix(t, "the writing", err.Error())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the writing's error %v does not wrap fs.ErrNotExist", err)
	}
	parent := filepath.Join(base, "qak_FAKE")
	e.temp = filepath.Join(parent, "temp")
	if err := os.MkdirAll(filepath.Join(e.temp, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.temp, "d", "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.temp, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(e.temp, 0o755) })
	temp := e.temp
	err = e.Close(context.Background())
	os.Chmod(temp, 0o755)
	if err == nil {
		t.Skip("the directory was removed: the test runs as a user who may")
	}
	noPrefix(t, "the removal", err.Error())
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("the removal's error %v does not wrap fs.ErrPermission", err)
	}
}
