package session

import (
	"path/filepath"
	"testing"
)

// TestTheRegistryIsAbsolute pins the registry's directory as an absolute path, so the
// entry an engine_unreachable refusal names can be found from anywhere: a relative
// XDG_STATE_HOME is passed over for HOME, and a relative HOME is taken from the working
// directory.
func TestTheRegistryIsAbsolute(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "state")
	t.Setenv("HOME", "home")
	dir, err := walledDir()
	want, _ := filepath.Abs(filepath.Join("home", ".local", "state", "qory-forager", "walled"))
	if err != nil || dir != want {
		t.Errorf("the registry is %q, %v; want %q", dir, err, want)
	}
}
