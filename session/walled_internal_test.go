package session

import (
	"errors"
	"io/fs"
	"os"
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

// TestAnUnwalledRunJoinsAgainAfterAKilledSession pins the registry of a session without
// a wall: when such a session is killed, its entry stays with its lock free, and the
// same run joins again; another run's unwalled entry whose lock is free is removed, and
// one whose lock is held stays.
func TestAnUnwalledRunJoinsAgainAfterAKilledSession(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	const run, other, going = "00000000-0000-4000-8000-000000000001",
		"00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003"
	held, err := register(going, nil, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	defer held.release()
	for _, id := range []string{other, run} {
		r, err := register(id, nil, nil, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		// A killed session leaves its entry, and the kernel frees its lock.
		r.f.Close()
	}
	again, err := register(run, nil, nil, nil, true)
	if err != nil {
		t.Fatalf("the run joins again after a killed session: %v", err)
	}
	defer again.release()
	dir, err := walledDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, other)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the other run's entry, its lock free: %v; want it removed", err)
	}
	if _, err := os.Stat(filepath.Join(dir, going)); err != nil {
		t.Errorf("the entry of a session still going: %v; want it kept", err)
	}
}
