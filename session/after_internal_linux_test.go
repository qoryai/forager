package session

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// TestOthersLeftCountsNewProcessesOfEveryUser pins the stop's count: a process that
// started after the list of the starting processes counts, whatever its user, and one
// of the list does not.
func TestOthersLeftCountsNewProcessesOfEveryUser(t *testing.T) {
	kept := startingProcesses()
	if n, err := othersLeft(kept); err != nil || n != 0 {
		t.Fatalf("othersLeft with nothing new: %d, %v", n, err)
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	if n, err := othersLeft(kept); err != nil || n != 1 {
		t.Errorf("othersLeft with a sleep: %d, %v", n, err)
	}
	if n, err := othersLeft(startingProcesses()); err != nil || n != 0 {
		t.Errorf("othersLeft with the sleep kept: %d, %v", n, err)
	}
}

// fakeDaemon is an inner daemon on a socket of the test's: it answers the API's lists
// from its fields and records each call.
type fakeDaemon struct {
	mu         sync.Mutex
	calls      []string
	swarm      string
	services   []string
	plugins    []string
	containers []string
	// failList is the list that answers 500; slow, the one that answers after 2 s.
	failList, slow string
}

func (f *fakeDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	if r.URL.Path == f.slow {
		time.Sleep(2 * time.Second)
	}
	if r.URL.Path == f.failList {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	ids := func(list []string, key string) []map[string]string {
		var out []map[string]string
		for _, id := range list {
			out = append(out, map[string]string{key: id})
		}
		return out
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/info":
		json.NewEncoder(w).Encode(map[string]any{"Swarm": map[string]string{"LocalNodeState": f.swarm}})
	case r.Method == http.MethodGet && r.URL.Path == "/services":
		json.NewEncoder(w).Encode(ids(f.services, "ID"))
	case r.Method == http.MethodGet && r.URL.Path == "/plugins":
		json.NewEncoder(w).Encode(ids(f.plugins, "Name"))
	case r.Method == http.MethodGet && r.URL.Path == "/containers/json":
		json.NewEncoder(w).Encode(ids(f.containers, "Id"))
	}
}

// serveFake serves d on a socket that innerSocket is set to for the test.
func serveFake(t *testing.T, d *fakeDaemon) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: d}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	old := innerSocket
	innerSocket = sock
	t.Cleanup(func() { innerSocket = old })
}

// TestRemoveInnerRemovesEveryKind pins the inner daemon's objects the stop removes: the
// swarm's services and the swarm, each plugin, and each container, stopped ones too.
func TestRemoveInnerRemovesEveryKind(t *testing.T) {
	d := &fakeDaemon{swarm: "active", services: []string{"s1"}, plugins: []string{"example/plugin:1"}, containers: []string{"c1", "c2"}}
	serveFake(t, d)
	n, err := removeInner(time.Now().Add(2 * time.Second))
	if err != nil || n != 5 {
		t.Errorf("removeInner: %d, %v; want 5 listed", n, err)
	}
	want := []string{
		"GET /info", "GET /services", "DELETE /services/s1", "POST /swarm/leave?force=true",
		"GET /plugins", "DELETE /plugins/example%2Fplugin:1?force=true",
		"GET /containers/json?all=true", "DELETE /containers/c1?force=true&v=true", "DELETE /containers/c2?force=true&v=true",
	}
	d.mu.Lock()
	if !slices.Equal(d.calls, want) {
		t.Errorf("the calls\n%q\nwant\n%q", d.calls, want)
	}
	d.swarm, d.services, d.plugins, d.containers, d.calls = "inactive", nil, nil, nil, nil
	d.mu.Unlock()
	if n, err := removeInner(time.Now().Add(2 * time.Second)); err != nil || n != 0 {
		t.Errorf("removeInner with nothing left: %d, %v", n, err)
	}
}

// TestRemoveInnerFailsClosed pins the stop's failures: a list that fails, a daemon
// that answers too late, and a daemon that is not there are errors, never nothing left.
func TestRemoveInnerFailsClosed(t *testing.T) {
	for _, c := range []struct {
		name string
		d    *fakeDaemon
	}{
		{"a failed list", &fakeDaemon{failList: "/containers/json"}},
		{"a slow answer", &fakeDaemon{slow: "/plugins"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			serveFake(t, c.d)
			if _, err := removeInner(time.Now().Add(2 * time.Second)); err == nil {
				t.Error("removeInner returned no error")
			}
		})
	}
	old := innerSocket
	innerSocket = filepath.Join(t.TempDir(), "none.sock")
	defer func() { innerSocket = old }()
	if _, err := removeInner(time.Now().Add(time.Second)); err == nil {
		t.Error("removeInner with no daemon returned no error")
	}
}

// TestOthersLeftCountsAProcessWhoseStatCannotBeRead pins the stop's count of a process
// it cannot read: one whose stat file cannot be read or parsed counts as left while its
// /proc folder is there, and is not kept as a starting process; a zombie does not count.
func TestOthersLeftCountsAProcessWhoseStatCannotBeRead(t *testing.T) {
	root := t.TempDir()
	// Numbers above the largest pid_max, 2^22, so the test's process is none of them.
	stat := func(state, start string) string {
		return "100 (a b) c) " + state + " 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 " + start + " 0 0\n"
	}
	for name, content := range map[string]string{
		"4194401": stat("S", "500"),
		"4194402": "",
		"4194403": "garbage\n",
		"4194404": stat("Z", "600"),
		"4194405": stat("S", "0"),
	} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		switch {
		case name == "4194402":
			// A folder in place of the file: reading it fails.
			if err := os.Mkdir(filepath.Join(dir, "stat"), 0o755); err != nil {
				t.Fatal(err)
			}
		default:
			if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	was := procRoot
	procRoot = root
	defer func() { procRoot = was }()
	kept := startingProcesses()
	if want := []procID{{4194401, 500}}; !slices.Equal(kept, want) {
		t.Errorf("startingProcesses: %v; want %v", kept, want)
	}
	if n, err := othersLeft(kept); err != nil || n != 3 {
		t.Errorf("othersLeft: %d, %v; want 3, for the unreadable, the unparsed and the zero start", n, err)
	}
}
