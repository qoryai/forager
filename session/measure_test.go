package session_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/qoryai/forager/wall"
)

// fakeCgroup writes the cgroup v2 files the helper's exec reads into a directory of
// the test's and returns it: memory.max, memory.peak and cpu.stat.
func fakeCgroup(t *testing.T, peak, cpuStat string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{"memory.max": "max\n", "memory.peak": peak, "cpu.stat": cpuStat} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestSessionExitedHasTheMeasureOfTheEnclosure pins the measure on
// dev.qory.session.exited: behind a wall, the last measure record the session's socket
// read, the helper's exec sending its record after every process of the launch;
// each member left out, apart from the other, when the record has no whole number of 0 or more for
// it; neither without a record; and neither without a wall, whatever a process sends.
func TestSessionExitedHasTheMeasureOfTheEnclosure(t *testing.T) {
	walled := func(sp *runSpec) {
		sp.Wall, sp.Image, sp.Mounts = &openWall{}, "example.com/agent:1", []wall.Mount{{Path: sp.Dir}}
	}
	cgroup := fakeCgroup(t, "4096\n", "usage_usec 12999\nuser_usec 10000\n")
	for _, c := range []struct {
		name  string
		wall  bool
		env   []string
		code  int
		peak  any
		cpu   any
		state string
	}{
		{"the helper's record comes last and counts", true, []string{"FAKE_CGROUP_ROOT=" + cgroup, "FAKE_MEASURE={\"peak_memory_bytes\": 100, \"cpu_time_ms\": 5}", "FAKE_EXIT=3"}, 3, float64(4096), float64(12), "failed"},
		{"the last of two records counts", true, []string{"FAKE_MEASURE={\"peak_memory_bytes\": 100, \"cpu_time_ms\": 5}\n{\"peak_memory_bytes\": 2048, \"cpu_time_ms\": 7}"}, 0, float64(2048), float64(7), "succeeded"},
		{"a member that is no whole number of 0 or more is left out", true, []string{"FAKE_MEASURE={\"peak_memory_bytes\": -1, \"cpu_time_ms\": 7}"}, 0, nil, float64(7), "succeeded"},
		{"a fraction and a string are left out", true, []string{"FAKE_MEASURE={\"peak_memory_bytes\": 1.5, \"cpu_time_ms\": \"7\"}"}, 0, nil, nil, "succeeded"},
		{"no record, no measure", true, nil, 0, nil, nil, "succeeded"},
		{"no wall, no measure", false, []string{"FAKE_MEASURE={\"peak_memory_bytes\": 100, \"cpu_time_ms\": 5}"}, 0, nil, nil, "succeeded"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp := spec(t, c.env...)
			if c.wall {
				walled(&sp)
			}
			res, err := run(context.Background(), sp)
			if err != nil {
				t.Fatal(err)
			}
			exited := ofType(events(t, res), "dev.qory.session.exited")
			if len(exited) != 1 {
				t.Fatalf("%d session.exited", len(exited))
			}
			d := data(exited[0])
			if res.ExitCode != c.code || d["state"] != c.state || d["peak_memory_bytes"] != c.peak || d["cpu_time_ms"] != c.cpu {
				t.Errorf("exit %d, session.exited %v; want exit %d, %s, peak_memory_bytes %v, cpu_time_ms %v", res.ExitCode, d, c.code, c.state, c.peak, c.cpu)
			}
		})
	}
}
