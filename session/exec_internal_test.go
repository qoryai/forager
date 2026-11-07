package session

import (
	"maps"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/qoryai/forager/session/internal/descriptor"
	"github.com/qoryai/forager/session/internal/socket"
)

// TestParseExecRefusesANameWithANULOrAnEqualsSign pins what no argument of a process
// can carry to the helper's exec, a NUL, beside an equals sign: neither is a name.
func TestParseExecRefusesANameWithANULOrAnEqualsSign(t *testing.T) {
	for _, name := range []string{"A\x00B", "A=B", "A\x00"} {
		if _, _, err := parseExec([]string{"--unset", name, "--", "true"}); err == nil {
			t.Errorf("%q was taken as a name", name)
		}
	}
	names, argv, err := parseExec([]string{"--unset", "A", "--unset", "_B1", "--", "p", "--unset", "C"})
	if err != nil || len(names) != 2 || names[1] != "_B1" || len(argv) != 3 || argv[1] != "--unset" {
		t.Errorf("parseExec: %q, %q, %v", names, argv, err)
	}
}

// TestReadMeasureReadsTheCgroupFiles pins what the helper's exec reads of the cgroup
// v2 files: nothing without memory.max; peak_memory_bytes from memory.peak and
// cpu_time_ms from usage_usec in cpu.stat, in milliseconds rounded down; and each
// member left out, apart from the other, never 0, when its file is missing or its value is not a
// whole number of 0 or more, as under gVisor, which emulates /sys/fs/cgroup.
func TestReadMeasureReadsTheCgroupFiles(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		want  map[string]any
	}{
		{"no memory.max", map[string]string{"memory.peak": "4096\n", "cpu.stat": "usage_usec 2500\n"}, nil},
		{"both", map[string]string{"memory.max": "max\n", "memory.peak": "4096\n", "cpu.stat": "usage_usec 2500999\nuser_usec 1\nsystem_usec 2\n"},
			map[string]any{"peak_memory_bytes": int64(4096), "cpu_time_ms": int64(2500)}},
		{"memory.max and no memory.peak", map[string]string{"memory.max": "8589934592\n", "cpu.stat": "usage_usec 5000\n"},
			map[string]any{"cpu_time_ms": int64(5)}},
		{"memory.max and no cpu.stat", map[string]string{"memory.max": "max\n", "memory.peak": "1\n"},
			map[string]any{"peak_memory_bytes": int64(1)}},
		{"no usage_usec line", map[string]string{"memory.max": "max\n", "memory.peak": "7", "cpu.stat": "user_usec 1000\n"},
			map[string]any{"peak_memory_bytes": int64(7)}},
		{"values that do not parse", map[string]string{"memory.max": "max\n", "memory.peak": "lots\n", "cpu.stat": "usage_usec -5\n"}, map[string]any{}},
		{"a value past int64", map[string]string{"memory.max": "max\n", "memory.peak": "99999999999999999999\n", "cpu.stat": "usage_usec 1.5\n"}, map[string]any{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range c.files {
				if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := readMeasure(root); !maps.Equal(got, c.want) || (got == nil) != (c.want == nil) {
				t.Errorf("readMeasure: %v, want %v", got, c.want)
			}
		})
	}
}

// TestSendMeasureSendsOneRecord pins what the helper's exec sends to the session's
// socket: one record of the measure source with the members it read, and nothing when
// it read none.
func TestSendMeasureSendsOneRecord(t *testing.T) {
	sock, err := socket.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []descriptor.Record
	go sock.Serve(func(rec descriptor.Record) {
		mu.Lock()
		got = append(got, rec)
		mu.Unlock()
	}, nil)
	root := t.TempDir()
	for name, content := range map[string]string{"memory.max": "max\n", "memory.peak": "123\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := sendMeasure(sock.Path(), root); err != nil {
		t.Fatal(err)
	}
	if err := sendMeasure(sock.Path(), t.TempDir()); err != nil {
		t.Fatal(err)
	}
	sock.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Source != descriptor.SourceMeasure || !maps.Equal(got[0].Record, map[string]any{"peak_memory_bytes": float64(123)}) {
		t.Errorf("the socket read %+v; want one measure record with peak_memory_bytes 123", got)
	}
}
