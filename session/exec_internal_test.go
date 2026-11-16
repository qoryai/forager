package session

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
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
		{"a value over 2^53-1", map[string]string{"memory.max": "max\n", "memory.peak": "9007199254740992\n", "cpu.stat": "usage_usec 9007199254740991999\n"},
			map[string]any{"cpu_time_ms": int64(9007199254740991)}},
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
	go sock.Serve(func(rec descriptor.Record) error {
		mu.Lock()
		got = append(got, rec)
		mu.Unlock()
		return nil
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

// TestCheckRuntimeMountsRefusesAMountOverTheRuntime pins the check of the helper's exec
// on the mount table: the wall's binds, the runtime's folder once for each runtime
// among them, pass, and so do a mount point with an escaped space and a shiftfs mount
// on a runtime's bind. A mount at /qory, at /qory/runtime, a second one at a runtime's
// folder that is not a shiftfs mount on the first, or one below it, fails with a line
// that starts with the fix and has the mount point.
func TestCheckRuntimeMountsRefusesAMountOverTheRuntime(t *testing.T) {
	line := func(id int, point string) string {
		return fmt.Sprintf("%d 1 0:5%d /src%d %s ro,relatime - ext4 /dev/sda1 rw\n", id, id, id, point)
	}
	shifted := func(id, parent int, point, fsType string) string {
		return fmt.Sprintf("%d %d 0:6%d / %s ro,relatime shared:4 - %s %s ro\n", id, parent, id, point, fsType, point)
	}
	base := line(1, "/") + line(2, "/qory/qory") + line(3, "/qory/hooks") + line(4, "/qory/runtime/claude") +
		line(5, "/workspace") + line(6, "/qory/runtime/codex") + line(7, `/work\040space`) + line(8, "/qory/runtimes")
	if err := checkRuntimeMounts(base, ""); err != nil {
		t.Fatalf("the wall's binds: %v", err)
	}
	if err := checkRuntimeMounts(base+shifted(9, 4, "/qory/runtime/claude", "shiftfs"), ""); err != nil {
		t.Errorf("a shiftfs mount on the runtime's bind: %v", err)
	}
	for _, c := range []struct{ name, extra, want string }{
		{"a mount at /qory", line(9, "/qory"), "/qory"},
		{"a mount at /qory/runtime", line(9, "/qory/runtime"), "/qory/runtime"},
		{"a second mount at the folder", line(9, "/qory/runtime/claude"), "/qory/runtime/claude"},
		{"a second mount at the folder on the bind, not shiftfs", shifted(9, 4, "/qory/runtime/claude", "ext4"),
			"/qory/runtime/claude"},
		{"a shiftfs mount at the folder on another mount", shifted(9, 6, "/qory/runtime/claude", "shiftfs"),
			"/qory/runtime/claude"},
		{"a third mount at the folder", shifted(9, 4, "/qory/runtime/claude", "shiftfs") +
			shifted(10, 9, "/qory/runtime/claude", "shiftfs"), "/qory/runtime/claude"},
		{"a mount below the folder", line(9, "/qory/runtime/claude/bin"), "/qory/runtime/claude/bin"},
		{"an escaped mount below the folder", line(9, `/qory/runtime/claude/my\040bin`), "/qory/runtime/claude/my bin"},
	} {
		err := checkRuntimeMounts(base+c.extra, "")
		if err == nil || !strings.HasPrefix(err.Error(), "remove the image's symbolic link that leads a mount to "+c.want+":") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if got := unescapeMountPoint(`/a\134b\011c\04`); got != "/a\\b\tc\\04" {
		t.Errorf("unescapeMountPoint: %q", got)
	}
}

// TestCheckRuntimeMountsRefusesAProgramOutsideItsBind pins the check of the helper's
// exec for a program below /qory/runtime/<runtime>: it passes with one bind there, or
// one and a shiftfs mount on it, and fails with none, as when an image's symbolic link
// at /qory led the bind elsewhere. A program elsewhere needs no mount.
func TestCheckRuntimeMountsRefusesAProgramOutsideItsBind(t *testing.T) {
	const program = "/qory/runtime/claude/bin/claude"
	bound := "1 0 0:51 / / rw - ext4 /dev/sda1 rw\n" +
		"4 1 0:54 /src /qory/runtime/claude ro,relatime - ext4 /dev/sda1 rw\n"
	for _, c := range []struct{ name, mountinfo, program string }{
		{"one bind", bound, program},
		{"a shiftfs mount on it", bound + "9 4 0:69 / /qory/runtime/claude ro - shiftfs /qory/runtime/claude ro\n", program},
		{"no bind, another folder", "1 0 0:51 / / rw - ext4 /dev/sda1 rw\n", "/usr/local/bin/claude"},
	} {
		if err := checkRuntimeMounts(c.mountinfo, c.program); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	moved := "1 0 0:51 / / rw - ext4 /dev/sda1 rw\n" +
		"4 1 0:54 /src /work/runtime/claude ro,relatime - ext4 /dev/sda1 rw\n"
	err := checkRuntimeMounts(moved, program)
	if err == nil || !strings.HasPrefix(err.Error(), "remove the image's symbolic link at or above /qory/runtime/claude:") {
		t.Errorf("a program with no bind at its folder: %v", err)
	}
}

// TestCheckRuntimeLinksRefusesALinkAtQory pins the check of the helper's exec on /qory
// and /qory/runtime: folders, or no such path, pass; a symbolic link at either fails
// with a line that starts with the fix.
func TestCheckRuntimeLinksRefusesALinkAtQory(t *testing.T) {
	root := t.TempDir()
	if err := checkRuntimeLinks(root); err != nil {
		t.Errorf("no /qory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "qory", "runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkRuntimeLinks(root); err != nil {
		t.Errorf("folders: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "work"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, at := range []string{"/qory/runtime", "/qory"} {
		p := filepath.Join(root, at)
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "work"), p); err != nil {
			t.Fatal(err)
		}
		err := checkRuntimeLinks(root)
		if err == nil || !strings.HasPrefix(err.Error(), "replace the image's symbolic link "+at+" with a folder:") {
			t.Errorf("a link at %s: %v", at, err)
		}
	}
}

// TestProgramPathIsAbsolute pins the path the helper's exec checks for the program: the
// path LookPath found, or the argument, made absolute; none for a bare name not found.
func TestProgramPathIsAbsolute(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ arg, found, want string }{
		{"/qory/runtime/claude/bin/claude", "", "/qory/runtime/claude/bin/claude"},
		{"claude", "/qory/runtime/claude/bin/claude", "/qory/runtime/claude/bin/claude"},
		{"/qory/runtime/x/../claude/bin/claude", "", "/qory/runtime/claude/bin/claude"},
		{"bin/claude", "bin/claude", filepath.Join(wd, "bin", "claude")},
		{"claude", "", ""},
	} {
		if got := programPath(c.arg, c.found); got != c.want {
			t.Errorf("programPath(%q, %q) = %q; want %q", c.arg, c.found, got, c.want)
		}
	}
}
