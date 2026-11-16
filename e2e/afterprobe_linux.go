//go:build linux

package e2e

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/qoryai/forager/wall"
)

// afterInspect is [modeAfterInspect]'s program, After's command. It finds the helper
// among the processes of the container, the one that runs wall.HelperPath with --after-only,
// and writes into afterInspectFile one line for each thing it tried against it, as
// "name: result": whether it listed the helper's descriptors, read its environment and
// followed its socket's descriptor, with each error's text, and whether it took any of
// the descriptors 0 to 11 with pidfd_getfd. It also connects to After's socket a second
// time and sends a forged exit.
func afterInspect() int {
	var out strings.Builder
	say := func(name string, err error) {
		switch {
		case err == nil:
			fmt.Fprintf(&out, "%s: allowed\n", name)
		case errors.Is(err, os.ErrPermission), errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
			fmt.Fprintf(&out, "%s: denied\n", name)
		default:
			fmt.Fprintf(&out, "%s: failed: %v\n", name, err)
		}
	}
	found := false
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cmdline, _ := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		// The helper's command line is the helper's path, exec and --after-only; the
		// container's init has them too, after its own, and is not the helper.
		if !strings.HasPrefix(string(cmdline), wall.HelperPath+"\x00") || !strings.Contains(string(cmdline), "--after-only") {
			continue
		}
		found = true
		_, err = os.ReadDir("/proc/" + e.Name() + "/fd")
		say("list the helper's descriptors", err)
		_, err = os.ReadFile("/proc/" + e.Name() + "/environ")
		say("read the helper's environment", err)
		_, err = os.Readlink("/proc/" + e.Name() + "/fd/3")
		say("follow the helper's descriptor 3", err)
		say("attach to the helper with ptrace", syscall.PtraceAttach(pid))
		pfd, err := unix.PidfdOpen(pid, 0)
		say("open the helper with pidfd_open", err)
		if err == nil {
			taken := 0
			for fd := 0; fd < 12; fd++ {
				if nfd, err := unix.PidfdGetfd(pfd, fd, 0); err == nil {
					taken++
					syscall.Close(nfd)
				}
			}
			fmt.Fprintf(&out, "descriptors taken with pidfd_getfd: %d\n", taken)
		}
	}
	if !found {
		out.WriteString("no helper found\n")
	}
	if conn, err := net.Dial("unix", afterSocket); err == nil {
		conn.Write([]byte(`{"source":"after","record":{"event":"exited","exit_code":0}}` + "\n"))
		conn.Close()
		out.WriteString("second connection: made\n")
	} else {
		fmt.Fprintf(&out, "second connection: %v\n", err)
	}
	if err := os.WriteFile(afterInspectFile, []byte(out.String()), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "after-inspect:", err)
		return 1
	}
	return 3
}
