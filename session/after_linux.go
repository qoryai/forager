package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/qoryai/forager/wall"
)

// initialPIDNamespace is the pid namespace of a machine's first process: a process in
// it is not in a container.
const initialPIDNamespace = "pid:[4026531836]"

// containerInits are the names, in /proc/1/comm, of the init programs an engine runs
// as a container's pid 1: Docker's --init, tini, and Podman's.
var containerInits = []string{"docker-init", "tini", "catatonit"}

// contained reports whether Exec runs as a container's first program: its parent is
// the container's init, pid 1, an engine's init program, in a pid namespace that is
// not the machine's. Exec stops other processes only there, since kill(-1) outside a
// container reaches every process of the user.
func contained() bool {
	ns, err := os.Readlink("/proc/self/ns/pid")
	if err != nil || ns == initialPIDNamespace || os.Getppid() != 1 {
		return false
	}
	comm, err := os.ReadFile("/proc/1/comm")
	return err == nil && slices.Contains(containerInits, strings.TrimSpace(string(comm)))
}

// stopOthers stops every other process of the container that Exec can stop: it sends
// SIGKILL to each process of its user but itself and pid 1, and with docker removes
// each container of the inner daemon on [wall.NestSocket], until no such process and
// no inner container is left. It returns an error when Exec does not run as a
// container's first program, or when one is still left after wait.
func stopOthers(docker bool, wait time.Duration) error {
	if !contained() {
		return errors.New("the helper's exec does not run as the first program of a container, so it stops no process")
	}
	deadline := time.Now().Add(wait)
	for {
		// kill(-1) reaches every process the caller may signal but itself and pid 1.
		unix.Kill(-1, unix.SIGKILL)
		inner := 0
		if docker {
			inner = removeInner()
		}
		left := othersLeft()
		if left == 0 && inner == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d processes and %d inner containers were still running after %s", left, inner, wait)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// othersLeft counts the processes of Exec's user, but Exec, pid 1 and those that
// have exited and wait to be reaped, that /proc lists.
func othersLeft() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	self, uid := os.Getpid(), strconv.Itoa(os.Getuid())
	n := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self || pid == 1 {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/status")
		if err != nil {
			continue
		}
		var state, real string
		for _, l := range strings.Split(string(b), "\n") {
			switch f := strings.Fields(l); {
			case len(f) >= 2 && f[0] == "State:":
				state = f[1]
			case len(f) >= 2 && f[0] == "Uid:":
				real = f[1]
			}
		}
		if real == uid && state != "Z" && state != "X" {
			n++
		}
	}
	return n
}

// removeInner removes each running container of the inner daemon, killing it, and
// returns how many it listed. A daemon it cannot reach lists none.
func removeInner() int {
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", wall.NestSocket)
		},
	}}
	resp, err := client.Get("http://docker/containers/json")
	if err != nil {
		return 0
	}
	var listed []struct {
		ID string `json:"Id"`
	}
	err = json.NewDecoder(resp.Body).Decode(&listed)
	resp.Body.Close()
	if err != nil {
		return 0
	}
	for _, c := range listed {
		req, err := http.NewRequest(http.MethodDelete, "http://docker/containers/"+url.PathEscape(c.ID)+"?force=true", nil)
		if err != nil {
			continue
		}
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	return len(listed)
}

// readOnlyMount reports whether p is on a mount that is read-only.
func readOnlyMount(p string) bool {
	var fs unix.Statfs_t
	return unix.Statfs(p, &fs) == nil && fs.Flags&unix.ST_RDONLY != 0
}
