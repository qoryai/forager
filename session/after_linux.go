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

// procID is a process as /proc lists it: its number and its start time in clock ticks
// after the machine's boot, which together tell it from a later process with the same
// number.
type procID struct {
	pid   int
	start uint64
}

// startingProcesses are the processes /proc lists as Exec starts, before the program:
// pid 1, Exec, and with nested Docker the inner daemon and its containerd, which
// [wall.Nest] started as root. No process of the agent's runs yet.
func startingProcesses() []procID {
	var out []procID
	walkProcesses(func(p procID, _ string) { out = append(out, p) })
	return out
}

// walkProcesses calls f with each process /proc lists that has not exited, and its
// real user's number, and returns an error when /proc cannot be read.
func walkProcesses(f func(p procID, uid string)) error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// The fields after the command's name, which may contain spaces and ), are the
		// state, third, and the start time, the 22nd.
		cut := strings.LastIndexByte(string(stat), ')')
		if cut < 0 {
			continue
		}
		fields := strings.Fields(string(stat[cut+1:]))
		if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
			continue
		}
		start, err := strconv.ParseUint(fields[19], 10, 64)
		if err != nil {
			continue
		}
		uid := ""
		if b, err := os.ReadFile("/proc/" + e.Name() + "/status"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if f := strings.Fields(l); len(f) >= 2 && f[0] == "Uid:" {
					uid = f[1]
				}
			}
		}
		f(procID{pid, start}, uid)
	}
	return nil
}

// stopOthers stops every other process of the container that Exec can stop: it sends
// SIGKILL to each process of its user but itself and pid 1, and with docker removes,
// through the inner daemon's API on [wall.NestSocket], the swarm's services, the
// swarm itself, every plugin and every container, until no process is left that kept
// does not list and no inner object is left. kept are the processes that ran before
// the program, [startingProcesses]: those of every user count. A list that fails, or
// that the daemon does not answer in time, counts as objects left. It returns an error
// when Exec does not run as a container's first program, or when a process or an inner
// object is still left after wait.
func stopOthers(docker bool, wait time.Duration, kept []procID) error {
	if !contained() {
		return errors.New("the helper's exec does not run as the first program of a container, so it stops no process")
	}
	deadline := time.Now().Add(wait)
	for {
		// kill(-1) reaches every process the caller may signal but itself and pid 1.
		unix.Kill(-1, unix.SIGKILL)
		var innerErr error
		inner := 0
		if docker {
			inner, innerErr = removeInner(deadline)
		}
		left, err := othersLeft(kept)
		if err == nil && innerErr == nil && left == 0 && inner == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			switch {
			case err != nil:
				return fmt.Errorf("the processes left could not be listed: %v", err)
			case innerErr != nil:
				return fmt.Errorf("%d processes were still running after %s, and the inner daemon's objects could not be removed: %v", left, wait, innerErr)
			}
			return fmt.Errorf("%d processes and %d inner containers, plugins, services or swarms were still there after %s", left, inner, wait)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// othersLeft counts the processes of every user, but Exec, pid 1, those of kept and
// those that have exited and wait to be reaped, that /proc lists.
func othersLeft(kept []procID) (int, error) {
	self := os.Getpid()
	n := 0
	err := walkProcesses(func(p procID, _ string) {
		if p.pid != self && p.pid != 1 && !slices.Contains(kept, p) {
			n++
		}
	})
	return n, err
}

// innerSocket is the inner daemon's socket, [wall.NestSocket], or a test's.
var innerSocket = wall.NestSocket

// innerWait is the longest one call of the inner daemon's API may take.
const innerWait = time.Second

// removeInner removes, through the inner daemon's API, the swarm's services, the
// swarm, each plugin and each container, running or not, and returns how many it
// listed. It returns an error when a list or a removal fails, or when the daemon does
// not answer one within innerWait and before deadline: what it could not list may be
// left.
func removeInner(deadline time.Time) (int, error) {
	// No call outlasts the stop's deadline, so the stop takes at most its wait.
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	client := &http.Client{Timeout: innerWait, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", innerSocket)
		},
	}}
	call := func(method, path string, out any) error {
		req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		switch {
		case method == http.MethodDelete && resp.StatusCode == http.StatusNotFound:
			// Gone already.
			return nil
		case resp.StatusCode/100 != 2:
			return fmt.Errorf("%s %s: status %d", method, path, resp.StatusCode)
		case out != nil:
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}
	var errs []error
	n := 0
	var info struct {
		Swarm struct {
			LocalNodeState string
		}
	}
	if err := call(http.MethodGet, "/info", &info); err != nil {
		return n, err
	}
	if state := info.Swarm.LocalNodeState; state != "" && state != "inactive" {
		// A swarm's services start their tasks again: they go first, then the swarm.
		var services []struct {
			ID string
		}
		if err := call(http.MethodGet, "/services", &services); err != nil {
			errs = append(errs, err)
		}
		for _, s := range services {
			errs = append(errs, call(http.MethodDelete, "/services/"+url.PathEscape(s.ID), nil))
		}
		errs = append(errs, call(http.MethodPost, "/swarm/leave?force=true", nil))
		n += 1 + len(services)
	}
	var plugins []struct {
		Name string
	}
	if err := call(http.MethodGet, "/plugins", &plugins); err != nil {
		return n, err
	}
	for _, p := range plugins {
		errs = append(errs, call(http.MethodDelete, "/plugins/"+url.PathEscape(p.Name)+"?force=true", nil))
	}
	var containers []struct {
		ID string `json:"Id"`
	}
	if err := call(http.MethodGet, "/containers/json?all=true", &containers); err != nil {
		return n, err
	}
	for _, c := range containers {
		errs = append(errs, call(http.MethodDelete, "/containers/"+url.PathEscape(c.ID)+"?force=true&v=true", nil))
	}
	return n + len(plugins) + len(containers), errors.Join(errs...)
}

// readOnlyMount reports whether p is on a mount that is read-only.
func readOnlyMount(p string) bool {
	var fs unix.Statfs_t
	return unix.Statfs(p, &fs) == nil && fs.Flags&unix.ST_RDONLY != 0
}
