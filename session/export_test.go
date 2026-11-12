package session

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/qoryai/forager/wall"
)

// SetCgroupRoot sets where [Exec] reads the enclosure's cgroup v2 files.
func SetCgroupRoot(root string) { cgroupRoot = root }

// SetExecHooks sets what [Exec] calls just before it starts the program and once it
// has reaped it; nil for nothing.
func SetExecHooks(before, after func()) { beforeStart, afterWait = before, after }

// SetUserHome sets the home of the user the session runs as, where the session reads
// the transcript of a runtime with resume whose launch has no HOME, and returns the
// home it replaced.
func SetUserHome(dir string) string {
	old, _ := userHome()
	userHome = func() (string, error) { return dir, nil }
	return old
}

// SetTranscriptPoll sets how often a join of spec reads the runtime's transcript.
func SetTranscriptPoll(spec *SessionSpec, d time.Duration) { spec.transcriptPoll = d }

// TranscriptReaders is the number of goroutines that read a runtime's transcript.
func TranscriptReaders() int { return len(transcriptStacks()) }

// transcriptStacks are the stacks of the goroutines that read a runtime's transcript:
// those that contain [transcript.run].
func transcriptStacks() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	var readers []string
	for g := range strings.SplitSeq(string(buf), "\n\n") {
		if strings.Contains(g, "session.(*transcript).run(") {
			readers = append(readers, g)
		}
	}
	return readers
}

// SetCloseWait sets how long the sinks get to flush at the end of a join and at the
// close, and returns the wait it replaced.
func SetCloseWait(d time.Duration) time.Duration {
	old := closeWait
	closeWait = d
	return old
}

// SetFinalWait sets how long the sinks get to flush at the close of a run behind a
// separate gateway, and returns the wait it replaced.
func SetFinalWait(d time.Duration) time.Duration {
	old := finalWait
	finalWait = d
	return old
}

// SetJoinRetry sets how long a join request is sent again after a try with no answer
// or a 503, and the waits between the tries, the last one repeated; it returns a
// function that sets back what it replaced.
func SetJoinRetry(window time.Duration, waits ...time.Duration) (restore func()) {
	oldWindow, oldWaits := joinWindow, joinWaits
	joinWindow, joinWaits = window, waits
	return func() { joinWindow, joinWaits = oldWindow, oldWaits }
}

// SetRegisterPause sets what a run calls between its check against the registry of
// walled runs and the writing of its entry, under the registry's lock; nil for nothing.
func SetRegisterPause(f func(runID string)) { registerPause = f }

// SetRunContainersExist sets what the registry asks whether a run's containers exist;
// nil for the engine's answer.
func SetRunContainersExist(
	f func(ctx context.Context, e wall.Engine, runID string) (bool, error),
) {
	if f == nil {
		runContainersExist = askContainers
		return
	}
	runContainersExist = func(
		ctx context.Context, _ *wall.Docker, e wall.Engine, runID string,
	) (bool, error) {
		return f(ctx, e, runID)
	}
}

// SetRunContainersAsked sets what the registry asks whether a run's containers exist,
// with the Docker of the run that asks, nil for another wall; nil for the engine's
// answer.
func SetRunContainersAsked(
	f func(ctx context.Context, d *wall.Docker, e wall.Engine, runID string) (bool, error),
) {
	if f == nil {
		f = askContainers
	}
	runContainersExist = f
}

// BindLookups are the entries looked up on the way to p, as a walled run records them
// for a bind in its entry in the registry.
func BindLookups(p string) ([]string, error) {
	looks, err := lookups(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range looks {
		out = append(out, l.entry())
	}
	return out, nil
}

// DirInBinds fails a working directory that lies in none of the binds.
var DirInBinds = dirInBinds

// SetExitObserved sets what a run calls the moment its runtime's exit is observed,
// once Cancelled is decided; nil for nothing.
func SetExitObserved(f func()) { exitObserved = f }

// Readable is what a runtime is given to ask of a file before it reads it from this
// machine, for the places a walled run could have written.
func Readable(places []string) func(string) (string, error) {
	return readable(func() ([]string, error) { return places, nil })
}

// SetMachineBundles sets the files an unwalled run reads the machine's authorities
// from, until restore is called.
func SetMachineBundles(paths []string) (restore func()) {
	old := machineBundles
	machineBundles = func() []string { return paths }
	return func() { machineBundles = old }
}

// SetEngineCertsDir sets where Run.EngineProxy writes the run's certificate, until
// restore is called.
func SetEngineCertsDir(dir string) (restore func()) {
	old := engineCertsDir
	engineCertsDir = dir
	return func() { engineCertsDir = old }
}

// ReadableDir is what a runtime is given to ask of a directory before it passes it to
// the program, for the places a walled run could have written.
func ReadableDir(places []string) func(string) (string, error) {
	return readableDir(func() ([]string, error) { return places, nil })
}

// HoldJoining takes the run's joining lock, as Join and the host steps take it, and
// returns the call that gives it back.
func HoldJoining(r *Run) func() {
	r.joining.Lock()
	return r.joining.Unlock
}

// OpenHostProxies is how many of the run's forwarders for host work are open.
func OpenHostProxies(r *Run) int {
	r.hosts.mu.Lock()
	defer r.hosts.mu.Unlock()
	return len(r.hosts.open)
}

// SetManifestRoots sets authorities, as PEM, that the check of a run's image at its
// registry trusts beside the machine's and the run's, nil for none, and returns what
// they were.
func SetManifestRoots(pem []byte) []byte {
	old := manifestRoots
	manifestRoots = pem
	return old
}

// SetManifestCheck sets what checks a run's image by reference at its registry, in
// place of the request through the run's proxy, and returns a function that restores
// the request.
func SetManifestCheck(f func(ctx context.Context, image string) error) (restore func()) {
	manifestHook = f
	return func() { manifestHook = nil }
}

// SetManifestWait sets how long the check of a run's image at its registry may take,
// and returns what it was.
func SetManifestWait(d time.Duration) time.Duration {
	old := manifestWait
	manifestWait = d
	return old
}

// WallForwarder starts the forwarder a walled run has, whose address a wall's relay
// forwards to, and returns its address and the token the relay opens each connection
// with, and how to stop it: on one machine the run's proxy secret, and behind a separate
// gateway a hop token.
func (r *Run) WallForwarder() (addr, token string, stop func(), err error) {
	var f *forwarder
	if r.remote == nil {
		token = r.answer.ProxySecret
		f, err = listenForwarder("127.0.0.1:0", r.disc.Proxy.Address, "", "")
	} else {
		if token, err = newForwarderSecret(); err != nil {
			return "", "", nil, err
		}
		f, err = listenForwarding("127.0.0.1:0", forwarding{dial: r.link.DialProxy, hop: token})
	}
	if err != nil {
		return "", "", nil, err
	}
	return f.Addr(), token, func() { f.Close() }, nil
}

// WallProxy returns the address of a walled run's forwarder, where the wall's relay
// sends every connection, and the token the relay opens each connection with.
func (r *Run) WallProxy() (addr, token string) { return r.wallFwd.Addr(), r.relayToken }
