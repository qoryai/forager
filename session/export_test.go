package session

import (
	"context"
	"time"

	"github.com/qoryai/forager/wall"
)

// SetCloseWait sets how long the sinks get to flush at the end of a join and at the
// close.
func SetCloseWait(d time.Duration) { closeWait = d }

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

// ReadableDir is what a runtime is given to ask of a directory before it passes it to
// the program, for the places a walled run could have written.
func ReadableDir(places []string) func(string) (string, error) {
	return readableDir(func() ([]string, error) { return places, nil })
}
