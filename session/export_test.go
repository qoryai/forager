package session

import (
	"context"

	"github.com/qoryai/forager/wall"
)

// SetRegisterPause sets what a run calls between its check against the registry of
// walled runs and the writing of its entry, under the registry's lock; nil for nothing.
func SetRegisterPause(f func(runID string)) { registerPause = f }

// SetRunContainersExist sets what the registry asks whether a run's containers exist;
// nil for the engine's own answer.
func SetRunContainersExist(
	f func(ctx context.Context, e wall.Engine, runID string) (bool, error),
) {
	if f == nil {
		f = wall.RunContainersExist
	}
	runContainersExist = f
}

// DirInBinds fails a working directory that lies in none of the binds.
var DirInBinds = dirInBinds
