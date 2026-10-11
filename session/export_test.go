package session

import (
	"context"
	"sync"

	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/wall"
)

// trusted are the authorities' files of the separate gateways a test trusts, by URL.
var trusted sync.Map

func init() {
	remoteTrust = func(u string) server.RemoteTLS {
		if f, ok := trusted.Load(u); ok {
			return server.RemoteTLS{CAFile: f.(string)}
		}
		return server.RemoteTLS{}
	}
}

// TrustRemote trusts the certificate chain of the separate gateway at url to the
// authorities of caFile, until untrust is called; any other gateway's to the system's
// roots.
func TrustRemote(url, caFile string) (untrust func()) {
	trusted.Store(url, caFile)
	return func() { trusted.Delete(url) }
}

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

// SetExitObserved sets what a run calls the moment its runtime's exit is observed,
// once Cancelled is decided; nil for nothing.
func SetExitObserved(f func()) { exitObserved = f }
