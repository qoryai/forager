package session

import (
	"errors"
	"sync"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/wall"
)

// engineCertsDir is where [Run.EngineProxy] writes the run's certificate, a directory
// per registry host; empty means /etc/docker/certs.d, as for the Docker wall.
var engineCertsDir string

// engineOpen is one open engine proxy: its forwarder, and what removes the run's
// certificates it wrote.
type engineOpen struct {
	fwd    *forwarder
	remove func() error
}

// engineProxies is the run's open engine proxy, at most one.
type engineProxies struct {
	mu   sync.Mutex
	open *engineOpen
}

// hold lists o as the open engine proxy. The caller checked that none is open.
func (e *engineProxies) hold(o *engineOpen) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.open = o
}

// held reports whether an engine proxy is open.
func (e *engineProxies) held() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.open != nil
}

// close ends o, when it is open still, or the open engine proxy when o is nil: its
// forwarder takes no connection, and its certificates are removed.
func (e *engineProxies) close(o *engineOpen) error {
	e.mu.Lock()
	if o == nil {
		o = e.open
	}
	if o == nil || e.open != o {
		e.mu.Unlock()
		return nil
	}
	e.open = nil
	e.mu.Unlock()
	return errors.Join(o.fwd.Close(), o.remove())
}

// closeEngine ends the open engine proxy at a join or at the close, and passes the
// error of a certificate that could not be removed to OpenSpec.Report.
func (r *Run) closeEngine() {
	if err := r.engine.close(nil); err != nil {
		r.open.Report(accesskey.ShownError(r.maskEngine(err, r.open.EngineProxy)).Error())
	}
}

// EngineProxy opens the engine proxy for host work in a run with no wall, such as a
// build whose pulls and push the machine's container engine sends through its proxy
// setting, OpenSpec.EngineProxy. A forwarder listens at OpenSpec.EngineProxy.Addr,
// passes on only a request with OpenSpec.EngineProxy.Password, and reaches the
// gateway's proxy as the host proxy does: with the run's proxy secret on one machine,
// and with the run key behind a separate gateway. The run's masker gets the password
// before the forwarder listens. For a run with a certificate authority, EngineProxy
// writes the run's certificate as qory-run-<id>.crt in /etc/docker/certs.d/<host>/ for
// each of hosts, as [wall.Trust] does; a host that cannot be a directory name, such as
// a *. pattern, gets none. Open it while a host step is open; it stays open after the
// step exits.
//
// close ends it: the forwarder takes no connection, and the certificates and the
// directories made for them are removed. The next [Run.Join] and [Run.Close] end it
// too, and pass the error of a certificate they could not remove to OpenSpec.Report.
// A second close, or a close after a join or the run's close, returns nil.
//
// An error means nothing is open and no certificate of the call is left: a session of
// the run is running, the run is closed, the run has a wall, whose image step listens
// at the engine proxy's address, OpenSpec.EngineProxy is nil or not a loopback
// host:port with a password of the shape a forwarder checks, no host step is open, an
// engine proxy of the run is open, the address is in use, or a certificate could not
// be written. Each error starts with its fix and contains no password.
func (r *Run) EngineProxy(hosts []string) (close func() error, err error) {
	if !r.joining.TryLock() {
		return nil, errors.New("Open the engine proxy after Join returns: a session of the run is still running.")
	}
	defer r.joining.Unlock()
	p := r.open.EngineProxy
	switch {
	case r.closed:
		return nil, errors.New("Open a new run for the engine proxy: the run is closed.")
	case r.open.Wall != nil:
		return nil, errors.New("Open the engine proxy in a run with no wall: a walled run's image step listens at the engine proxy's address.")
	case p == nil:
		return nil, errors.New("Set OpenSpec.EngineProxy to the engine's proxy setting: the run has no engine proxy.")
	case r.hostStep == nil:
		return nil, errors.New("Start a host step before you open the engine proxy: the engine proxy opens only during a host step.")
	case r.engine.held():
		return nil, errors.New("Close the engine proxy before you open it again: the engine has one proxy setting, and the run's engine proxy is open.")
	}
	fwd, err := r.listenEngine(p)
	if err != nil {
		return nil, r.maskEngine(err, p)
	}
	remove := func() error { return nil }
	if len(r.authority) > 0 {
		remove, err = wall.Trust(engineCertsDir, r.id, r.authority, hosts)
		if err != nil {
			return nil, r.maskEngine(errors.Join(err, fwd.Close()), p)
		}
	}
	o := &engineOpen{fwd: fwd, remove: remove}
	r.engine.hold(o)
	return func() error { return r.maskEngine(r.engine.close(o), p) }, nil
}
