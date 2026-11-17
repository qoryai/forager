package session

import (
	"errors"
	"fmt"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/server"
)

// PushProxy starts a forwarder on loopback with a fresh password for qory's push and the
// calls of its submit step. Every request through it reaches the run's push proxy at
// the gateway, which allows the hosts and paths of the run configuration's push
// credentials alone, sets those credentials, with the branch guard of each item's
// push_ref, and returns a 403 for every other request; the run's policy does not apply
// there, and each decision is a dev.qory.run.egress with channel push. The run's proxy,
// which the sessions, the setup step, After and [Run.HostProxy] go through, never sets
// a push credential. Env and CABundle are as [Run.HostProxy] sets them.
//
// It ends at [HostProxy.Close], at the next [Run.Join] or at [Run.Close], as the host
// proxy does; the gateway keeps the run's push proxy open until the run closes, so a
// PushProxy after a session reaches it again. An error means no push proxy started: the
// run's open listed no push credential in policy_applied, a session of the run is
// running, the run is closed, a copy step is open, the wall of a session could not be
// removed and may still run, a walled run with an authority has no bundle, or the
// forwarder's port could not be opened.
//
// On one machine it opens each connection to the gateway's proxy with the relay's
// preamble and the run answer's push_proxy_secret, and behind a separate gateway it
// dials the gateway's one address with [link.PushPreamble] and the run key
// ([server.Link.DialPush]). The password is checked as the host proxy's is, and the
// run's masker gets it before the forwarder starts. Neither the push proxy secret nor
// the run key enters the wall or a container.
func (r *Run) PushProxy() (HostProxy, error) {
	if !r.joining.TryLock() {
		return HostProxy{}, errors.New("Call PushProxy after Join returns: a session of the run is still running.")
	}
	defer r.joining.Unlock()
	if r.closed {
		return HostProxy{}, errors.New("Open another run: this run is closed.")
	}
	if !r.hasPush() {
		return HostProxy{}, errors.New("Add a push credential to the run configuration: this run has no push proxy.")
	}
	if r.hostStep != nil && r.hostStep.kind == event.StepCopy {
		return HostProxy{}, fmt.Errorf("Exit the copy step before you start the push proxy: a join during it closes the push proxy.\nThe copy step is step %d.", r.hostStep.n)
	}
	if err := r.wallKept(); err != nil {
		return HostProxy{}, err
	}
	if r.bundleErr != nil {
		return HostProxy{}, r.bundleErr
	}
	password, err := newForwarderSecret()
	if err != nil {
		return HostProxy{}, err
	}
	r.addPassword(password)
	var fwd *forwarder
	if r.remote == nil {
		fwd, err = listenForwarder(link.Loopback, r.disc.Proxy.Address, r.answer.PushProxySecret, password)
	} else {
		fwd, err = listenForwarding(link.Loopback, forwarding{dial: r.link.DialPush, hold: gatewayHold, password: password})
	}
	if err != nil {
		return HostProxy{}, err
	}
	r.hosts.add(fwd)
	return HostProxy{
		Env:      append(fwd.Env(), r.bundleVars...),
		ProxyURL: fwd.URL(),
		CABundle: r.bundle,
		close:    func() error { return r.hosts.close(fwd) },
	}, nil
}

// hasPush reports whether the run has a push proxy at the gateway: on one machine, the
// run answer's push_proxy_secret, and behind a separate gateway, a credential with
// purpose push among the members of policy_applied of the run's open.
func (r *Run) hasPush() bool {
	if r.remote == nil {
		return r.answer.PushProxySecret != ""
	}
	r.emitMu.Lock()
	creds, _ := r.members["credentials"].([]any)
	r.emitMu.Unlock()
	for _, e := range creds {
		if m, _ := e.(map[string]any); m != nil && m["purpose"] == server.PurposePush {
			return true
		}
	}
	return false
}
