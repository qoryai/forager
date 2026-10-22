package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/wall"
)

// FetchImage fetches the run's image that the policy names by its reference, as a host
// step of kind event.StepImage with the reference as its name, before the first join or
// between joins: the wall's [wall.Puller] pulls it, unless the engine holds it by that
// digest, and checks its user. With OpenSpec.EngineProxy the engine sends the pull
// through the run's proxy. For the step alone, a forwarder listens at its Addr, passes
// on only a request with its Password, and reaches the gateway's proxy as the host proxy
// does, and, for a run with a certificate authority, the engine trusts the run's
// certificate for the image's registry host and for each host of the run's
// credentials. Without EngineProxy the engine pulls over the machine's network. A join after the fetch finds the image by its digest and writes no
// image step; the first join of a run with no fetch fetches the image in its image
// step, after its dev.qory.session.started.
//
// A run whose image the machine defines, or whose wall is no wall.Puller, has nothing to
// fetch: FetchImage writes no step and returns nil.
//
// An error before the step means nothing is written: the run has no wall, a session of
// the run is running, the run is closed, a host step is open, a step fetched the image
// already, or EngineProxy is not a loopback host:port with a password. A failure of the
// fetch writes its line in the step and ends the step failed, or cancelled when ctx
// ended, with -1; an image whose user is root is a [*Refusal], image_user_root.
func (r *Run) FetchImage(ctx context.Context) error {
	if r.open.Wall == nil {
		return errors.New("Open the run with a wall to fetch its image: a run without a wall has no image.")
	}
	if !r.joining.TryLock() {
		return errors.New("Start the image's fetch after Join returns: a session of the run is still running.")
	}
	defer r.joining.Unlock()
	if r.closed {
		return fmt.Errorf("open a new run for the host step: the run is closed")
	}
	if r.hostStep != nil {
		return fmt.Errorf("Exit step %d before the image's fetch: one host step is open at a time.", r.hostStep.n)
	}
	if r.imageStep > 0 {
		return fmt.Errorf("Fetch the run's image once: step %d fetched it.", r.imageStep)
	}
	puller, ok := r.open.Wall.(wall.Puller)
	if !r.byReference || !ok {
		return nil
	}
	if err := checkEngineProxy(r.open.EngineProxy); err != nil {
		return err
	}
	r.hostStep = r.startStep(event.StepImage, r.img.Ref)
	step := r.hostStep
	if err := r.pullImage(ctx, puller); err != nil {
		r.writeLog("stderr", 0, step.n, failureLine(err))
		state := event.StateFailed
		if ctx.Err() != nil {
			state = event.StateCancelled
		}
		step.end(state, -1)
		return err
	}
	r.imageStep = step.n
	step.end(event.StateSucceeded, -1)
	return nil
}

// wallRequest is what the run's wall is asked for: the run's image, and Pull for an
// image by reference.
func (r *Run) wallRequest() wall.Request {
	return wall.Request{RunID: r.id, Image: r.img.Ref, Runtime: r.img.Runtime, Docker: r.img.Docker, RelayImage: r.relayImage, Pull: r.byReference}
}

// pullImage runs the wall's pull of the run's image by reference: with
// OpenSpec.EngineProxy behind the engine proxy's forwarder, which it closes before it
// returns, and with the run's certificate for the image's registry host and the hosts
// of the run's credentials. The caller holds r.joining and writes the step.
func (r *Run) pullImage(ctx context.Context, puller wall.Puller) error {
	p := r.open.EngineProxy
	if p == nil {
		return puller.Pull(ctx, r.wallRequest(), nil, nil)
	}
	if err := checkEngineProxy(p); err != nil {
		return err
	}
	// The masker replaces the password in every line of the run's record from here on.
	r.masker.AddProxy(proxyUser, p.Password)
	var fwd *forwarder
	var err error
	if r.remote == nil {
		fwd, err = listenForwarder(p.Addr, r.disc.Proxy.Address, r.answer.ProxySecret, p.Password)
	} else {
		fwd, err = listenForwarding(p.Addr, forwarding{dial: r.link.DialProxy, password: p.Password})
	}
	if err != nil {
		return accesskey.ShownError(err)
	}
	var hosts []string
	for _, c := range r.answer.CredentialHosts {
		hosts = append(hosts, c.Hosts...)
	}
	err = puller.Pull(ctx, r.wallRequest(), r.authority, hosts)
	err = errors.Join(err, fwd.Close())
	// An engine's error may quote its proxy setting, the password with it.
	if err != nil && strings.Contains(err.Error(), p.Password) {
		err = errors.New(r.masker.Replace(err.Error()))
	}
	return err
}

// checkEngineProxy refuses an engine proxy whose address is not a loopback host:port
// with a port from 1 to 65535, or whose password is empty. Nil is no engine proxy.
func checkEngineProxy(p *EngineProxy) error {
	if p == nil {
		return nil
	}
	if !engineAddr(p.Addr) {
		return fmt.Errorf("Set the engine proxy's address to a loopback host:port, such as 127.0.0.1:3129: %s is not one.", accesskey.ShownValue(p.Addr, true))
	}
	if p.Password == "" {
		return errors.New("Give the engine proxy the password from the daemon's proxy setting: the password is empty.")
	}
	return nil
}

// engineAddr reports whether addr is a loopback IP address and a port from 1 to 65535.
func engineAddr(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || !loopback(addr) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}
