package session

import (
	"errors"
	"slices"
	"sync"

	"github.com/qoryai/forager/link"
)

// HostProxy is a forwarder on loopback for the programs of the run's host work, such
// as a fetch of the run's repositories or a compose of the harness: every request
// through it reaches the run's proxy, under the run's policy, and gets the run's
// credentials there. [Run.HostProxy] starts it, for every run, walled or not. It ends
// at [HostProxy.Close], at the next [Run.Join] or at [Run.Close]; from then on its port
// takes no connection.
//
// Its proxy URL has a password, 32 random bytes in base64url made for this forwarder
// alone, which every request must carry in its Proxy-Authorization, as the password of
// an unwalled session's proxy URL. Forager writes the password into no event, no run
// file and no report line, and the run's masker replaces it in the runtime's output.
type HostProxy struct {
	// Env is the variables that point a program at the forwarder: HTTP_PROXY,
	// HTTPS_PROXY, their lower-case forms and NO_PROXY, as [link.ProxyEnv] sets them to
	// ProxyURL, then, when CABundle is set, each variable of OpenSpec.CAEnv set to its
	// path.
	Env []string
	// ProxyURL is the forwarder's URL with its password,
	// http://qory:<password>@127.0.0.1:<port>.
	ProxyURL string
	// CABundle is the path of ca-bundle.pem in the run directory, the machine's
	// authorities and then the run's certificate; empty for a run with no certificate
	// authority.
	CABundle string

	close func() error
}

// Close ends the host proxy: its port takes no connection, and every connection
// through it closes. A host proxy that has ended already is left as it is.
func (h HostProxy) Close() error {
	if h.close == nil {
		return nil
	}
	return h.close()
}

// hostProxies are the run's open host proxies.
type hostProxies struct {
	mu   sync.Mutex
	open []*forwarder
}

// add lists f as open.
func (h *hostProxies) add(f *forwarder) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.open = append(h.open, f)
}

// close ends f, when it is open still.
func (h *hostProxies) close(f *forwarder) error {
	h.mu.Lock()
	i := slices.Index(h.open, f)
	if i >= 0 {
		h.open = slices.Delete(h.open, i, i+1)
	}
	h.mu.Unlock()
	if i < 0 {
		return nil
	}
	return f.Close()
}

// closeAll ends every open host proxy.
func (h *hostProxies) closeAll() {
	h.mu.Lock()
	all := h.open
	h.open = nil
	h.mu.Unlock()
	for _, f := range all {
		f.Close()
	}
}

// HostProxy starts a forwarder on loopback with a fresh password for the run's host
// work, walled or not: on one machine it opens each connection to the gateway's proxy
// with the run's proxy secret, and behind a separate gateway it dials the gateway's
// proxy with the run key, as an unwalled session's forwarder does. The run's masker
// gets the password before the forwarder starts. An error means no host proxy started:
// a session of the run is running, the run is closed, a walled run with an authority
// has no bundle because the machine has no CA bundle, or the forwarder's port could not
// be opened.
func (r *Run) HostProxy() (HostProxy, error) {
	if !r.joining.TryLock() {
		return HostProxy{}, errors.New("start the host proxy after Join returns: a session of the run is still running")
	}
	defer r.joining.Unlock()
	if r.closed {
		return HostProxy{}, errors.New("the run is closed")
	}
	if r.bundleErr != nil {
		return HostProxy{}, r.bundleErr
	}
	password, err := newForwarderSecret()
	if err != nil {
		return HostProxy{}, err
	}
	r.masker.AddProxy(proxyUser, password)
	var fwd *forwarder
	if r.remote == nil {
		fwd, err = listenForwarder(link.Loopback, r.disc.Proxy.Address, r.answer.ProxySecret, password)
	} else {
		fwd, err = listenForwarding(link.Loopback, forwarding{dial: r.link.DialProxy, password: password})
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
