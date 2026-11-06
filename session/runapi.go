package session

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
)

// errRunAPIClosed is the error of [Run.RunAPI] and of its client's requests once the run
// is closed.
var errRunAPIClosed = errors.New("Open another run to reach the run API: this run is closed.")

// errNoRunAPI is the error of [Run.RunAPI] for a run with no control plane.
var errNoRunAPI = errors.New("Open the run through a gateway with a control plane to reach the run API: this run has none, so it has no QORY_RUN_API.")

// RunAPI returns a client for the run's host work and the base URL of the run API,
// http://run-api.qory.invalid/v1/runs/<run id>, the value of QORY_RUN_API. Send requests
// to the five paths under it, with the client and no credential: the gateway signs each
// with its access key, and contracts/forager/v1/README.md §The run API lists the paths,
// the answers and the limits.
//
// The client works in this process alone: it has no port and no password. It dials the
// run's proxy on each request, on one machine with the run's proxy secret and behind a
// separate gateway with the run key, and follows no redirect. Call it at any time from
// [Open] to [Run.Close], from any goroutine, while a [Run.Join] runs too.
//
// An error means the run is closed or has no control plane. A request of the client
// fails once the run is closed.
func (r *Run) RunAPI() (*http.Client, string, error) {
	if r.runAPIClosed() {
		return nil, "", errRunAPIClosed
	}
	if r.answer.RunAPI == "" {
		return nil, "", errNoRunAPI
	}
	// The proxy's URL is never dialled: DialContext opens every connection to the run's
	// proxy.
	proxy := &url.URL{Scheme: "http", Host: "run-proxy"}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return proxy, nil },
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				if r.runAPIClosed() {
					return nil, errRunAPIClosed
				}
				return r.dialProxy(ctx)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, r.answer.RunAPI, nil
}

// runAPIClosed reports whether [Run.Close] began, or the gateway closed the run.
func (r *Run) runAPIClosed() bool { return r.ending.Load() || r.closing.Err() != nil }
