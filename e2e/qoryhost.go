package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/link"
)

// qoryHostReport is what the probe found of the route to link.QoryHost, when
// PROBE_QORY_HOST is 1. Each status is what the proxy returned, 0 when the request
// failed.
type qoryHostReport struct {
	// URL is QORY_HOST_URL as the probe found it.
	URL string `json:"url"`
	// Post and PostBody are the status and the body of a POST with a body and a query.
	Post     int    `json:"post"`
	PostBody string `json:"post_body"`
	// Tunnel is the error of a GET of https://host.qory.invalid/, empty when it got an
	// answer.
	Tunnel string `json:"tunnel"`
}

// probeQoryHost reaches the route at QORY_HOST_URL through the proxy, as a script in
// the enclosure does.
func probeQoryHost() *qoryHostReport {
	r := &qoryHostReport{URL: os.Getenv(link.EnvQoryHost)}
	proxyURL, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || proxyURL.Host == "" || r.URL == "" {
		return r
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: 30 * time.Second}
	if resp, err := client.Post(r.URL+"/tests?suite=unit", "application/json", strings.NewReader(`{"run":true}`)); err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		r.Post, r.PostBody = resp.StatusCode, string(b)
	}
	if resp, err := client.Get("https://" + link.QoryHost + "/"); err != nil {
		r.Tunnel = err.Error()
	} else {
		resp.Body.Close()
	}
	return r
}

// qoryHostThroughTheWall checks the route to link.QoryHost from inside the enclosure:
// QORY_HOST_URL is set; a POST reaches the run's handler, outside the enclosure, with
// its query, Content-Type, body and the session's number, and returns the handler's
// answer; no tunnel opens to the host; and the record has the route's decision, which
// the gateway took, and its denial of the tunnel.
func qoryHostThroughTheWall(t *testing.T, o Options, h hosts, outside string) {
	t.Run("the route to host.qory.invalid is reached from inside the wall", func(t *testing.T) {
		var mu sync.Mutex
		var got []string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			got = append(got, fmt.Sprintf("%s %s?%s session=%s type=%s body=%s", r.Method, r.URL.Path, r.URL.RawQuery,
				r.Header.Get(link.QorySessionHeader), r.Header.Get("Content-Type"), b))
			mu.Unlock()
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, "queued")
		})
		r, err := runIn(t, o, variant{env: []string{"PROBE_QORY_HOST=1"}, qoryRoute: handler}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		p := r.probe.QoryHost
		if p == nil {
			t.Fatal("the probe reported nothing of the route")
		}
		if p.URL != link.QoryHostURL {
			t.Errorf("QORY_HOST_URL is %q, want %q", p.URL, link.QoryHostURL)
		}
		if p.Post != http.StatusAccepted || p.PostBody != "queued" {
			t.Errorf("the POST got %d %q", p.Post, p.PostBody)
		}
		if p.Tunnel == "" {
			t.Error("a tunnel to the route's host opened")
		}
		mu.Lock()
		calls := slices.Clone(got)
		mu.Unlock()
		if want := []string{`POST /tests?suite=unit session=1 type=application/json body={"run":true}`}; !slices.Equal(calls, want) {
			t.Errorf("the handler got %q, want %q", calls, want)
		}
		var decisions []string
		for _, e := range r.events {
			if d, _ := e["data"].(map[string]any); e["type"] == event.RunEgress && d["host"] == link.QoryHost {
				decisions = append(decisions, fmt.Sprint(d["method"], " ", d["channel"], " ", d["decision"], " ", d["status"], " ", d["rule"]))
			}
		}
		// The session's decision reaches the record in a batch, so it may follow the
		// gateway's.
		want := []string{"CONNECT <nil> denied <nil> wall:qory-host", "HTTP qory_host allowed 202 wall:qory-host"}
		slices.Sort(decisions)
		if !slices.Equal(decisions, want) {
			t.Errorf("the record has %q, want %q", decisions, want)
		}
	})
}
