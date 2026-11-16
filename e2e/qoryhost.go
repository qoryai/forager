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
	"github.com/qoryai/forager/session"
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

// The files of the workspace through which the agent and the setup container's program
// meet in qoryHostFromTheSetup: the agent writes its proxy password into
// routePasswordFile, as any program of the agent's container could, and the setup's
// program writes the statuses its requests got into routeSetupFile.
const (
	routePasswordFile = "qory-route-password"
	routeSetupFile    = "qory-route-setup"
	// routeSetupWait is how long each side waits for the other's file.
	routeSetupWait = 2 * time.Minute
)

// waitForFile returns the content of the file at p once it is there and not empty, or
// an error after routeSetupWait.
func waitForFile(p string) (string, error) {
	for end := time.Now().Add(routeSetupWait); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("no %s after %s", p, routeSetupWait)
}

// probeSetupRoute is the agent's half of qoryHostFromTheSetup: it writes the password
// of its proxy URL into routePasswordFile and returns what the setup's program wrote
// into routeSetupFile.
func probeSetupRoute() string {
	u, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || u.User == nil {
		return "the agent's HTTP_PROXY has no password"
	}
	password, _ := u.User.Password()
	if err := os.WriteFile(routePasswordFile+".tmp", []byte(password), 0o600); err != nil {
		return err.Error()
	}
	if err := os.Rename(routePasswordFile+".tmp", routePasswordFile); err != nil {
		return err.Error()
	}
	got, err := waitForFile(routeSetupFile)
	if err != nil {
		return err.Error()
	}
	return got
}

// setupRoute is the setup container's half of qoryHostFromTheSetup, started by a setup
// command: once the agent wrote its password into routePasswordFile, it sends a GET to
// the route through the setup container's proxy, the wall's relay, without a
// Proxy-Authorization and with the agent's password in it, and writes the two statuses
// into routeSetupFile, 0 for a request that failed.
func setupRoute() int {
	password, err := waitForFile(routePasswordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "setup-route:", err)
		return 1
	}
	proxy, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || proxy.Host == "" {
		fmt.Fprintln(os.Stderr, "setup-route: the setup container has no HTTP_PROXY")
		return 1
	}
	withPassword := *proxy
	withPassword.User = url.UserPassword(link.ProxyUser, password)
	var statuses []string
	for _, p := range []*url.URL{proxy, &withPassword} {
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(p), DisableKeepAlives: true}, Timeout: 30 * time.Second}
		status := 0
		if resp, err := client.Get(link.QoryHostURL + "/setup"); err == nil {
			status = resp.StatusCode
			resp.Body.Close()
		}
		statuses = append(statuses, fmt.Sprint(status))
	}
	if err := os.WriteFile(routeSetupFile+".tmp", []byte(strings.Join(statuses, " ")), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "setup-route:", err)
		return 1
	}
	if err := os.Rename(routeSetupFile+".tmp", routeSetupFile); err != nil {
		fmt.Fprintln(os.Stderr, "setup-route:", err)
		return 1
	}
	return 0
}

// qoryHostFromTheSetup checks that the setup container never reaches the route to
// link.QoryHost while a session runs: a program the setup started sends a request to
// the route without a proxy password and one with the session's password, which the
// agent wrote into the workspace. Both get the gateway's 403, since the forwarder serves
// the route only from the agent container's address, and the handler gets neither.
func qoryHostFromTheSetup(t *testing.T, o Options, h hosts, outside string) {
	const name = "the setup container gets 403 from the route, also with the session's password"
	if !o.Setup {
		t.Run(name, func(t *testing.T) { t.Skip("the adapter starts no setup container") })
		return
	}
	t.Run(name, func(t *testing.T) {
		var mu sync.Mutex
		var got []string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got = append(got, r.Method+" "+r.URL.Path)
			mu.Unlock()
			io.WriteString(w, "reached")
		})
		var setupErr error
		commands := []session.SetupCommand{
			{Name: "start the route's caller", Args: []string{"sh", "-c", o.Probe + " " + modeSetupRoute + " >/tmp/setup-route.log 2>&1 &"}},
		}
		r, err := runIn(t, o, variant{env: []string{"PROBE_SETUP_ROUTE=1"}, qoryRoute: handler,
			setup: commands, onSetup: func(err error) { setupErr = err }}, false, h, outside)
		if err != nil || setupErr != nil {
			t.Fatalf("the setup: %v; the run: %v", setupErr, err)
		}
		if r.probe.SetupRoute != "403 403" {
			t.Errorf("the setup container's requests without and with the password got %q, want \"403 403\"", r.probe.SetupRoute)
		}
		mu.Lock()
		calls := slices.Clone(got)
		mu.Unlock()
		if len(calls) != 0 {
			t.Errorf("the handler got %q from the setup container", calls)
		}
	})
}
