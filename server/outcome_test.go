package server_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
)

// outcomePath is the outcome request's path of the run of these tests.
const outcomePath = "/v1/run-configuration/" + remoteRunID + "/outcome"

// openRemote is a remote link to g with a run open, so its requests carry the run
// secret, and the run URL of g's discovery.
func openRemote(t *testing.T, g *remoteGateway) (*server.Link, string) {
	t.Helper()
	k := remoteLink(t, g.url(), server.RemoteTLS{CAFile: g.ca.file}, fixed(credential))
	d, err := k.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.OpenRun(context.Background(), d.Run.URL, server.LinkRunRequest{RunID: remoteRunID}); err != nil {
		t.Fatal(err)
	}
	return k, d.Run.URL
}

// TestTheOutcomeRequestIsAReloadsGETOfOutcome pins the outcome request behind a
// separate gateway: one GET of <run.url>/<run_id>/outcome with no query and no body,
// with the run credential as Authorization: Bearer and the run's secret, as a reload
// carries them; an answer of the starter's outcome is returned as it came, the reason
// absent or one of the starter's, and a member Forager does not know is ignored.
func TestTheOutcomeRequestIsAReloadsGETOfOutcome(t *testing.T) {
	for body, want := range map[string]server.LinkOutcome{
		`{"state":"succeeded","reason":"all_checks_passed"}`:    {State: "succeeded", Reason: "all_checks_passed"},
		`{"state":"failed","reason":"checks_failed"}`:           {State: "failed", Reason: "checks_failed"},
		`{"state":"cancelled","reason":"no_longer_needed"}`:     {State: "cancelled", Reason: "no_longer_needed"},
		`{"state":"cancelled"}`:                                 {State: "cancelled"},
		`{"state":"failed","reason":"checks_failed","later":1}`: {State: "failed", Reason: "checks_failed"},
		`{}`: {},
	} {
		g := startRemote(t, nil)
		var method, query, auth, secret string
		var hits atomic.Int32
		g.refusal = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != outcomePath {
				return false
			}
			hits.Add(1)
			method, query, auth, secret = r.Method, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get(server.HeaderRunSecret)
			answer(w, 200, body)
			return true
		}
		k, runURL := openRemote(t, g)
		got, err := k.Outcome(context.Background(), runURL, remoteRunID)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", body, got, err, want)
		}
		if hits.Load() != 1 || method != http.MethodGet || query != "" || auth != "Bearer "+credential || secret != runSecret {
			t.Errorf("%s: %d asks, %s ?%s, Authorization %q, run secret %q", body, hits.Load(), method, query, auth, secret)
		}
	}
}

// TestABadReasonIsDroppedAlone pins that a reason the schema refuses, one that is not a
// code or is empty, and one of Forager's reserved codes or an old name, is dropped
// alone, as the gateway drops it: the answer's valid state is the outcome, with no
// error.
func TestABadReasonIsDroppedAlone(t *testing.T) {
	for body, want := range map[string]server.LinkOutcome{
		`{"state":"failed","reason":"Checks failed"}`:      {State: "failed"},
		`{"state":"failed","reason":""}`:                   {State: "failed"},
		`{"state":"succeeded","reason":7}`:                 {State: "succeeded"},
		`{"state":"cancelled","reason":"timeout"}`:         {State: "cancelled"},
		`{"state":"cancelled","reason":"interrupted"}`:     {State: "cancelled"},
		`{"state":"cancelled","reason":"stopped"}`:         {State: "cancelled"},
		`{"state":"failed","reason":"session_lost"}`:       {State: "failed"},
		`{"state":"failed","reason":"run_closed"}`:         {State: "failed"},
		`{"state":"failed","reason":"issuer_unreachable"}`: {State: "failed"},
		`{"state":"succeeded","reason":"X","later":true}`:  {State: "succeeded"},
	} {
		g := startRemote(t, nil)
		g.refusal = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != outcomePath {
				return false
			}
			answer(w, 200, body)
			return true
		}
		k, runURL := openRemote(t, g)
		got, err := k.Outcome(context.Background(), runURL, remoteRunID)
		if got != want || err != nil {
			t.Errorf("%s: %+v %v, want %+v", body, got, err, want)
		}
	}
}

// TestAnOutcomeThatIsNotValidIsNone pins what counts as {}: an answer the schema
// refuses, a reason without a state, a state that is not one of run.exited's, with a
// reason or without; a body that is not JSON or holds a member twice; a 410, a 404 and
// a 500, whatever they carry. Each is the empty outcome, with an error that says why
// and holds neither the run credential nor the run secret.
func TestAnOutcomeThatIsNotValidIsNone(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
	}{
		{200, `{"reason":"no_longer_needed"}`},
		{200, `{"state":"lost"}`},
		{200, `{"reason":"Checks failed"}`},
		{200, `{"state":"lost","reason":"checks_failed"}`},
		{200, `{"state":"lost","reason":"Checks failed"}`},
		{200, `{"state":"","reason":"checks_failed"}`},
		{200, `{"state":"succeeded","state":"failed"}`},
		{200, `{"state":"succeeded","state":"failed","reason":"x"}`},
		{200, `{"state":"succeeded","reason":"a","reason":"b"}`},
		{200, `["succeeded"]`},
		{200, `not json`},
		{200, ``},
		{410, `{"error":"stopped","from":"gateway","state":"failed","reason":"checks_failed"}`},
		{404, `{"state":"succeeded"}`},
		{500, `{"state":"succeeded"}`},
	} {
		g := startRemote(t, nil)
		g.refusal = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != outcomePath {
				return false
			}
			answer(w, c.status, c.body)
			return true
		}
		k, runURL := openRemote(t, g)
		got, err := k.Outcome(context.Background(), runURL, remoteRunID)
		if got != (server.LinkOutcome{}) || err == nil {
			t.Errorf("%d %s: %+v %v, want {} and an error", c.status, c.body, got, err)
		}
		if err != nil && (strings.Contains(err.Error(), credential) || strings.Contains(err.Error(), runSecret)) {
			t.Errorf("%d %s: the error holds a secret: %v", c.status, c.body, err)
		}
	}
}

// TestTheOutcomeRequestIsBounded pins the bound of the outcome request: a gateway that
// never answers costs at most the client's timeout, and the answer is {} with an error;
// the default bound is a little over the gateway's 6 seconds.
func TestTheOutcomeRequestIsBounded(t *testing.T) {
	if server.OutcomeTimeout <= 6*time.Second || server.OutcomeTimeout > 10*time.Second {
		t.Errorf("OutcomeTimeout is %s, want a little over 6s", server.OutcomeTimeout)
	}
	defer server.SetOutcomeTimeout(300 * time.Millisecond)()
	g := startRemote(t, nil)
	release := make(chan struct{})
	defer close(release)
	g.refusal = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != outcomePath {
			return false
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return true
	}
	k, runURL := openRemote(t, g)
	start := time.Now()
	got, err := k.Outcome(context.Background(), runURL, remoteRunID)
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the outcome request took %s, past its bound", took)
	}
	if got != (server.LinkOutcome{}) || err == nil {
		t.Errorf("%+v %v, want {} and an error", got, err)
	}
}

// TestTheLocalLinkAsksNoOutcome pins that the outcome request is never sent on the
// local link: there is no starter to ask, so it returns {} at once with nothing sent.
func TestTheLocalLinkAsksNoOutcome(t *testing.T) {
	var hits atomic.Int32
	g := linktest.Start(t, linkSecret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		answer(w, 200, `{"state":"succeeded","reason":"all_checks_passed"}`)
	}))
	k, _ := newLink(t, g)
	got, err := k.Outcome(context.Background(), "http://localhost/v1/run-configuration", runID)
	if got != (server.LinkOutcome{}) || err == nil || hits.Load() != 0 || g.Accepted.Load() != 0 {
		t.Errorf("%+v %v, %d requests, %d connections", got, err, hits.Load(), g.Accepted.Load())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the local link waited: %v", err)
	}
}
