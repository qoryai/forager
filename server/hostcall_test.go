package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
)

// TestTheLinkSendsTheHostCalls pins both host calls on the local link: a POST of
// <run.url>/<run_id>/next-session or /pushed-commits with Content-Type:
// application/json and the body as given, whose 2xx body comes back as it came, empty
// for a 204; a coded refusal is an accesskey.Refusal with its from; a 410 is the end of
// the run; a 502 with a code is a refusal too; a 503 with no body is a StatusError; an
// answer over the most is an error; and
// a run id of another form or a run URL off the link sends nothing.
func TestTheLinkSendsTheHostCalls(t *testing.T) {
	type got struct{ line, contentType, body string }
	var seen []got
	var reply func(w http.ResponseWriter, r *http.Request)
	g := linktest.Start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, got{r.Method + " " + r.URL.Path, r.Header.Get("Content-Type"), string(b)})
		reply(w, r)
	}))
	k, _ := newLink(t, g)
	ctx := context.Background()
	runURL := server.LocalOrigin + "/v1/run-configuration"
	calls := map[string]func(context.Context, string, string, []byte) ([]byte, error){"/next-session": k.NextSession, "/pushed-commits": k.PushedCommits}
	for path, call := range calls {
		seen = nil
		reply = func(w http.ResponseWriter, _ *http.Request) { answer(w, 200, `{"next":"end"}`) }
		b, err := call(ctx, runURL, runID, []byte("not json"))
		if err != nil || string(b) != `{"next":"end"}` {
			t.Errorf("%s: %q, %v", path, b, err)
		}
		if want := (got{"POST /v1/run-configuration/" + runID + path, "application/json", "not json"}); len(seen) != 1 || seen[0] != want {
			t.Errorf("%s: the gateway got %+v, want %+v", path, seen, want)
		}
		reply = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
		if b, err := call(ctx, runURL, runID, nil); err != nil || b == nil || len(b) != 0 {
			t.Errorf("%s: a 204: %q, %v", path, b, err)
		}
		for status, body := range map[int]string{
			409: `{"error":"run_ended","from":"apiary","message":"Start a new run."}`,
			502: `{"error":"control_plane_unavailable","from":"gateway","message":"Send it again."}`,
		} {
			reply = func(w http.ResponseWriter, _ *http.Request) { answer(w, status, body) }
			_, err := call(ctx, runURL, runID, []byte(`{}`))
			var ref *accesskey.Refusal
			if !errors.As(err, &ref) || ref.Status != status || !strings.Contains(body, `"`+ref.From+`"`) || !strings.Contains(body, `"`+ref.Code+`"`) {
				t.Errorf("%s: a %d: %v (%+v)", path, status, err, ref)
			}
		}
		reply = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }
		var se *server.StatusError
		if _, err := call(ctx, runURL, runID, []byte(`{}`)); !errors.As(err, &se) || se.Status != http.StatusServiceUnavailable {
			t.Errorf("%s: a 503 with no body: %v", path, err)
		}
		reply = func(w http.ResponseWriter, _ *http.Request) {
			answer(w, 410, `{"error":"run_closed","from":"gateway"}`)
		}
		if _, err := call(ctx, runURL, runID, []byte(`{}`)); err == nil {
			t.Errorf("%s: a 410: no error", path)
		} else if _, ok := server.Ended(err); !ok {
			t.Errorf("%s: a 410 is no end: %v", path, err)
		}
		seen = nil
		if _, err := call(ctx, runURL, "R", []byte(`{}`)); err == nil {
			t.Errorf("%s: a run id of another form", path)
		}
		if _, err := call(ctx, "https://elsewhere.example/v1/run-configuration", runID, []byte(`{}`)); err == nil {
			t.Errorf("%s: a run URL off the link", path)
		}
		if len(seen) != 0 {
			t.Errorf("%s: the gateway got %+v", path, seen)
		}
	}
	reply = func(w http.ResponseWriter, _ *http.Request) {
		answer(w, 200, strings.Repeat(" ", server.MaxPushedCommitsAnswer+1))
	}
	if _, err := k.PushedCommits(ctx, runURL, runID, []byte(`{}`)); err == nil || !strings.HasPrefix(err.Error(), "Check the gateway and the control plane: ") {
		t.Errorf("an answer over the most: %v", err)
	}
}

// TestAHostCallWaitsPastTheLinksWait pins the session's wait for a host call: longer
// than the link's wait for every other request, which the test sets to 50 ms, so an
// answer that comes after 300 ms still reaches the caller.
func TestAHostCallWaitsPastTheLinksWait(t *testing.T) {
	g := linktest.Start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		time.Sleep(300 * time.Millisecond)
		answer(w, 200, `{"next":"end"}`)
	}))
	k, _ := newLink(t, g)
	server.SetLinkWaits(k, 50*time.Millisecond, 50*time.Millisecond)
	runURL := server.LocalOrigin + "/v1/run-configuration"
	if b, err := k.NextSession(context.Background(), runURL, runID, []byte(`{}`)); err != nil || string(b) != `{"next":"end"}` {
		t.Errorf("next-session: %q, %v", b, err)
	}
	if _, err := k.PushedCommits(context.Background(), runURL, runID, []byte(`{}`)); err != nil {
		t.Errorf("pushed-commits: %v", err)
	}
}
