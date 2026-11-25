package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/internal/linktest"
	"github.com/qoryai/forager/server"
)

// TestTheLinkSendsTheHostCalls pins the host calls on the local link: a POST of
// <run.url>/<run_id>/next-session, /pushed-commits or /findings with Content-Type:
// application/json and the body as given, or a GET of /findings with neither, whose 2xx
// body comes back as it came, empty for a 204; a coded refusal is an accesskey.Refusal with its from; a 410 is the end of
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
	calls := map[string]func(context.Context, string, string, []byte) ([]byte, error){
		"POST /next-session": k.NextSession, "POST /pushed-commits": k.PushedCommits, "POST /findings": k.PostFindings,
		"GET /findings": func(ctx context.Context, runURL, runID string, _ []byte) ([]byte, error) {
			return k.Findings(ctx, runURL, runID)
		},
	}
	for path, call := range calls {
		seen = nil
		reply = func(w http.ResponseWriter, _ *http.Request) { answer(w, 200, `{"next":"end"}`) }
		b, err := call(ctx, runURL, runID, []byte("not json"))
		if err != nil || string(b) != `{"next":"end"}` {
			t.Errorf("%s: %q, %v", path, b, err)
		}
		method, under, _ := strings.Cut(path, " ")
		want := got{method + " /v1/run-configuration/" + runID + under, "application/json", "not json"}
		if method == http.MethodGet {
			want.contentType, want.body = "", ""
		}
		if len(seen) != 1 || seen[0] != want {
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
	for path, most := range map[string]int{"POST /pushed-commits": server.MaxPushedCommitsAnswer, "POST /findings": 64 << 10, "GET /findings": 16 << 20} {
		for _, over := range []int{0, 1} {
			reply = func(w http.ResponseWriter, _ *http.Request) { answer(w, 200, strings.Repeat(" ", most+over)) }
			b, err := calls[path](ctx, runURL, runID, []byte(`{}`))
			if over == 0 && (err != nil || len(b) != most) || over == 1 && (err == nil || !strings.HasPrefix(err.Error(), "Check the gateway and the control plane: ")) {
				t.Errorf("%s: an answer of %d bytes: %d bytes, %v", path, most+over, len(b), err)
			}
		}
	}
}

// TestAPostFindingsBodyOverItsLimitIsNotSent pins the link's check of a POST findings
// body: 8 MiB is sent, and a longer one is an error that starts with the fix, with nothing
// sent.
func TestAPostFindingsBodyOverItsLimitIsNotSent(t *testing.T) {
	var sent []int
	g := linktest.Start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		sent = append(sent, int(n))
		answer(w, 200, `{}`)
	}))
	k, _ := newLink(t, g)
	runURL := server.LocalOrigin + "/v1/run-configuration"
	for _, n := range []int{8 << 20, 8<<20 + 1, 8<<20 + 2, 64 << 20} {
		_, err := k.PostFindings(context.Background(), runURL, runID, make([]byte, n))
		if n == 8<<20 && err != nil || n > 8<<20 && (err == nil || err.Error() != "Send a POST findings body of at most 8 MiB (8,388,608 bytes): this one is longer, so nothing was sent.") {
			t.Errorf("a body of %d bytes: %v", n, err)
		}
	}
	if len(sent) != 1 || sent[0] != 8<<20 {
		t.Errorf("the gateway got bodies of %v bytes", sent)
	}
}

// TestALinkRefusalHasItsRetryAfter pins the wait the link reads from a coded refusal's
// retry_after: whole seconds from 1 to 31 days are the wait, and none, 0, a negative,
// a fraction, a string and a value over 31 days are no wait.
func TestALinkRefusalHasItsRetryAfter(t *testing.T) {
	var body string
	g := linktest.Start(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		answer(w, http.StatusTooManyRequests, body)
	}))
	k, _ := newLink(t, g)
	runURL := server.LocalOrigin + "/v1/run-configuration"
	most := int64(server.MaxRetryAfter / time.Second)
	for retryAfter, want := range map[string]time.Duration{
		`7`:                           7 * time.Second,
		strconv.FormatInt(most, 10):   server.MaxRetryAfter,
		``:                            0,
		`0`:                           0,
		`-7`:                          0,
		`7.5`:                         0,
		`"7"`:                         0,
		strconv.FormatInt(most+1, 10): 0,
	} {
		body = `{"error":"rate_limited","from":"apiary","message":"Send it again."}`
		if retryAfter != "" {
			body = `{"error":"rate_limited","from":"apiary","message":"Send it again.","retry_after":` + retryAfter + `}`
		}
		_, err := k.NextSession(context.Background(), runURL, runID, []byte(`{}`))
		var ref *accesskey.Refusal
		if !errors.As(err, &ref) || ref.Code != "rate_limited" || ref.RetryAfter != want || err.Error() != "Send it again." {
			t.Errorf("retry_after %q: %v (%+v), want RetryAfter %v", retryAfter, err, ref, want)
		}
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
	if _, err := k.Findings(context.Background(), runURL, runID); err != nil {
		t.Errorf("GET findings: %v", err)
	}
	if _, err := k.PostFindings(context.Background(), runURL, runID, []byte(`{}`)); err != nil {
		t.Errorf("POST findings: %v", err)
	}
}
