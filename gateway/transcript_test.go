package gateway_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/server"
)

// resumeDoc is a run configuration that continues a paused run.
const resumeDoc = `{"version":1,"resume":{"run_id":"0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d","session_id":"3f1b2c4d-0000-4000-8000-000000000001","path":"~/.claude/projects/-workspace/3f1b2c4d-0000-4000-8000-000000000001.jsonl"}}`

// transcriptControl is a control that serves doc and GET
// <run.url>/<run_id>/resume/transcript with answer, and counts those requests.
func transcriptControl(t *testing.T, c *control, doc string, answer *func(w http.ResponseWriter, r *http.Request), count *int) {
	t.Helper()
	c.serveDocument(doc, 'a')
	f := func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/resume/transcript") {
			return false
		}
		c.mu.Lock()
		*count++
		c.mu.Unlock()
		(*answer)(w, r)
		return true
	}
	c.intercept.Store(&f)
}

// transcriptFile serves the transcript b, its digest signed as digest, by the
// control's signer.
func transcriptFile(c *control, b []byte, digest string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if digest == "" {
			sum := sha256.Sum256(b)
			digest = hex.EncodeToString(sum[:])
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: r.Header.Get(server.HeaderSignature), Digest: digest}))
		w.Write(b)
	}
}

// transcriptRefusal serves status with a body, signed unless unsigned.
func transcriptRefusal(c *control, status int, unsigned bool) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		body := []byte(`{"error":"not_found"}`)
		if !unsigned {
			w.Header().Set(server.HeaderSignature, c.signer.SignAnswer(accesskey.Answer{Status: status, RequestSignature: r.Header.Get(server.HeaderSignature), Body: body}))
		}
		w.WriteHeader(status)
		w.Write(body)
	}
}

// getTranscript sends the transcript request of runID on the local link and returns the
// status, the Content-Type, the body and the read error.
func getTranscript(t *testing.T, h *harness, runID string) (int, string, []byte, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, server.LocalOrigin+"/v1/run-configuration/"+runID+"/transcript", nil)
	resp, err := raw(t, h.g.LocalLink()).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), b, err
}

// wantResume is resumeDoc's resume.
var wantResume = server.LinkResume{RunID: "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d", SessionID: "3f1b2c4d-0000-4000-8000-000000000001",
	Path: "~/.claude/projects/-workspace/3f1b2c4d-0000-4000-8000-000000000001.jsonl"}

// TestATranscriptRequestReadsThePausedRunsTranscript pins the link's transcript request
// on the local link, of a run whose run answer has the run configuration's resume: the gateway reads GET <run.url>/<run_id>/resume/transcript with
// its signed client and streams the verified bytes as application/x-ndjson; a signed
// 404 is 404 not_found from apiary; an unsigned answer is 502 transcript_unavailable;
// bytes that fail the signed digest end with a read error; and a run without resume
// gets 404 not_found from the gateway, with nothing sent.
func TestATranscriptRequestReadsThePausedRunsTranscript(t *testing.T) {
	c := newControl(t)
	var answer func(w http.ResponseWriter, r *http.Request)
	var count int
	transcriptControl(t, c, resumeDoc, &answer, &count)
	h := start(t, gateway.Config{Server: c.server()})
	a := h.open(server.LinkRunRequest{})
	if a.Resume == nil || *a.Resume != wantResume {
		t.Errorf("the run answer's resume %+v; want %+v", a.Resume, wantResume)
	}
	content := bytes.Repeat([]byte(`{"type":"assistant"}`+"\n"), 2000)

	answer = transcriptFile(c, content, "")
	if status, ct, b, err := getTranscript(t, h, a.RunID); status != http.StatusOK || ct != "application/x-ndjson" || !bytes.Equal(b, content) || err != nil {
		t.Errorf("the transcript: %d %q, %d bytes, %v", status, ct, len(b), err)
	}
	answer = transcriptRefusal(c, http.StatusNotFound, false)
	if status, _, b, _ := getTranscript(t, h, a.RunID); status != http.StatusNotFound || !strings.Contains(string(b), `"error":"not_found"`) || !strings.Contains(string(b), `"from":"apiary"`) {
		t.Errorf("a signed 404: %d %s", status, b)
	}
	answer = transcriptRefusal(c, http.StatusNotFound, true)
	if status, _, b, _ := getTranscript(t, h, a.RunID); status != http.StatusBadGateway || !strings.Contains(string(b), `"error":"transcript_unavailable"`) {
		t.Errorf("an unsigned 404: %d %s", status, b)
	}
	answer = transcriptFile(c, content, strings.Repeat("0", 64))
	if status, _, _, err := getTranscript(t, h, a.RunID); status != http.StatusOK || err == nil {
		t.Errorf("bytes that fail the digest: %d, %v; want a read error", status, err)
	}
	if count != 4 {
		t.Errorf("%d transcript requests sent; want 4", count)
	}
	if status, _, _, _ := getTranscript(t, h, event.NewRunID()); status != http.StatusBadRequest {
		t.Errorf("a run id of no run: %d", status)
	}

	c.serveDocument(`{"version":1}`, 'b')
	b := h.open(server.LinkRunRequest{})
	if b.Resume != nil {
		t.Errorf("the run answer of a run without resume has %+v", b.Resume)
	}
	if status, _, body, _ := getTranscript(t, h, b.RunID); status != http.StatusNotFound || !strings.Contains(string(body), `"from":"gateway"`) {
		t.Errorf("a run without resume: %d %s", status, body)
	}
	if count != 4 {
		t.Errorf("%d transcript requests sent; want none for a run without resume", count-4)
	}
}

// TestATranscriptRequestBehindASeparateGateway pins the transcript request on the one
// address: the run answer has the run configuration's resume, and the request goes
// under /qory-link/run-configuration/<run_id>/transcript with the run's run key, the
// answer signed; another run's key is 400 run_key_invalid.
func TestATranscriptRequestBehindASeparateGateway(t *testing.T) {
	c := gatewayControl(t)
	var answer func(w http.ResponseWriter, r *http.Request)
	var count int
	transcriptControl(t, c, resumeDoc, &answer, &count)
	content := []byte(`{"type":"user"}` + "\n")
	answer = transcriptFile(c, content, "")
	r := startRemote(t, c, gateway.Config{})
	e := r.open(t, runKeyFor(t, event.NewRunID(), nil), server.LinkRunRequest{})
	if e.a.Resume == nil || *e.a.Resume != wantResume {
		t.Errorf("the run answer's resume %+v; want %+v", e.a.Resume, wantResume)
	}
	got := r.do(t, e.key, http.MethodGet, "/qory-link/run-configuration/"+e.a.RunID+"/transcript", nil)
	if got.status != http.StatusOK || !bytes.Equal(got.body, content) {
		t.Errorf("the transcript: %d %s", got.status, got.body)
	}
	other := runKeyFor(t, event.NewRunID(), nil)
	r.mu.Lock()
	r.keys = append(r.keys, other)
	r.mu.Unlock()
	if got := r.do(t, other, http.MethodGet, "/qory-link/run-configuration/"+e.a.RunID+"/transcript", nil); got.status != http.StatusBadRequest || got.refusal()["error"] != "run_key_invalid" {
		t.Errorf("another run's key: %d %s", got.status, got.body)
	}
	if count != 1 {
		t.Errorf("%d transcript requests sent; want 1", count)
	}
}
