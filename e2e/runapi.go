package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
	"github.com/qoryai/forager/session"
)

// What the fake control plane of the case of the run API serves.
const (
	runAPIKeyID    = "ak_f1xt0re00000000e"
	runAPIWorkItem = `{"work_item":{"title":"Fix the failing build"}}`
	// runAPIGood is the version whose file matches its signed digest, and runAPIBad the
	// version whose file does not.
	runAPIGood = "good"
	runAPIBad  = "bad"
)

// runAPIFile is the file of the fake control plane.
var runAPIFile = bytes.Repeat([]byte("artifact "), 1<<14)

// runAPIReport is what the probe found of the run API, when PROBE_RUN_API is 1. Each
// status is what the proxy returned, and each error the read's, empty for a clean end.
type runAPIReport struct {
	Base         string `json:"base"`
	WorkItem     int    `json:"work_item"`
	WorkItemBody string `json:"work_item_body"`
	Outside      int    `json:"outside"`
	OutsideBody  string `json:"outside_body"`
	OtherRun     int    `json:"other_run"`
	File         int    `json:"file"`
	FileBytes    int    `json:"file_bytes"`
	FileErr      string `json:"file_err"`
	BadFile      int    `json:"bad_file"`
	BadFileBytes int    `json:"bad_file_bytes"`
	BadFileErr   string `json:"bad_file_err"`
	Tunnel       string `json:"tunnel"`
	// Push and PushBody are the status and the body of a POST of artifacts.
	Push     int    `json:"push"`
	PushBody string `json:"push_body"`
}

// probeRunAPI reaches the run API at QORY_RUN_API through the proxy, as a program in the
// enclosure does.
func probeRunAPI() *runAPIReport {
	r := &runAPIReport{Base: os.Getenv(link.EnvRunAPI)}
	proxyURL, err := url.Parse(os.Getenv("HTTP_PROXY"))
	if err != nil || proxyURL.Host == "" || r.Base == "" {
		return r
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: 30 * time.Second}
	read := func(path string) (int, []byte, string) {
		resp, err := client.Get(r.Base + path)
		if err != nil {
			return 0, nil, err.Error()
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, b, err.Error()
		}
		return resp.StatusCode, b, ""
	}
	var body []byte
	r.WorkItem, body, _ = read("/work-item")
	r.WorkItemBody = string(body)
	r.Outside, body, _ = read("/diagnostics")
	r.OutsideBody = string(body)
	other := strings.TrimSuffix(r.Base, os.Getenv("QORY_RUN_ID")) + event.NewRunID()
	if resp, err := client.Get(other + "/work-item"); err == nil {
		r.OtherRun = resp.StatusCode
		resp.Body.Close()
	}
	r.File, body, r.FileErr = read("/artifacts/" + runAPIGood + "/files/report.md")
	r.FileBytes = len(body)
	r.BadFile, body, r.BadFileErr = read("/artifacts/" + runAPIBad + "/files/report.md")
	r.BadFileBytes = len(body)
	if resp, err := client.Post(r.Base+"/artifacts", "application/json", strings.NewReader(`{"artifacts":[]}`)); err == nil {
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		r.Push, r.PushBody = resp.StatusCode, string(body)
	}
	if resp, err := client.Get("https://" + link.RunAPIHost + "/"); err != nil {
		r.Tunnel = err.Error()
	} else {
		resp.Body.Close()
	}
	return r
}

// startRunAPIControl starts a fake control plane in front of the reference receiver: a
// run's registration and its events, and the paths the probe reads under the run. Its
// server document is what a gateway takes.
func startRunAPIControl(t *testing.T) *gateway.Server {
	t.Helper()
	key, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := accesskey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	store, err := receiver.OpenFile(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	pinned := accesskey.Pin{{Alg: "ed25519", PublicKey: signer.PublicKey().String()}}
	pin, _ := json.Marshal(pinned)
	var srv *httptest.Server
	h := &receiver.Handler{
		Keys: func(id string) (receiver.AccessKey, bool) {
			return receiver.AccessKey{PublicKey: key.PublicKey()}, id == runAPIKeyID
		},
		Signer: signer,
		Store:  store,
		Configuration: func() ([]byte, string) {
			doc := []byte(`{"version":1,"node_id":"nd_f1xt0re00000000e","workspaces":["ws_f1xt0re00000000e"],"apiary_public_key":` + string(pin) +
				`,"events":{"url":"` + srv.URL + receiver.DefaultEventsPath + `","types":["*"]},"run":{"url":"` + srv.URL + receiver.DefaultRunPath + `"}}`)
			sum := sha256.Sum256(doc)
			return doc, "sha256=" + hex.EncodeToString(sum[:])
		},
		RunConfiguration: func(receiver.Run) ([]byte, string, *receiver.Refusal) { return receiver.NoPolicy, "", nil },
	}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, _ := strings.CutPrefix(r.URL.Path, receiver.DefaultRunPath+"/")
		_, path, _ := strings.Cut(rest, "/")
		sig := r.Header.Get(server.HeaderSignature)
		file := func(digest []byte) {
			sum := sha256.Sum256(digest)
			w.Header().Set("Content-Length", fmt.Sprint(len(runAPIFile)))
			w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: sig, Digest: hex.EncodeToString(sum[:])}))
			w.Write(runAPIFile)
		}
		switch path {
		case "work-item":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(server.HeaderSignature, signer.SignAnswer(accesskey.Answer{Status: http.StatusOK, RequestSignature: sig, Body: []byte(runAPIWorkItem)}))
			io.WriteString(w, runAPIWorkItem)
		case "artifacts/" + runAPIGood + "/files/report.md":
			file(runAPIFile)
		case "artifacts/" + runAPIBad + "/files/report.md":
			file([]byte("other bytes"))
		default:
			h.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &gateway.Server{Version: 1, URL: srv.URL, AccessKeyID: runAPIKeyID, ApiaryPublicKey: pinned, AccessKey: key, InstanceID: "i_test"}
}

// runAPIThroughTheWall checks the run API from inside the enclosure, with no key in it,
// in a run whose OpenSpec.RunAPICheck returns a refusal for a POST of artifacts: a
// walled run reaches a fake control plane at QORY_RUN_API through the proxy; a request
// outside the five shapes and another run's get 404; a file ends cleanly when its bytes
// match its digest and in a read error when they do not; the POST gets the check's 422
// and never reaches the gateway; no tunnel opens to the host; and the record has the
// requests.
func runAPIThroughTheWall(t *testing.T, o Options, h hosts, outside string) {
	t.Run("the run API is reached from inside the wall", func(t *testing.T) {
		runID := event.NewRunID()
		check := func(_ context.Context, req session.RunAPIRequest) (*session.RunAPIRefusal, error) {
			if req.Path != "/artifacts" {
				return nil, nil
			}
			return &session.RunAPIRefusal{Status: http.StatusUnprocessableEntity, Code: "push_checks_failed",
				Message: "Fix the failing checks, then push again:\ngo test exited 1.", Findings: []string{"go test ./...: 1 failure"}}, nil
		}
		r, err := runIn(t, o, variant{runID: runID, server: startRunAPIControl(t), env: []string{"PROBE_RUN_API=1"}, runAPICheck: check}, false, h, outside)
		if err != nil {
			t.Fatal(err)
		}
		p := r.probe.RunAPI
		if p == nil {
			t.Fatal("the probe reported nothing of the run API")
		}
		if want := link.RunAPIURL(runID); p.Base != want {
			t.Errorf("QORY_RUN_API is %q, want %q", p.Base, want)
		}
		if p.WorkItem != http.StatusOK || p.WorkItemBody != runAPIWorkItem {
			t.Errorf("the work item: %d %s", p.WorkItem, p.WorkItemBody)
		}
		if p.Outside != http.StatusNotFound || !strings.Contains(p.OutsideBody, `"not_found"`) {
			t.Errorf("a request outside the five shapes: %d %s", p.Outside, p.OutsideBody)
		}
		if p.OtherRun != http.StatusNotFound {
			t.Errorf("another run's work item: %d", p.OtherRun)
		}
		if p.File != http.StatusOK || p.FileErr != "" || p.FileBytes != len(runAPIFile) {
			t.Errorf("a file: %d, %d bytes, %q", p.File, p.FileBytes, p.FileErr)
		}
		if p.BadFile != http.StatusOK || !strings.Contains(p.BadFileErr, "unexpected EOF") {
			t.Errorf("a file that fails its digest: %d, %d bytes, %q; want a read error", p.BadFile, p.BadFileBytes, p.BadFileErr)
		}
		const refused = `{"error":"push_checks_failed","message":"Fix the failing checks, then push again:\ngo test exited 1.","findings":["go test ./...: 1 failure"]}`
		if p.Push != http.StatusUnprocessableEntity || p.PushBody != refused {
			t.Errorf("the POST of artifacts: %d %s", p.Push, p.PushBody)
		}
		if p.Tunnel == "" {
			t.Error("a tunnel to the run API's host opened")
		}
		var got []string
		for _, e := range r.events {
			if d, _ := e["data"].(map[string]any); e["type"] == event.RunEgress && d["channel"] == "run_api" {
				got = append(got, fmt.Sprint(d["request_method"], " ", d["status"], " ", d["rule"]))
			}
		}
		const rule = " wall:run-api"
		want := fmt.Sprint([]string{"GET 200" + rule, "GET 404" + rule, "GET 404" + rule, "GET 200" + rule, "GET 502" + rule})
		if fmt.Sprint(got) != want {
			t.Errorf("the record has %v, want %s", got, want)
		}
	})
}
