package receiver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/server"
)

// The ids of the bench: the fixture instance, inst, and otherInst, another instance of
// the same gateway node; a run id; the node pool's key, whose choice is the gateway, and
// the gateway's two keys.
const (
	inst      = "i_gYKDhIWGh4iJiouMjY6PkA"
	otherInst = "i_otherinstance00000000"
	runID     = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
	poolID    = "ak_f1xt0re000000000"
	gwID      = "ak_f1xt0re00000000g"
	gwID2     = "ak_f1xt0re00000000h"
)

// bench is a receiver with a node pool whose choice is one gateway, and the gateway, of
// two keys, its clock at now.
type bench struct {
	t     *testing.T
	h     *Handler
	store *File
	now   time.Time
	keys  map[string]*accesskey.Key
}

func newBench(t *testing.T) *bench {
	t.Helper()
	key := func(b byte) *accesskey.Key {
		k, err := accesskey.NewKey([]byte(strings.Repeat(string(rune('a'+b)), 32)))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	store, err := OpenFile(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	b := &bench{t: t, store: store, now: time.Unix(1700000000, 0).UTC(),
		keys: map[string]*accesskey.Key{poolID: key(1), gwID: key(2), gwID2: key(3)}}
	b.h = &Handler{
		Keys: func(id string) (AccessKey, bool) {
			switch id {
			case poolID:
				return AccessKey{PublicKey: b.keys[id].PublicKey(), Node: "np_f1xt0re000000000"}, true
			case gwID, gwID2:
				return AccessKey{PublicKey: b.keys[id].PublicKey(), Node: "ng_f1xt0re000000000"}, true
			}
			return AccessKey{}, false
		},
		Signer:     key(0),
		Store:      store,
		Now:        func() time.Time { return b.now },
		Nodes:      map[string]Node{"np_f1xt0re000000000": {Workspace: "ws_f1xt0re000000000", Gateway: "ng_f1xt0re000000000"}},
		Workspaces: map[string]Workspace{"ws_f1xt0re000000000": {}},
		Gateways: map[string]Gateway{"ng_f1xt0re000000000": {URL: "https://gateway.example:8443", Workspace: "ws_f1xt0re000000000",
			AccessKeys: []string{gwID, gwID2}}},
	}
	return b
}

// at is the bench's clock as a body's time.
func (b *bench) at() string { return server.RegistrationTime(b.now) }

// serve sends a request signed under the access key id as the instance: a POST of the
// body, a batch to the events endpoint, or a GET with no body at the bench's clock.
func (b *bench) serve(id, instance, method, target string, body []byte) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(string(body)))
	req.Header.Set(server.HeaderAccessKeyID, id)
	req.Header.Set(server.HeaderInstanceID, instance)
	req.Header.Set(server.HeaderContractVersion, "1")
	sr := accesskey.Request{AccessKeyID: id, InstanceID: instance, Method: method, Target: target}
	if method == http.MethodPost {
		sr.Body = body
		req.Header.Set("Content-Type", RegistrationType)
		if target == DefaultEventsPath {
			req.Header.Set("Content-Type", server.ContentType)
		}
	} else {
		sr.Timestamp = strconv.FormatInt(b.now.Unix(), 10)
		req.Header.Set(server.HeaderTimestamp, sr.Timestamp)
	}
	sig, err := b.keys[id].SignRequest(sr)
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set(server.HeaderSignature, sig)
	rec := httptest.NewRecorder()
	b.h.ServeHTTP(rec, req)
	return rec
}

// runKey registers the run through the pool's key and returns its run key.
func (b *bench) runKey(runID string) string {
	b.t.Helper()
	rec := b.serve(poolID, inst, http.MethodPost, DefaultRunPath, []byte(`{"version":1,"run_id":"`+runID+`","time":"`+b.at()+`"}`))
	var ans struct {
		RunKey string `json:"run_key"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ans) != nil {
		b.t.Fatalf("the registration: %d %s", rec.Code, rec.Body.String())
	}
	return ans.RunKey
}

// attach posts an attach of the run key with an interval of 30 seconds as the access key
// id and the instance.
func (b *bench) attach(id, instance, runID, runKey string) *httptest.ResponseRecorder {
	body := []byte(`{"version":1,"run_key":"` + runKey + `","interval_seconds":30,"events":["*"],"forager_version":"test","contract_version":1,"time":"` + b.at() + `"}`)
	return b.serve(id, instance, http.MethodPost, DefaultRunPath+"/"+runID+"/attach", body)
}

// events is a batch of the run's events of the types given, at the bench's clock.
func (b *bench) events(e *event.Emitter, types ...string) []byte {
	b.t.Helper()
	var lines []string
	for _, ty := range types {
		data := map[string]any{}
		switch ty {
		case event.RunHeartbeat:
			data = map[string]any{"elapsed_seconds": 30, "interval_seconds": 30}
		case event.RunExited:
			data = map[string]any{"state": "succeeded", "exit_code": 0}
		}
		ev := e.Make(ty, data)
		ev.Time = b.now.Format(time.RFC3339Nano)
		line, err := ev.JSON()
		if err != nil {
			b.t.Fatal(err)
		}
		lines = append(lines, string(line))
	}
	return []byte("[" + strings.Join(lines, ",") + "]")
}

// TestRunAttachedComesAfterTheRest pins run_attached at the end of the attach's order.
// The run key binds a run to one gateway node, and wrong_gateway comes first, so no
// request reaches run_attached through the endpoints alone: the test records the run as
// another gateway node's. The run key's own gateway then gets 409 run_attached, after a
// gateway that may not serve the run's workspace, 409 workspace_not_served, and after a
// run that has ended, 410.
func TestRunAttachedComesAfterTheRest(t *testing.T) {
	b := newBench(t)
	rk := b.runKey(runID)
	b.h.runs[runID].attached = "ng_f1xt0re00000000z"
	b.h.runs[runID].since, b.h.runs[runID].interval = b.now, 30*time.Second
	check := func(name string, status int, body string) {
		t.Helper()
		if rec := b.attach(gwID, inst, runID, rk); rec.Code != status || rec.Body.String() != body {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body.String(), status, body)
		}
	}
	check("the run key's gateway, the run attached by another gateway node", http.StatusConflict, `{"error":"run_attached"}`)
	b.h.Gateways["ng_f1xt0re000000000"] = Gateway{URL: "https://gateway.example:8443", Workspace: "ws_f1xt0re000000001", AccessKeys: []string{gwID}}
	check("a gateway that may not serve the workspace, the run attached by another", http.StatusConflict, `{"error":"workspace_not_served"}`)
	b.h.runs[runID].outcome = &outcome{state: "failed"}
	check("a run that has ended, attached by another", http.StatusGone, "")
}

// TestTheAttachingInstanceSendsWhileTheRunIsLive pins the attaching instance: while the
// run is live, the gateway node that attached it, under any of its active keys and the
// instance id its attach was signed with, gets the stored attach answer, its batches
// accepted and its reloads answered; another instance of the same node attaching gets
// 409 run_attached, its batch 409 wrong_gateway and its reload 404, and the starter's
// outcome alone leaves it so. Once the run's dev.qory.run.exited is accepted, a batch
// from the other instance, under either key, gets the answer the attaching instance
// would: a resend of a batch already accepted the same 202, deduplicated.
func TestTheAttachingInstanceSendsWhileTheRunIsLive(t *testing.T) {
	b := newBench(t)
	rk := b.runKey(runID)
	first := b.attach(gwID, inst, runID, rk)
	if first.Code != http.StatusOK {
		t.Fatalf("the attach: %d %s", first.Code, first.Body.String())
	}
	e := event.NewEmitter(runID, nil)
	coded := func(name string, rec *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		want := ""
		if code != "" {
			want = `{"error":"` + code + `"}`
		}
		if rec.Code != status || rec.Body.String() != want {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body.String(), status, want)
		}
	}
	stored := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusOK || rec.Body.String() != first.Body.String() ||
			rec.Header().Get(server.HeaderRunConfiguration) != first.Header().Get(server.HeaderRunConfiguration) {
			t.Errorf("%s: %d %s, want the stored answer", name, rec.Code, rec.Body.String())
		}
	}
	accepted := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusAccepted {
			t.Errorf("%s: %d %s, want 202", name, rec.Code, rec.Body.String())
		}
	}
	reload := func(id, instance string) *httptest.ResponseRecorder {
		return b.serve(id, instance, http.MethodGet, DefaultRunPath+"/"+runID, nil)
	}

	stored("the same node and instance attaching again", b.attach(gwID, inst, runID, rk))
	stored("the same instance attaching again with its old id under the node's other key", b.attach(gwID2, inst, runID, rk))
	coded("another instance of the same node attaching", b.attach(gwID, otherInst, runID, rk), http.StatusConflict, "run_attached")
	accepted("a batch from the attaching instance", b.serve(gwID, inst, http.MethodPost, DefaultEventsPath, b.events(e, event.RunStarted)))
	coded("a batch from another instance while the run is live", b.serve(gwID, otherInst, http.MethodPost, DefaultEventsPath, b.events(e, event.RunHeartbeat)),
		http.StatusConflict, "wrong_gateway")
	if rec := reload(gwID2, inst); rec.Code != http.StatusOK {
		t.Errorf("a reload from the attaching instance under the node's other key: %d", rec.Code)
	}
	coded("a reload from another instance while the run is live", reload(gwID, otherInst), http.StatusNotFound, "")

	outcome := []byte(`{"version":1,"state":"failed","time":"` + b.at() + `"}`)
	if rec := b.serve(poolID, inst, http.MethodPost, DefaultRunPath+"/"+runID+"/outcome", outcome); rec.Code != http.StatusOK {
		t.Fatalf("the outcome: %d %s", rec.Code, rec.Body.String())
	}
	coded("a batch from another instance after the outcome alone", b.serve(gwID2, otherInst, http.MethodPost, DefaultEventsPath, b.events(e, event.RunHeartbeat)),
		http.StatusConflict, "wrong_gateway")
	coded("a reload from another instance after the outcome alone", reload(gwID, otherInst), http.StatusNotFound, "")

	exited := b.events(e, event.RunExited)
	accepted("the batch with run.exited from the attaching instance", b.serve(gwID, inst, http.MethodPost, DefaultEventsPath, exited))
	count := b.store.Count()
	other := b.serve(gwID2, otherInst, http.MethodPost, DefaultEventsPath, exited)
	own := b.serve(gwID, inst, http.MethodPost, DefaultEventsPath, exited)
	if other.Code != http.StatusAccepted || other.Code != own.Code || other.Body.String() != own.Body.String() ||
		other.Header().Get(server.HeaderRunConfiguration) != own.Header().Get(server.HeaderRunConfiguration) {
		t.Errorf("another instance's resend after the end: %d %q, want the attaching instance's %d %q", other.Code, other.Body.String(), own.Code, own.Body.String())
	}
	if b.store.Count() != count {
		t.Errorf("the resends stored %d events, want none", b.store.Count()-count)
	}
	accepted("a new batch from another instance after the end", b.serve(gwID, otherInst, http.MethodPost, DefaultEventsPath, b.events(e, event.RunHeartbeat)))
	if rec := reload(gwID, otherInst); rec.Code != http.StatusOK {
		t.Errorf("a reload from another instance after the end: %d", rec.Code)
	}
}

// TestAnotherInstanceSendsOnceTheHeartbeatsGoQuiet pins the other way a run stops being
// live: with no heartbeat within 3 × its interval of the attach, a batch from another
// instance of the attaching gateway node is accepted.
func TestAnotherInstanceSendsOnceTheHeartbeatsGoQuiet(t *testing.T) {
	b := newBench(t)
	rk := b.runKey(runID)
	if rec := b.attach(gwID, inst, runID, rk); rec.Code != http.StatusOK {
		t.Fatalf("the attach: %d %s", rec.Code, rec.Body.String())
	}
	start := b.now
	e := event.NewEmitter(runID, nil)
	b.now = start.Add(90 * time.Second)
	if rec := b.serve(gwID, otherInst, http.MethodPost, DefaultEventsPath, b.events(e, event.RunStarted)); rec.Code != http.StatusConflict {
		t.Errorf("a batch from another instance 90 seconds after the attach: %d, want 409", rec.Code)
	}
	b.now = start.Add(91 * time.Second)
	if rec := b.serve(gwID, otherInst, http.MethodPost, DefaultEventsPath, b.events(e, event.RunStarted)); rec.Code != http.StatusAccepted {
		t.Errorf("a batch from another instance 91 seconds after the attach: %d %s, want 202", rec.Code, rec.Body.String())
	}
}
