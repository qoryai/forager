package receiver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
)

// TestRunAttachedComesAfterTheRest pins run_attached at the end of the attach's order.
// The run key binds a run to one gateway node, and wrong_gateway comes first, so no
// request reaches run_attached through the endpoints alone: the test records the run as
// another gateway node's. The run key's own gateway then gets 409 run_attached, after a
// gateway that may not serve the run's workspace, 409 workspace_not_served, and after a
// run that has ended, 410.
func TestRunAttachedComesAfterTheRest(t *testing.T) {
	key := func(b byte) *accesskey.Key {
		k, err := accesskey.NewKey([]byte(strings.Repeat(string(rune('a'+b)), 32)))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	signer, poolKey, gatewayKey := key(0), key(1), key(2)
	const (
		inst   = "i_gYKDhIWGh4iJiouMjY6PkA"
		runID  = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
		poolID = "ak_f1xt0re000000000"
		gwID   = "ak_f1xt0re00000000g"
	)
	store, err := OpenFile(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(1700000000, 0).UTC()
	h := &Handler{
		Keys: func(id string) (AccessKey, bool) {
			switch id {
			case poolID:
				return AccessKey{PublicKey: poolKey.PublicKey(), Node: "np_f1xt0re000000000"}, true
			case gwID:
				return AccessKey{PublicKey: gatewayKey.PublicKey(), Node: "ng_f1xt0re000000000"}, true
			}
			return AccessKey{}, false
		},
		Signer:     signer,
		Store:      store,
		Now:        func() time.Time { return now },
		Nodes:      map[string]Node{"np_f1xt0re000000000": {Workspace: "ws_f1xt0re000000000", Gateway: "ng_f1xt0re000000000"}},
		Workspaces: map[string]Workspace{"ws_f1xt0re000000000": {}},
		Gateways: map[string]Gateway{"ng_f1xt0re000000000": {URL: "https://gateway.example:8443", Workspace: "ws_f1xt0re000000000",
			AccessKeys: []string{gwID}}},
	}
	post := func(id string, k *accesskey.Key, target string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(string(body)))
		req.Header.Set(server.HeaderAccessKeyID, id)
		req.Header.Set(server.HeaderInstanceID, inst)
		req.Header.Set(server.HeaderContractVersion, "1")
		req.Header.Set("Content-Type", RegistrationType)
		sig, err := k.SignRequest(accesskey.Request{AccessKeyID: id, InstanceID: inst, Method: http.MethodPost, Target: target, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(server.HeaderSignature, sig)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	at := server.RegistrationTime(now)
	rec := post(poolID, poolKey, DefaultRunPath, []byte(`{"version":1,"run_id":"`+runID+`","time":"`+at+`"}`))
	var ans struct {
		RunKey string `json:"run_key"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ans) != nil {
		t.Fatalf("the registration: %d %s", rec.Code, rec.Body.String())
	}
	h.runs[runID].attached = "ng_f1xt0re00000000z"
	h.runs[runID].since, h.runs[runID].interval = now, 30*time.Second
	attach := []byte(`{"version":1,"run_key":"` + ans.RunKey + `","interval_seconds":30,"events":["*"],"forager_version":"test","contract_version":1,"time":"` + at + `"}`)
	target := DefaultRunPath + "/" + runID + "/attach"
	check := func(name string, status int, body string) {
		t.Helper()
		if rec := post(gwID, gatewayKey, target, attach); rec.Code != status || rec.Body.String() != body {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body.String(), status, body)
		}
	}
	check("the run key's gateway, the run attached by another gateway node", http.StatusConflict, `{"error":"run_attached"}`)
	h.Gateways["ng_f1xt0re000000000"] = Gateway{URL: "https://gateway.example:8443", Workspace: "ws_f1xt0re000000001", AccessKeys: []string{gwID}}
	check("a gateway that may not serve the workspace, the run attached by another", http.StatusConflict, `{"error":"workspace_not_served"}`)
	h.runs[runID].outcome = &outcome{state: "failed"}
	check("a run that has ended, attached by another", http.StatusGone, "")
}
