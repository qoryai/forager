package receiver_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// The records of the stand: a node pool whose choice is the named gateway gw, the node
// whose choice is direct, the workspaces ws and ws1 of one organisation and ws2 of
// another, gw at the workspace level of ws, orgGW at the level of the organisation of
// ws and ws1, and keylessGW at ws with no active key. The fixture access key, key, and
// poolKey2 are the pool's two active keys; gwKey and gwKey2 the gateway's; directKey
// and directKey2 the direct node's; otherNode stands for a node of its own.
const (
	pool       = "np_f1xt0re000000000"
	directNode = "nd_f1xt0re000000000"
	ws         = "ws_f1xt0re000000000"
	ws1        = "ws_f1xt0re000000001"
	ws2        = "ws_f1xt0re000000002"
	gw         = "ng_f1xt0re000000000"
	orgGW      = "ng_f1xt0re000000001"
	keylessGW  = "ng_f1xt0re000000002"
	poolKey2   = "ak_f1xt0re000000002"
	directKey  = "ak_f1xt0re000000003"
	directKey2 = "ak_f1xt0re000000004"
	gwKey      = "ak_f1xt0re00000000g"
	gwKey2     = "ak_f1xt0re00000000h"
	orgGWKey   = "ak_f1xt0re00000000j"
	gwURL      = "https://gateway.example:8443"
	orgOne     = "org_one"
	orgTwo     = "org_two"
)

// gatewayKey is the fixture gateway key, and gatewayKey2 the gateway's second key.
var (
	gatewayKey  = mustKey(accesskey.ParseSecret("qak_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A"))
	gatewayKey2 = mustKey(accesskey.NewKey([]byte("0123456789abcdef0123456789abcdef")))
)

// secrets are the stand's access keys by id, each held from its secret.
var secrets = map[string]*accesskey.Key{
	key: fixtureKey, poolKey2: fixtureKey, otherNode: fixtureKey, directKey: fixtureKey, directKey2: fixtureKey,
	gwKey: gatewayKey, gwKey2: gatewayKey2, orgGWKey: gatewayKey,
}

// stand is a receiver with the records above, its clock at now.
type stand struct {
	t    *testing.T
	h    *receiver.Handler
	keys map[string]receiver.AccessKey
	now  time.Time
}

// enforceAPI is the run configuration the stand's hook gives every run.
var enforceAPI = []byte(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}}`)

func newStand(t *testing.T) *stand {
	t.Helper()
	h, _, _ := handler(t, 0)
	s := &stand{t: t, h: h, now: time.Unix(1700000000, 0).UTC()}
	s.keys = map[string]receiver.AccessKey{
		key:        {PublicKey: fixtureKey.PublicKey(), Node: pool},
		poolKey2:   {PublicKey: fixtureKey.PublicKey(), Node: pool},
		otherNode:  {PublicKey: fixtureKey.PublicKey()},
		directKey:  {PublicKey: fixtureKey.PublicKey(), Node: directNode},
		directKey2: {PublicKey: fixtureKey.PublicKey(), Node: directNode},
		gwKey:      {PublicKey: gatewayKey.PublicKey(), Node: gw},
		gwKey2:     {PublicKey: gatewayKey2.PublicKey(), Node: gw},
		orgGWKey:   {PublicKey: gatewayKey.PublicKey(), Node: orgGW},
	}
	h.Keys = func(id string) (receiver.AccessKey, bool) { k, ok := s.keys[id]; return k, ok }
	h.Now = func() time.Time { return s.now }
	h.Nodes = map[string]receiver.Node{pool: {Workspace: ws, Gateway: gw}, directNode: {Workspace: ws, Gateway: receiver.Direct}}
	h.Workspaces = map[string]receiver.Workspace{ws: {Organisation: orgOne}, ws1: {Organisation: orgOne}, ws2: {Organisation: orgTwo}}
	h.Organisations = map[string]receiver.Organisation{orgOne: {}, orgTwo: {}}
	h.Gateways = map[string]receiver.Gateway{
		gw:        {URL: gwURL, Workspace: ws, AccessKeys: []string{gwKey, gwKey2}},
		orgGW:     {URL: "https://gateway-two.example", Organisation: orgOne, AccessKeys: []string{orgGWKey}},
		keylessGW: {URL: "https://gateway-three.example", Workspace: ws, AccessKeys: []string{"ak_f1xt0re00000000k"}},
	}
	h.RunConfiguration = func(r receiver.Run) ([]byte, string, *receiver.Refusal) {
		lastRun, hooked = &r, hooked+1
		if r.Labels["repository"] == refusedRepository {
			return nil, "", &receiver.Refusal{Status: http.StatusConflict, Code: "repository_unknown"}
		}
		return enforceAPI, "", nil
	}
	return s
}

// at is the stand's clock as a body's time.
func (s *stand) at() string { return server.RegistrationTime(s.now) }

// signed makes a request signed under the access key id's secret, as the fixture
// instance: a POST of application/json, a batch when the target is the events
// endpoint, or a GET at the stand's clock.
func (s *stand) signed(id, method, target string, body []byte) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(string(body)))
	req.Header.Set(server.HeaderAccessKeyID, id)
	req.Header.Set(server.HeaderInstanceID, inst)
	req.Header.Set(server.HeaderContractVersion, "1")
	sr := accesskey.Request{AccessKeyID: id, InstanceID: inst, Method: method, Target: target}
	if method == http.MethodPost {
		sr.Body = body
		req.Header.Set("Content-Type", receiver.RegistrationType)
		if target == receiver.DefaultEventsPath {
			req.Header.Set("Content-Type", server.ContentType)
			req.Header.Set(server.HeaderDelivery, event.NewID())
		}
	} else {
		sr.Timestamp = itoa64(s.now.Unix())
		req.Header.Set(server.HeaderTimestamp, sr.Timestamp)
	}
	sig, err := secrets[id].SignRequest(sr)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set(server.HeaderSignature, sig)
	return req
}

func itoa64(n int64) string { b, _ := json.Marshal(n); return string(b) }

// register posts a body to the run endpoint as the access key id.
func (s *stand) register(id string, body []byte) (*http.Request, *httptest.ResponseRecorder) {
	req := s.signed(id, http.MethodPost, receiver.DefaultRunPath, body)
	return req, serve(s.h, req)
}

// gatewayBody is a registration of the gateway shape of the run, at the stand's clock,
// asking for the attach window given, 0 for none.
func (s *stand) gatewayBody(runID string, labels map[string]string, attach int) []byte {
	b, err := server.GatewayRegistration{RunID: runID, Labels: labels, AttachSeconds: attach, Time: s.at()}.Body()
	if err != nil {
		s.t.Fatal(err)
	}
	return b
}

// directBody is a registration of the direct shape of the run at the stand's clock.
func (s *stand) directBody(runID string) []byte {
	return registration(runID, nil, 30, s.now.Unix())
}

// runKey registers the run through the pool's key and returns its run key.
func (s *stand) runKey(runID string) string {
	s.t.Helper()
	req, rec := s.register(key, s.gatewayBody(runID, map[string]string{"repository": "acme/shop"}, 0))
	if rec.Code != http.StatusOK || !signedAnswer(req, rec) {
		s.t.Fatalf("the registration through a gateway: %d %s", rec.Code, rec.Body.String())
	}
	var a server.RegistrationAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		s.t.Fatal(err)
	}
	return a.RunKey
}

// attachBody is an attach of the run key at the stand's clock with the interval.
func (s *stand) attachBody(runKey string, interval int) []byte {
	b, err := server.Attach{RunKey: runKey, IntervalSeconds: interval, Events: []string{"*"}, ForagerVersion: "test", Time: s.at()}.Body()
	if err != nil {
		s.t.Fatal(err)
	}
	return b
}

// attach posts an attach of the run as the access key id.
func (s *stand) attach(id, runID string, body []byte) (*http.Request, *httptest.ResponseRecorder) {
	req := s.signed(id, http.MethodPost, receiver.DefaultRunPath+"/"+runID+"/attach", body)
	return req, serve(s.h, req)
}

// outcomeBody is an outcome's body at the stand's clock, a member left out when empty.
func (s *stand) outcomeBody(state, reason string) []byte {
	m := map[string]any{"version": 1, "time": s.at()}
	if state != "" {
		m["state"] = state
	}
	if reason != "" {
		m["reason"] = reason
	}
	b, _ := json.Marshal(m)
	return b
}

// outcome posts an outcome of the run as the access key id.
func (s *stand) outcome(id, runID string, body []byte) (*http.Request, *httptest.ResponseRecorder) {
	req := s.signed(id, http.MethodPost, receiver.DefaultRunPath+"/"+runID+"/outcome", body)
	return req, serve(s.h, req)
}

// batch posts a batch of the run's events of the types given as the access key id.
func (s *stand) batch(id string, e *event.Emitter, types ...string) (*http.Request, *httptest.ResponseRecorder) {
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
		ev.Time = s.now.UTC().Format(time.RFC3339Nano)
		line, err := ev.JSON()
		if err != nil {
			s.t.Fatal(err)
		}
		lines = append(lines, string(line))
	}
	return s.batchOf(id, []byte("["+strings.Join(lines, ",")+"]"))
}

// batchOf posts a batch body as the access key id.
func (s *stand) batchOf(id string, body []byte) (*http.Request, *httptest.ResponseRecorder) {
	req := s.signed(id, http.MethodPost, receiver.DefaultEventsPath, body)
	return req, serve(s.h, req)
}

// expect checks a signed answer of the status, with the code's body, none for an empty
// code.
func (s *stand) expect(name string, req *http.Request, rec *httptest.ResponseRecorder, status int, code string) {
	s.t.Helper()
	want := ""
	if code != "" {
		want = `{"error":"` + code + `"}`
	}
	if rec.Code != status || rec.Body.String() != want || !signedAnswer(req, rec) {
		s.t.Errorf("%s: %d %s, signed %v; want %d %s", name, rec.Code, rec.Body.String(), signedAnswer(req, rec), status, code)
	}
}

// TestARunThroughAGatewayMatchesTheKnownAnswers pins the receiver to the known answers
// of a run through a gateway: the registration of registration-gateway.json under the
// fixture access key, the key of a node pool whose choice is the gateway of the fixture
// gateway key, at the fixture time, is answered the bytes of
// registration-gateway-answer.json, its run key signed under the receiver's key, with
// the digest of the key's discovery and neither X-Qory-Run-Configuration nor ETag; the
// attach of attach.json under the fixture gateway key gets the run configuration with
// the registration's labels and about, as attach-answer.json; the outcome of
// outcome.json gets outcome-answer.json.
func TestARunThroughAGatewayMatchesTheKnownAnswers(t *testing.T) {
	s := newStand(t)
	s.now = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s.h.Gateways[gw] = receiver.Gateway{URL: gwURL, Workspace: ws, AccessKeys: []string{gwKey}}
	req, rec := s.register(key, fixture(t, "fixtures/known-answers/registration-gateway.json"))
	if want := fixture(t, "fixtures/known-answers/registration-gateway-answer.json"); rec.Code != http.StatusOK || rec.Body.String() != strings.TrimSpace(string(want)) || !signedAnswer(req, rec) {
		t.Fatalf("the registration through a gateway: %d %s, want %s", rec.Code, rec.Body.String(), want)
	}
	if rec.Header().Get(server.HeaderRunConfiguration) != "" || rec.Header().Get("ETag") != "" || rec.Header().Get(server.HeaderConfiguration) == "" ||
		rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("the registration's answer headers %v", rec.Header())
	}
	if lastRun == nil || lastRun.Node != pool || lastRun.Workspace != ws || lastRun.Gateway != gw || lastRun.AccessKeyID != key || lastRun.InstanceID != inst {
		t.Errorf("the hook was handed %+v", lastRun)
	}
	var a server.RegistrationAnswer
	json.Unmarshal(rec.Body.Bytes(), &a)
	k, err := runkey.Verify(a.RunKey, pin)
	if err != nil || k.AttachBy.Sub(k.Issued) != receiver.AttachWindow || k.NodeID != pool || k.Gateway != gw || k.Workspace != ws {
		t.Errorf("the run key: %+v, %v", k, err)
	}

	s.now = s.now.Add(5 * time.Second)
	req, rec = s.attach(gwKey, k.RunID, fixture(t, "fixtures/known-answers/attach.json"))
	var got, want any
	json.Unmarshal(rec.Body.Bytes(), &got)
	json.Unmarshal(fixture(t, "fixtures/known-answers/attach-answer.json"), &want)
	d := digestOf(enforceAPI)
	if rec.Code != http.StatusOK || !jsonEqual(got, want) || rec.Header().Get(server.HeaderRunConfiguration) != d || rec.Header().Get("ETag") != `"`+d+`"` || !signedAnswer(req, rec) {
		t.Errorf("the attach: %d %s %v", rec.Code, rec.Body.String(), rec.Header())
	}
	// Line 5 is the digest of the gateway key's discovery, and line 6 the run
	// configuration's own, without labels and about, as its reload and batches carry.
	disc := serve(s.h, s.signed(gwKey, http.MethodGet, server.WellKnown, nil))
	if c := rec.Header().Get(server.HeaderConfiguration); c == "" || c != disc.Header().Get(server.HeaderConfiguration) {
		t.Errorf("the attach's configuration digest %q, want the gateway key's discovery's %q", c, disc.Header().Get(server.HeaderConfiguration))
	}
	reloadReq := s.signed(gwKey, http.MethodGet, receiver.DefaultRunPath+"/"+k.RunID, nil)
	if rr := serve(s.h, reloadReq); !runAnswer(reloadReq, rr, enforceAPI) {
		t.Errorf("the gateway's reload: %d %s", rr.Code, rr.Body.String())
	}
	if _, br := s.batch(gwKey, event.NewEmitter(k.RunID, nil), event.RunStarted); br.Header().Get(server.HeaderRunConfiguration) != d {
		t.Errorf("the gateway's batch: the run configuration digest %q, want %q", br.Header().Get(server.HeaderRunConfiguration), d)
	}

	s.now = time.Date(2026, 10, 11, 12, 30, 0, 0, time.UTC)
	req, rec = s.outcome(key, k.RunID, fixture(t, "fixtures/known-answers/outcome.json"))
	if rec.Code != http.StatusOK || rec.Body.String() != strings.TrimSpace(string(fixture(t, "fixtures/known-answers/outcome-answer.json"))) || !signedAnswer(req, rec) {
		t.Errorf("the outcome: %d %s", rec.Code, rec.Body.String())
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// TestTheRegistrationRefusesInItsOrder pins the run endpoint's own order for a
// registration, each code at its place: the same bytes under any active key of the
// node that registered the run get the stored answer, the same run key, before a run it
// wants nothing more of, a signed 410, before a gateway's own key, 409 gateway_key,
// before a shape that does not match the node's choice, 409 node_is_direct or
// node_uses_gateway, before a default that resolves to none, no_default_gateway, before
// a named gateway that may no longer serve the node's workspace, gateway_not_serving,
// before a gateway with no active key, gateway_without_key, before an instance it does
// not admit, instance_limit, before a run id another node registered, run_id_used,
// before the hook's refusal.
func TestTheRegistrationRefusesInItsOrder(t *testing.T) {
	s := newStand(t)
	id := event.NewRunID()
	body := s.gatewayBody(id, nil, 0)
	_, first := s.register(key, body)
	if first.Code != http.StatusOK {
		t.Fatalf("the registration: %d %s", first.Code, first.Body.String())
	}
	admitted, stopped := true, ""
	s.h.Admit = func(string, string) bool { return admitted }
	s.h.Stop = func(run string) bool { return run == stopped }

	// 1 before 2 and everything after: the same bytes under the pool's other key.
	admitted, stopped = false, id
	s.h.Nodes[pool] = receiver.Node{Workspace: ws, Gateway: receiver.Default}
	req, rec := s.register(poolKey2, body)
	if rec.Code != http.StatusOK || rec.Body.String() != first.Body.String() || !signedAnswer(req, rec) {
		t.Errorf("the same bytes under the pool's other key: %d %s, want the stored answer", rec.Code, rec.Body.String())
	}
	req, rec = s.register(otherNode, body)
	s.expect("the same bytes from another node, which it wants nothing more of", req, rec, http.StatusGone, "")

	// 2 before 2a.
	req, rec = s.register(gwKey, body)
	s.expect("a run it wants nothing more of, from a gateway's key", req, rec, http.StatusGone, "")
	stopped = ""

	// 2a before 3.
	req, rec = s.register(gwKey, s.directBody(event.NewRunID()))
	s.expect("a gateway's key, the direct shape", req, rec, http.StatusConflict, "gateway_key")
	req, rec = s.register(gwKey, s.gatewayBody(event.NewRunID(), nil, 0))
	s.expect("a gateway's key, the gateway shape", req, rec, http.StatusConflict, "gateway_key")

	// 3 before 4: the pool's default resolves to none.
	req, rec = s.register(key, s.directBody(id))
	s.expect("the direct shape from a node whose choice is a default that resolves to none", req, rec, http.StatusConflict, "node_uses_gateway")
	req, rec = s.register(directKey, s.gatewayBody(id, nil, 0))
	s.expect("the gateway shape from a direct node", req, rec, http.StatusConflict, "node_is_direct")
	req, rec = s.register(otherNode, s.gatewayBody(id, nil, 0))
	s.expect("the gateway shape from a key with no node", req, rec, http.StatusConflict, "node_is_direct")

	// 4 before 7 and 8.
	req, rec = s.register(key, s.gatewayBody(id, map[string]string{"repository": "acme/other"}, 0))
	s.expect("a default that resolves to none, a run id used and an instance not admitted", req, rec, http.StatusConflict, "no_default_gateway")

	// 5 before 6, 7 and 8: a named gateway at another workspace.
	s.h.Nodes[pool] = receiver.Node{Workspace: ws, Gateway: "ng_f1xt0re000000009"}
	req, rec = s.register(key, s.gatewayBody(id, map[string]string{"repository": "acme/other"}, 0))
	s.expect("a named gateway the records do not hold", req, rec, http.StatusConflict, "gateway_not_serving")
	s.h.Gateways["ng_f1xt0re000000009"] = receiver.Gateway{URL: gwURL, Workspace: ws1}
	req, rec = s.register(key, s.gatewayBody(id, map[string]string{"repository": "acme/other"}, 0))
	s.expect("a named gateway of another workspace, with no key", req, rec, http.StatusConflict, "gateway_not_serving")

	// 6 before 7 and 8.
	s.h.Nodes[pool] = receiver.Node{Workspace: ws, Gateway: keylessGW}
	req, rec = s.register(key, s.gatewayBody(id, map[string]string{"repository": "acme/other"}, 0))
	s.expect("a gateway whose one access key Keys does not hold", req, rec, http.StatusConflict, "gateway_without_key")
	s.keys["ak_f1xt0re00000000k"] = receiver.AccessKey{PublicKey: gatewayKey.PublicKey(), Node: orgGW}
	req, rec = s.register(key, s.gatewayBody(id, map[string]string{"repository": "acme/other"}, 0))
	s.expect("a gateway whose one access key is another gateway's", req, rec, http.StatusConflict, "gateway_without_key")

	// 7 before 8.
	s.h.Nodes[pool] = receiver.Node{Workspace: ws, Gateway: gw}
	req, rec = s.register(key, s.gatewayBody(id, map[string]string{"repository": "acme/other"}, 0))
	s.expect("an instance it does not admit, other bytes of the run id", req, rec, http.StatusConflict, "instance_limit")

	// 8 before 9.
	admitted = true
	req, rec = s.register(key, s.gatewayBody(id, map[string]string{"repository": refusedRepository}, 0))
	s.expect("other bytes of the run id, labels the hook refuses", req, rec, http.StatusConflict, "run_id_used")
	req, rec = s.register(otherNode, s.directBody(id))
	s.expect("the run id from another node", req, rec, http.StatusConflict, "run_id_used")

	// 9.
	req, rec = s.register(key, s.gatewayBody(event.NewRunID(), map[string]string{"repository": refusedRepository}, 0))
	s.expect("a run the hook refuses", req, rec, http.StatusConflict, "repository_unknown")

	// A direct node registers as before, and a key of its own reports directly.
	if req, rec := s.register(directKey, s.directBody(event.NewRunID())); !runAnswer(req, rec, enforceAPI) {
		t.Errorf("a direct registration: %d %s", rec.Code, rec.Body.String())
	}
	if req, rec := s.register(otherNode, s.directBody(event.NewRunID())); !runAnswer(req, rec, enforceAPI) {
		t.Errorf("a direct registration under a key with no node: %d %s", rec.Code, rec.Body.String())
	}
}

// TestTheGatewayResolvesFromTheRecords pins the resolution at each registration, from
// the key's node's record and never from the body: a named gateway; the default, the
// workspace's first, else its organisation's; and a change of choice or of default
// that applies to new registrations alone, a run already registered attaching at the
// gateway its run key names. The run key names the gateway's live keys, the first two,
// and the registration's instance; attach_seconds is the default when absent, granted
// up to the ceiling and clamped above it, and refused below 1.
func TestTheGatewayResolvesFromTheRecords(t *testing.T) {
	s := newStand(t)
	parse := func(name string, rec *httptest.ResponseRecorder) runkey.Key {
		t.Helper()
		var a server.RegistrationAnswer
		json.Unmarshal(rec.Body.Bytes(), &a)
		k, err := runkey.Verify(a.RunKey, pin)
		if rec.Code != http.StatusOK || err != nil {
			t.Fatalf("%s: %d %s, %v", name, rec.Code, rec.Body.String(), err)
		}
		return k
	}
	named := event.NewRunID()
	k := parse("a named gateway", answerOf(s.register(key, s.gatewayBody(named, nil, 0))))
	if k.Gateway != gw || k.GatewayURL != gwURL || len(k.GatewayKeys) != 2 || k.GatewayKeys[0] != gatewayKey.PublicKey() || k.GatewayKeys[1] != gatewayKey2.PublicKey() ||
		k.InstanceID != inst || k.NodeID != pool || k.Workspace != ws || !k.Issued.Equal(s.now) || !k.AttachBy.Equal(s.now.Add(receiver.AttachWindow)) {
		t.Errorf("the run key of a named gateway: %+v", k)
	}

	s.h.Nodes[pool] = receiver.Node{Workspace: ws, Gateway: receiver.Default}
	s.h.Organisations[orgOne] = receiver.Organisation{Default: orgGW}
	if k := parse("the organisation's default", answerOf(s.register(key, s.gatewayBody(event.NewRunID(), nil, 0)))); k.Gateway != orgGW || k.GatewayURL != "https://gateway-two.example" {
		t.Errorf("the organisation's default: %+v", k)
	}
	s.h.Workspaces[ws] = receiver.Workspace{Organisation: orgOne, Default: gw}
	if k := parse("the workspace's default", answerOf(s.register(key, s.gatewayBody(event.NewRunID(), nil, 0)))); k.Gateway != gw {
		t.Errorf("the workspace's default, before the organisation's: %+v", k)
	}

	// The run registered under the named gateway attaches there, whatever the pool's
	// choice is now.
	s.h.Workspaces[ws] = receiver.Workspace{Organisation: orgOne}
	if req, rec := s.attach(gwKey, named, s.attachBody(s.storedKey(named), 30)); rec.Code != http.StatusOK || !signedAnswer(req, rec) {
		t.Errorf("the attach at the gateway the run key names, after the choice changed: %d %s", rec.Code, rec.Body.String())
	}

	for asked, granted := range map[int]time.Duration{0: receiver.AttachWindow, 1: time.Second, 1200: 1200 * time.Second, 3600: receiver.AttachCeiling, 3601: receiver.AttachCeiling, 100000: receiver.AttachCeiling} {
		if k := parse("attach_seconds", answerOf(s.register(key, s.gatewayBody(event.NewRunID(), nil, asked)))); k.AttachBy.Sub(k.Issued) != granted {
			t.Errorf("attach_seconds %d: the window granted %v, want %v", asked, k.AttachBy.Sub(k.Issued), granted)
		}
	}
	id := event.NewRunID()
	for name, body := range map[string]string{
		"attach_seconds 0":                    `{"version":1,"run_id":"` + id + `","attach_seconds":0,"time":"` + s.at() + `"}`,
		"attach_seconds not an integer":       `{"version":1,"run_id":"` + id + `","attach_seconds":1.5,"time":"` + s.at() + `"}`,
		"attach_seconds in the direct shape":  strings.Replace(string(s.directBody(id)), `"version":1`, `"version":1,"attach_seconds":60`, 1),
		"one member of the direct shape only": `{"version":1,"run_id":"` + id + `","forager_version":"test","time":"` + s.at() + `"}`,
	} {
		req, rec := s.register(key, []byte(body))
		s.expect(name, req, rec, http.StatusBadRequest, "invalid_request")
	}
}

// answerOf is the answer of a request and its answer.
func answerOf(_ *http.Request, rec *httptest.ResponseRecorder) *httptest.ResponseRecorder { return rec }

// storedKey is the stored run key of a run the pool registered with the stand's
// gateway body of no labels at its clock: the same bytes again get the same answer.
func (s *stand) storedKey(runID string) string {
	s.t.Helper()
	_, rec := s.register(key, s.gatewayBody(runID, nil, 0))
	var a server.RegistrationAnswer
	json.Unmarshal(rec.Body.Bytes(), &a)
	if a.RunKey == "" {
		s.t.Fatalf("no stored answer for %s: %d %s", runID, rec.Code, rec.Body.String())
	}
	return a.RunKey
}

// TestTheAttachRefusesInItsOrder pins the attach's order after the shared one: a key
// that is not a gateway's, 409 not_a_gateway, before a run key that does not verify,
// 400 run_key_invalid; the same gateway node attaching the same live run again, under
// any of its keys and any bytes, the stored answer; a run that has ended, 410, before a
// run key past its attach_by, 409 run_key_expired, before a run key that names another
// gateway, 409 wrong_gateway, before a gateway that may not serve the run's workspace,
// 409 workspace_not_served.
func TestTheAttachRefusesInItsOrder(t *testing.T) {
	s := newStand(t)
	id := event.NewRunID()
	rk := s.runKey(id)

	// a before b.
	req, rec := s.attach(key, id, s.attachBody(rk, 30))
	s.expect("the pool's key", req, rec, http.StatusConflict, "not_a_gateway")
	req, rec = s.attach(directKey, id, []byte(strings.Replace(string(s.attachBody(rk, 30)), rk, rk[:len(rk)-4]+"AAAA", 1)))
	s.expect("a node's key with a run key that does not verify", req, rec, http.StatusConflict, "not_a_gateway")

	// b.
	other := mustKey(accesskey.NewKey(make([]byte, 32)))
	k, _ := runkey.Parse(rk)
	foreign, err := k.Sign(other)
	if err != nil {
		t.Fatal(err)
	}
	k.RunID = event.NewRunID()
	elsewhere, _ := k.Sign(signingKey)
	for name, body := range map[string][]byte{
		"a run key whose signature fails":       []byte(strings.Replace(string(s.attachBody(rk, 30)), rk, rk[:len(rk)-4]+"AAAA", 1)),
		"a run key under a server key not held": s.attachBody(foreign, 30),
		"the run key of another run":            s.attachBody(elsewhere, 30),
	} {
		req, rec := s.attach(gwKey, id, body)
		s.expect(name, req, rec, http.StatusBadRequest, "run_key_invalid")
	}
	for name, body := range map[string][]byte{
		"no run key":         []byte(`{"version":1,"interval_seconds":30,"events":["*"],"forager_version":"test","contract_version":1,"time":"` + s.at() + `"}`),
		"an interval of 301": []byte(strings.Replace(string(s.attachBody(rk, 30)), `"interval_seconds":30`, `"interval_seconds":301`, 1)),
	} {
		req, rec := s.attach(key, id, body)
		s.expect(name, req, rec, http.StatusBadRequest, "invalid_request")
	}
	stale := s.attachBody(rk, 30)
	s.now = s.now.Add(301 * time.Second)
	if _, rec := s.attach(gwKey, id, stale); rec.Code != http.StatusUnauthorized || rec.Header().Get(server.HeaderSignature) != "" {
		t.Errorf("an attach whose time is outside the window: %d", rec.Code)
	}
	s.now = s.now.Add(-301 * time.Second)

	// 3 before 4 and 5: past attach_by, never attached, from the wrong gateway.
	expired := event.NewRunID()
	expiredKey := s.runKey(expired)
	s.now = s.now.Add(receiver.AttachWindow)
	if req, rec := s.attach(gwKey, expired, s.attachBody(expiredKey, 30)); rec.Code != http.StatusOK || !signedAnswer(req, rec) {
		t.Errorf("an attach at attach_by: %d %s", rec.Code, rec.Body.String())
	}
	late := event.NewRunID()
	s.now = s.now.Add(-receiver.AttachWindow)
	lateKey := s.runKey(late)
	s.now = s.now.Add(receiver.AttachWindow + time.Second)
	req, rec = s.attach(orgGWKey, late, s.attachBody(lateKey, 30))
	s.expect("a second past attach_by, from another gateway", req, rec, http.StatusConflict, "run_key_expired")
	s.now = s.now.Add(-receiver.AttachWindow - time.Second)

	// 2 before 3: an outcome given before the attach ends the run.
	given := event.NewRunID()
	givenKey := s.runKey(given)
	if _, rec := s.outcome(key, given, s.outcomeBody("failed", "")); rec.Code != http.StatusOK {
		t.Fatalf("the outcome: %d", rec.Code)
	}
	s.now = s.now.Add(receiver.AttachWindow + time.Second)
	req, rec = s.attach(orgGWKey, given, s.attachBody(givenKey, 30))
	s.expect("a run an outcome ended, past attach_by, from another gateway", req, rec, http.StatusGone, "")
	s.now = s.now.Add(-receiver.AttachWindow - time.Second)

	// 4 before 5: the organisation's gateway serves the workspace, the run key names
	// another; a gateway of another workspace is wrong first.
	req, rec = s.attach(orgGWKey, id, s.attachBody(rk, 30))
	s.expect("a gateway that serves the workspace and is not the run key's", req, rec, http.StatusConflict, "wrong_gateway")
	s.h.Gateways[orgGW] = receiver.Gateway{URL: "https://gateway-two.example", Organisation: orgTwo, AccessKeys: []string{orgGWKey}}
	req, rec = s.attach(orgGWKey, id, s.attachBody(rk, 30))
	s.expect("a gateway that neither serves the workspace nor is the run key's", req, rec, http.StatusConflict, "wrong_gateway")

	// 5.
	s.h.Gateways[gw] = receiver.Gateway{URL: gwURL, Workspace: ws1, AccessKeys: []string{gwKey, gwKey2}}
	req, rec = s.attach(gwKey, id, s.attachBody(rk, 30))
	s.expect("the run key's gateway, moved to another workspace", req, rec, http.StatusConflict, "workspace_not_served")
	s.h.Gateways[gw] = receiver.Gateway{URL: gwURL, Organisation: orgOne, AccessKeys: []string{gwKey, gwKey2}}

	// The attach, then 1: the same gateway node under its other key and other bytes.
	lastRun = nil
	req, rec = s.attach(gwKey, id, s.attachBody(rk, 30))
	if rec.Code != http.StatusOK || !signedAnswer(req, rec) || rec.Header().Get(server.HeaderRunConfiguration) != digestOf(enforceAPI) {
		t.Fatalf("the attach: %d %s %v", rec.Code, rec.Body.String(), rec.Header())
	}
	if lastRun == nil || lastRun.Node != pool || lastRun.AccessKeyID != key || lastRun.Gateway != gw || lastRun.Workspace != ws ||
		!maps.Equal(lastRun.Labels, map[string]string{"repository": "acme/shop"}) {
		t.Errorf("the hook was handed, at the attach, %+v; want the registration's placement", lastRun)
	}
	attached := rec.Body.String()
	s.now = s.now.Add(10 * time.Second)
	req, rec = s.attach(gwKey2, id, s.attachBody(rk, 60))
	if rec.Code != http.StatusOK || rec.Body.String() != attached || !signedAnswer(req, rec) {
		t.Errorf("the same gateway node again, under its other key and other bytes: %d %s", rec.Code, rec.Body.String())
	}
	req, rec = s.attach(orgGWKey, id, s.attachBody(rk, 30))
	s.expect("another gateway once the run is attached", req, rec, http.StatusConflict, "wrong_gateway")

	// 2: the run ends with its dev.qory.run.exited.
	e := event.NewEmitter(id, nil)
	if _, rec := s.batch(gwKey, e, event.RunExited); rec.Code != http.StatusAccepted {
		t.Fatalf("the batch with run.exited: %d %s", rec.Code, rec.Body.String())
	}
	req, rec = s.attach(gwKey, id, s.attachBody(rk, 30))
	s.expect("the same gateway once the run exited", req, rec, http.StatusGone, "")

	// 2: a run it wants nothing more of.
	wanted := event.NewRunID()
	wantedKey := s.runKey(wanted)
	s.h.Stop = func(run string) bool { return run == wanted }
	req, rec = s.attach(gwKey, wanted, s.attachBody(wantedKey, 30))
	s.expect("a run it wants nothing more of", req, rec, http.StatusGone, "")
}

// TestLivenessCountsFromTheAttach pins the liveness of a run through a gateway: from
// the attach, with the attach's interval, until 3 × the interval passes with no recent
// heartbeat, a heartbeat being as recent as its time corrected by the run's clock
// offset plus the tolerance, never more recent than its arrival; once lost, the same
// gateway's attach is a 410. Before the attach the run is lost at its attach_by.
func TestLivenessCountsFromTheAttach(t *testing.T) {
	s := newStand(t)
	id := event.NewRunID()
	rk := s.runKey(id)
	s.now = s.now.Add(100 * time.Second)
	start := s.now
	if _, rec := s.attach(gwKey, id, s.attachBody(rk, 30)); rec.Code != http.StatusOK {
		t.Fatalf("the attach: %d %s", rec.Code, rec.Body.String())
	}
	again := func(name string, at time.Time, status int) {
		t.Helper()
		s.now = at
		if _, rec := s.attach(gwKey, id, s.attachBody(rk, 30)); rec.Code != status {
			t.Errorf("%s: %d, want %d", name, rec.Code, status)
		}
	}
	again("90 seconds after the attach, 3 × its interval", start.Add(90*time.Second), http.StatusOK)

	e := event.NewEmitter(id, nil)
	s.now = start.Add(60 * time.Second)
	if _, rec := s.batch(gwKey2, e, event.RunHeartbeat); rec.Code != http.StatusAccepted {
		t.Fatalf("a heartbeat from the gateway's other key: %d %s", rec.Code, rec.Body.String())
	}
	again("90 seconds after the heartbeat", start.Add(150*time.Second), http.StatusOK)
	again("91 seconds after the heartbeat", start.Add(151*time.Second), http.StatusGone)

	// A run whose clock runs 1000 seconds behind: its offset corrects its heartbeats.
	behind := event.NewRunID()
	s.now = start
	behindKey := s.runKey(behind)
	if _, rec := s.attach(gwKey, behind, s.attachBody(behindKey, 30)); rec.Code != http.StatusOK {
		t.Fatalf("the attach: %d", rec.Code)
	}
	late := event.NewEmitter(behind, nil).Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30})
	late.Time = start.Add(60*time.Second - 1000*time.Second).UTC().Format(time.RFC3339Nano)
	lateLine, _ := late.JSON()
	s.now = start.Add(60 * time.Second)
	if _, rec := s.batchOf(gwKey, []byte("["+string(lateLine)+"]")); rec.Code != http.StatusAccepted {
		t.Fatalf("a heartbeat of a clock behind: %d", rec.Code)
	}
	s.now = start.Add(150 * time.Second)
	if _, rec := s.attach(gwKey, behind, s.attachBody(behindKey, 30)); rec.Code != http.StatusOK {
		t.Errorf("90 seconds after the arrival of a heartbeat of a clock 1000 seconds behind: %d, want the stored answer", rec.Code)
	}

	// A heartbeat whose time runs ahead is no more recent than its arrival.
	ahead := event.NewRunID()
	s.now = start
	aheadKey := s.runKey(ahead)
	if _, rec := s.attach(gwKey, ahead, s.attachBody(aheadKey, 30)); rec.Code != http.StatusOK {
		t.Fatalf("the attach: %d", rec.Code)
	}
	ev := event.NewEmitter(ahead, nil).Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30})
	ev.Time = start.Add(time.Hour).UTC().Format(time.RFC3339Nano)
	line, _ := ev.JSON()
	s.now = start.Add(30 * time.Second)
	if _, rec := s.batchOf(gwKey, []byte("["+string(line)+"]")); rec.Code != http.StatusAccepted {
		t.Fatalf("a heartbeat from the future: %d", rec.Code)
	}
	s.now = start.Add(121 * time.Second)
	if _, rec := s.attach(gwKey, ahead, s.attachBody(aheadKey, 30)); rec.Code != http.StatusGone {
		t.Errorf("91 seconds after the arrival of a heartbeat dated an hour ahead: %d, want 410", rec.Code)
	}
}

// TestOneNodeSendsForARun pins who may send for a run: for a run through a gateway,
// the gateway node that attached it, under any of its active keys, and a batch from any
// other key, the pool's own among them and the gateway's before the attach, is a signed
// 409 wrong_gateway; for a direct run, the node that registered it, under any of its
// keys, and another node's batch is a signed 409 wrong_node, even for events already
// stored. A reload from anyone else is a signed 404. Events after the end are accepted
// from the attaching gateway node, and a batch of a run the receiver holds no
// registration of from anyone.
func TestOneNodeSendsForARun(t *testing.T) {
	s := newStand(t)
	id := event.NewRunID()
	rk := s.runKey(id)
	e := event.NewEmitter(id, nil)
	notFound := func(name, keyID, runID string) {
		t.Helper()
		req := s.signed(keyID, http.MethodGet, receiver.DefaultRunPath+"/"+runID, nil)
		if rec := serve(s.h, req); rec.Code != http.StatusNotFound || rec.Body.Len() != 0 || !signedAnswer(req, rec) {
			t.Errorf("%s: %d %s, want a signed 404", name, rec.Code, rec.Body.String())
		}
	}
	reloaded := func(name, keyID, runID string) {
		t.Helper()
		req := s.signed(keyID, http.MethodGet, receiver.DefaultRunPath+"/"+runID, nil)
		if rec := serve(s.h, req); !runAnswer(req, rec, enforceAPI) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	req, rec := s.batch(gwKey, e, event.RunStarted)
	s.expect("a batch from the run key's gateway before the attach", req, rec, http.StatusConflict, "wrong_gateway")
	notFound("a reload from the run key's gateway before the attach", gwKey, id)
	notFound("a reload from the pool before the attach", key, id)
	if _, rec := s.attach(gwKey, id, s.attachBody(rk, 30)); rec.Code != http.StatusOK {
		t.Fatalf("the attach: %d", rec.Code)
	}
	if _, rec := s.batch(gwKey2, e, event.RunStarted); rec.Code != http.StatusAccepted {
		t.Errorf("a batch from the gateway's other key: %d %s", rec.Code, rec.Body.String())
	}
	reloaded("a reload from the gateway's other key", gwKey2, id)
	beat := e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30})
	line, _ := beat.JSON()
	if _, rec := s.batchOf(gwKey, []byte("["+string(line)+"]")); rec.Code != http.StatusAccepted {
		t.Errorf("a heartbeat from the gateway: %d", rec.Code)
	}
	for name, keyID := range map[string]string{"the pool's key": key, "another gateway's key": orgGWKey, "a key with no node": otherNode} {
		req, rec := s.batchOf(keyID, []byte("["+string(line)+"]"))
		s.expect("a stored batch from "+name, req, rec, http.StatusConflict, "wrong_gateway")
		notFound("a reload from "+name, keyID, id)
	}
	if _, rec := s.batch(gwKey, e, event.RunExited); rec.Code != http.StatusAccepted {
		t.Errorf("the batch with run.exited: %d", rec.Code)
	}
	if _, rec := s.batch(gwKey2, e, event.RunHeartbeat); rec.Code != http.StatusAccepted {
		t.Errorf("events after the end from the attaching gateway: %d", rec.Code)
	}

	direct := event.NewRunID()
	if _, rec := s.register(directKey, s.directBody(direct)); rec.Code != http.StatusOK {
		t.Fatalf("the direct registration: %d", rec.Code)
	}
	d := event.NewEmitter(direct, nil)
	if _, rec := s.batch(directKey2, d, event.RunStarted); rec.Code != http.StatusAccepted {
		t.Errorf("a direct run's batch from the node's other key: %d", rec.Code)
	}
	reloaded("a direct run's reload from the node's other key", directKey2, direct)
	for name, keyID := range map[string]string{"a pool's key": key, "a gateway's key": gwKey, "a key with no node": otherNode} {
		req, rec := s.batch(keyID, d, event.RunHeartbeat)
		s.expect("a direct run's batch from "+name, req, rec, http.StatusConflict, "wrong_node")
		notFound("a direct run's reload from "+name, keyID, direct)
	}
	if _, rec := s.batch(otherNode, event.NewEmitter(event.NewRunID(), nil), event.RunStarted); rec.Code != http.StatusAccepted {
		t.Errorf("a batch of a run never registered: %d", rec.Code)
	}
}

// TestTheOutcome pins the starter's outcome: accepted under any active key of the node
// that registered the run, before or after the attach and before or after its
// dev.qory.run.exited; the same bytes again, or the same state and reason with any time
// or bytes, compared after the reason rules, accepted again; a different state or
// reason, 409 outcome_given; a run the key's
// node did not register, even with the same bytes, or never registered, a signed 404
// not_found, before outcome_given; a body the contract refuses, 400 invalid_request, and
// a time outside the window the unsigned 401. Every answer is signed, and a 200 is
// {"version":1}.
func TestTheOutcome(t *testing.T) {
	s := newStand(t)
	id := event.NewRunID()
	s.runKey(id)
	ok := func(name, keyID, runID string, body []byte) {
		t.Helper()
		req, rec := s.outcome(keyID, runID, body)
		if rec.Code != http.StatusOK || rec.Body.String() != `{"version":1}` || !signedAnswer(req, rec) || rec.Header().Get(server.HeaderConfiguration) == "" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	body := s.outcomeBody("succeeded", "all_checks_passed")
	for name, keyID := range map[string]string{"the attaching gateway's key": gwKey, "a key with no node": otherNode, "a direct node's key": directKey} {
		req, rec := s.outcome(keyID, id, body)
		s.expect("an outcome from "+name, req, rec, http.StatusNotFound, "not_found")
	}
	req, rec := s.outcome(key, event.NewRunID(), body)
	s.expect("an outcome of a run never registered", req, rec, http.StatusNotFound, "not_found")
	ok("the outcome before the attach", key, id, body)
	ok("the same bytes under the pool's other key", poolKey2, id, body)
	s.now = s.now.Add(time.Minute)
	ok("the same state and reason with a new time", key, id, s.outcomeBody("succeeded", "all_checks_passed"))
	ok("the same state and reason with a new time, under the pool's other key", poolKey2, id, []byte(`{"time":"`+s.at()+`","reason":"all_checks_passed","state":"succeeded","version":1}`))

	// Compared after the reason rules: a reserved reason, or one that is no code, drops
	// to the same outcome; no state is cancelled with stopped.
	dropped := event.NewRunID()
	s.runKey(dropped)
	ok("an outcome with no reason", key, dropped, s.outcomeBody("failed", ""))
	s.now = s.now.Add(time.Second)
	ok("the same state with a reserved reason, which drops", key, dropped, s.outcomeBody("failed", "timeout"))
	ok("the same state with a reason that is no code, which drops", poolKey2, dropped, s.outcomeBody("failed", "Not A Code"))
	req, rec = s.outcome(key, dropped, s.outcomeBody("failed", "tests_failed"))
	s.expect("the same state with a reason that stays", req, rec, http.StatusConflict, "outcome_given")
	none := event.NewRunID()
	s.runKey(none)
	ok("an outcome with no state", key, none, s.outcomeBody("", ""))
	s.now = s.now.Add(time.Second)
	ok("no state again with a new time", key, none, s.outcomeBody("", ""))
	req, rec = s.outcome(key, none, s.outcomeBody("cancelled", "user_cancelled"))
	s.expect("cancelled with another reason, after no state", req, rec, http.StatusConflict, "outcome_given")
	req, rec = s.outcome(key, id, s.outcomeBody("failed", "all_checks_passed"))
	s.expect("another state", req, rec, http.StatusConflict, "outcome_given")
	req, rec = s.outcome(key, id, s.outcomeBody("succeeded", ""))
	s.expect("the same state without the reason", req, rec, http.StatusConflict, "outcome_given")
	req, rec = s.outcome(otherNode, id, s.outcomeBody("failed", ""))
	s.expect("a different outcome from another node", req, rec, http.StatusNotFound, "not_found")
	req, rec = s.outcome(gwKey, id, body)
	s.expect("the same bytes from the gateway's key", req, rec, http.StatusNotFound, "not_found")

	for name, b := range map[string]string{
		"an unknown state":         `{"version":1,"state":"done","time":"` + s.at() + `"}`,
		"no time":                  `{"version":1,"state":"failed"}`,
		"a member it does not say": `{"version":1,"state":"failed","exit_code":1,"time":"` + s.at() + `"}`,
		"a time that is no date":   `{"version":1,"time":"2026-13-01T00:00:00Z"}`,
	} {
		req, rec := s.outcome(key, id, []byte(b))
		s.expect(name, req, rec, http.StatusBadRequest, "invalid_request")
	}
	stale := s.outcomeBody("failed", "")
	s.now = s.now.Add(301 * time.Second)
	if _, rec := s.outcome(key, id, stale); rec.Code != http.StatusUnauthorized || rec.Header().Get(server.HeaderSignature) != "" {
		t.Errorf("an outcome outside the window: %d", rec.Code)
	}

	// A direct run's outcome, after its run.exited.
	direct := event.NewRunID()
	if _, rec := s.register(directKey, s.directBody(direct)); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if _, rec := s.batch(directKey, event.NewEmitter(direct, nil), event.RunExited); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("the direct run's run.exited: %d %s", rec.Code, rec.Body.String())
	}
	ok("a direct run's outcome after its run.exited, from the node's other key", directKey2, direct, s.outcomeBody("failed", "tests_failed"))
}

// TestTheEndMember pins the end member through Forager's client: no end before the
// outcome; once it is recorded, every signed 2xx to a batch of the run carries it, a
// replayed batch's included, its reason left out when the outcome has none, until the
// batch that carries the run's dev.qory.run.exited, whose answer holds none, and none
// after it. With no state the end is cancelled with the reason stopped, and a reason that
// is reserved, or no code, is dropped and the state kept.
func TestTheEndMember(t *testing.T) {
	s := newStand(t)
	s.now = time.Now().UTC().Truncate(time.Second)
	srv := httptest.NewServer(s.h)
	defer srv.Close()
	client := func(id string) *server.Client {
		return &server.Client{Config: &server.Config{Version: 1, URL: srv.URL, AccessKeyID: id, ApiaryPublicKey: pin}, Key: secrets[id], InstanceID: inst, UserAgent: "qory-forager/test"}
	}
	runURL, eventsURL := srv.URL+receiver.DefaultRunPath, srv.URL+receiver.DefaultEventsPath
	ctx := context.Background()
	body, err := server.GatewayRegistration{RunID: event.NewRunID(), Labels: map[string]string{"repository": "acme/shop"}, Time: s.at()}.Body()
	if err != nil {
		t.Fatal(err)
	}
	ans, err := client(key).RegisterThroughGateway(ctx, runURL, body)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := client(poolKey2).RegisterThroughGateway(ctx, runURL, body); err != nil || again.RunKey != ans.RunKey {
		t.Errorf("the same bytes under the pool's other key: %v, %v", again, err)
	}
	attach, _ := server.Attach{RunKey: ans.RunKey, IntervalSeconds: 30, Events: []string{"*"}, ForagerVersion: "test", Time: s.at()}.Body()
	aa, digest, err := client(gwKey).Attach(ctx, runURL, ans.RunID, attach)
	if err != nil || digest != digestOf(enforceAPI) || !maps.Equal(aa.Labels, map[string]string{"repository": "acme/shop"}) || aa.About != nil {
		t.Fatalf("the attach: %+v %s %v", aa, digest, err)
	}
	e := event.NewEmitter(ans.RunID, nil)
	deliver := func(types ...string) server.Delivery {
		t.Helper()
		var lines []string
		for _, ty := range types {
			data := map[string]any{"elapsed_seconds": 30, "interval_seconds": 30}
			if ty == event.RunExited {
				data = map[string]any{"state": "succeeded", "exit_code": 0}
			}
			line, _ := e.Make(ty, data).JSON()
			lines = append(lines, string(line))
		}
		d, err := client(gwKey2).Deliver(ctx, eventsURL, event.NewID(), []byte("["+strings.Join(lines, ",")+"]"), digest)
		if err != nil || !d.Accepted() {
			t.Fatalf("a delivery: %+v %v", d, err)
		}
		return d
	}
	if d := deliver(event.RunHeartbeat); d.ServerEnd != nil {
		t.Errorf("an end before the outcome: %+v", d.ServerEnd)
	}
	if err := client(poolKey2).PostOutcome(ctx, runURL, ans.RunID, server.Outcome{State: "failed", Reason: "tests_failed", Time: s.at()}); err != nil {
		t.Fatal(err)
	}
	want := server.ServerEnd{State: "failed", Reason: "tests_failed"}
	for i := range 2 {
		if d := deliver(event.RunHeartbeat); d.ServerEnd == nil || *d.ServerEnd != want {
			t.Errorf("batch %d after the outcome: %+v", i, d.ServerEnd)
		}
	}
	err = client(key).PostOutcome(ctx, runURL, ans.RunID, server.Outcome{State: "succeeded", Time: s.at()})
	var r *accesskey.Refusal
	if !errors.As(err, &r) || r.Code != "outcome_given" || err.Error() != "outcome "+runURL+"/"+ans.RunID+": outcome_given (status 409)" {
		t.Errorf("a different second outcome: %v", err)
	}
	if d := deliver(event.RunHeartbeat, event.RunExited); d.ServerEnd != nil {
		t.Errorf("an end on the answer to the batch that carries run.exited: %+v", d.ServerEnd)
	}
	if d := deliver(event.RunHeartbeat); d.ServerEnd != nil {
		t.Errorf("an end after run.exited: %+v", d.ServerEnd)
	}

	// The end of an outcome with no state, and of reasons that are dropped, on a
	// direct run.
	for _, c := range []struct {
		state, reason string
		want          server.ServerEnd
	}{
		{"", "", server.ServerEnd{State: "cancelled"}}, // the reason stopped is Forager's, which its client drops
		{"failed", "timeout", server.ServerEnd{State: "failed"}},
		{"succeeded", "Not A Code", server.ServerEnd{State: "succeeded"}},
	} {
		id := event.NewRunID()
		if _, rec := s.register(directKey, s.directBody(id)); rec.Code != http.StatusOK {
			t.Fatal(rec.Code)
		}
		if _, rec := s.outcome(directKey, id, s.outcomeBody(c.state, c.reason)); rec.Code != http.StatusOK {
			t.Fatalf("the outcome %q %q: %d %s", c.state, c.reason, rec.Code, rec.Body.String())
		}
		_, rec := s.batch(directKey2, event.NewEmitter(id, nil), event.RunHeartbeat)
		wantBody := map[string]map[string]string{"end": {"state": c.want.State}}
		if c.state == "" {
			wantBody["end"]["reason"] = event.ReasonStopped
		}
		var got map[string]map[string]string
		json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != http.StatusAccepted || !jsonEqual(got, wantBody) || rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("the end of the outcome %q %q: %d %s", c.state, c.reason, rec.Code, rec.Body.String())
		}
		if end := server.ReadEnd(rec.Body.Bytes()); end == nil || *end != c.want {
			t.Errorf("the end of the outcome %q %q, as Forager reads it: %+v", c.state, c.reason, end)
		}
	}
}

// TestTheClientsAgainstTheReceiver runs Forager's client calls of a run through a
// gateway against the receiver: a gateway-shape body from a direct node, or from a key
// with no node, is node_is_direct and never a direct registration; a gateway's key is
// gateway_key; the attach's refusals read as Forager reports them.
func TestTheClientsAgainstTheReceiver(t *testing.T) {
	s := newStand(t)
	s.now = time.Now().UTC().Truncate(time.Second)
	srv := httptest.NewServer(s.h)
	defer srv.Close()
	client := func(id string) *server.Client {
		return &server.Client{Config: &server.Config{Version: 1, URL: srv.URL, AccessKeyID: id, ApiaryPublicKey: pin}, Key: secrets[id], InstanceID: inst, UserAgent: "qory-forager/test"}
	}
	runURL := srv.URL + receiver.DefaultRunPath
	ctx := context.Background()
	for keyID, code := range map[string]string{directKey: "node_is_direct", otherNode: "node_is_direct", gwKey: "gateway_key"} {
		body, _ := server.GatewayRegistration{RunID: event.NewRunID(), Time: s.at()}.Body()
		_, err := client(keyID).RegisterThroughGateway(ctx, runURL, body)
		var r *accesskey.Refusal
		if !errors.As(err, &r) || r.Code != code || err.Error() != "register "+runURL+": "+code+" (status 409)" {
			t.Errorf("a gateway-shape registration under %s: %v, want %s", keyID, err, code)
		}
	}
	direct, _ := server.Registration{Version: 1, RunID: event.NewRunID(), Events: []string{"*"}, ForagerVersion: "test", ContractVersion: 1, IntervalSeconds: 30, Time: s.at()}.Body()
	_, _, err := client(key).Register(ctx, runURL, direct)
	var r *accesskey.Refusal
	if !errors.As(err, &r) || r.Code != "node_uses_gateway" {
		t.Errorf("a direct registration under a pool behind a gateway: %v", err)
	}

	body, _ := server.GatewayRegistration{RunID: event.NewRunID(), Time: s.at()}.Body()
	ans, err := client(key).RegisterThroughGateway(ctx, runURL, body)
	if err != nil {
		t.Fatal(err)
	}
	attach, _ := server.Attach{RunKey: ans.RunKey, IntervalSeconds: 30, Events: []string{"*"}, ForagerVersion: "test", Time: s.at()}.Body()
	for keyID, want := range map[string]string{key: "not_a_gateway (status 409)", orgGWKey: "wrong_gateway (status 409)"} {
		if _, _, err := client(keyID).Attach(ctx, runURL, ans.RunID, attach); err == nil || err.Error() != "attach "+runURL+"/"+ans.RunID+": "+want {
			t.Errorf("an attach under %s: %v, want %s", keyID, err, want)
		}
	}
	bad, _ := server.Attach{RunKey: runKeyUnder(t, ans.RunKey), IntervalSeconds: 30, Events: []string{"*"}, ForagerVersion: "test", Time: s.at()}.Body()
	if _, _, err := client(gwKey).Attach(ctx, runURL, ans.RunID, bad); err == nil || err.Error() != "attach "+runURL+"/"+ans.RunID+": run_key_invalid (status 400)" {
		t.Errorf("an attach with a run key under another server key: %v", err)
	}
	if _, _, err := client(gwKey).Attach(ctx, runURL, ans.RunID, attach); err != nil {
		t.Errorf("the attach: %v", err)
	}
	if rc, _, err := client(gwKey2).RunConfiguration(ctx, runURL, ans.RunID); err != nil || rc == nil {
		t.Errorf("a reload from the gateway's other key: %v", err)
	}
	if _, _, err := client(key).RunConfiguration(ctx, runURL, ans.RunID); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("a reload from the pool: %v", err)
	}
	err = client(gwKey).PostOutcome(ctx, runURL, ans.RunID, server.Outcome{State: "succeeded", Time: s.at()})
	if err == nil || err.Error() != "outcome "+runURL+"/"+ans.RunID+": not_found (status 404)" {
		t.Errorf("an outcome under the gateway's key: %v", err)
	}
}

// runKeyUnder is the run key's payload signed again under another server key.
func runKeyUnder(t *testing.T, rk string) string {
	t.Helper()
	k, err := runkey.Parse(rk)
	if err != nil {
		t.Fatal(err)
	}
	s, err := k.Sign(mustKey(accesskey.NewKey(make([]byte, 32))))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// nodeShape is discovery's node_id of a node, node pool or gateway.
var nodeShape = regexp.MustCompile(`^n[dpg]_[0-9a-hjkmnp-tv-z]{16}$`)

// TestEachKeyDiscoversItsOwnNode pins discovery per access key: a gateway's key gets
// its gateway's id, ng_, as node_id and every workspace the gateway may serve, its
// workspace's at the workspace level and each of its organisation's at the organisation
// level, sorted; a pool's key its pool and its one workspace, as Forager's client reads
// it; a key with no node the document as configured. Each digest is sha256= and the hex
// SHA-256 of the document served, and the answers to the key's batches carry the same.
func TestEachKeyDiscoversItsOwnNode(t *testing.T) {
	s := newStand(t)
	s.now = time.Now().UTC().Truncate(time.Second)
	srv := httptest.NewServer(s.h)
	defer srv.Close()
	client := func(id string) *server.Client {
		return &server.Client{Config: &server.Config{Version: 1, URL: srv.URL, AccessKeyID: id, ApiaryPublicKey: pin}, Key: secrets[id], InstanceID: inst, UserAgent: "qory-forager/test"}
	}
	conf := fixture(t, "fixtures/configuration/with-run.json")
	for keyID, want := range map[string]struct {
		node       string
		workspaces []string
	}{
		gwKey:     {gw, []string{ws}},
		orgGWKey:  {orgGW, []string{ws, ws1}},
		key:       {pool, []string{ws}},
		otherNode: {"nd_f1xt0re000000000", []string{ws}},
	} {
		req := s.signed(keyID, http.MethodGet, server.WellKnown, nil)
		rec := serve(s.h, req)
		var doc struct {
			NodeID     string   `json:"node_id"`
			Workspaces []string `json:"workspaces"`
		}
		digest := rec.Header().Get(server.HeaderConfiguration)
		if rec.Code != http.StatusOK || !signedAnswer(req, rec) || json.Unmarshal(rec.Body.Bytes(), &doc) != nil || doc.NodeID != want.node ||
			!nodeShape.MatchString(doc.NodeID) || strings.Join(doc.Workspaces, ",") != strings.Join(want.workspaces, ",") {
			t.Errorf("discovery under %s: %d %s", keyID, rec.Code, rec.Body.String())
			continue
		}
		if digest != digestOf(rec.Body.Bytes()) || (keyID == otherNode) != (rec.Body.String() == string(conf)) {
			t.Errorf("discovery under %s: the digest %s of %s", keyID, digest, rec.Body.String())
		}
		if !strings.HasPrefix(want.node, "ng_") {
			c, d, err := client(keyID).Discover(context.Background())
			if err != nil || c.NodeID != want.node || strings.Join(c.Workspaces, ",") != strings.Join(want.workspaces, ",") || d != digest {
				t.Errorf("discovery under %s, as Forager's client reads it: %+v %s, %v", keyID, c, d, err)
			}
		}
		_, brec := s.batch(keyID, event.NewEmitter(event.NewRunID(), nil), event.RunStarted)
		if brec.Header().Get(server.HeaderConfiguration) != digest {
			t.Errorf("a batch under %s: the configuration digest %s, want %s", keyID, brec.Header().Get(server.HeaderConfiguration), digest)
		}
	}
}
