package receiver_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/receiver"
	"github.com/qoryai/forager/server"
)

const (
	key  = "ak_f1xt0re000000000"
	inst = "i_gYKDhIWGh4iJiouMjY6PkA"
)

// fixtureKey is the fixture access key, and signingKey the fixture signing key, the
// receiver's own here.
var (
	fixtureKey = mustKey(accesskey.ParseSecret("qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"))
	signingKey = mustKey(accesskey.NewKey([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`")))
	pin        = accesskey.Pin{{Alg: "ed25519", PublicKey: signingKey.PublicKey().String()}}
)

func mustKey(k *accesskey.Key, err error) *accesskey.Key {
	if err != nil {
		panic(err)
	}
	return k
}

// keys is a lookup that holds the fixture access key, and a second access key id of
// the same public key, standing for another node, and counts how often it is called.
func keys(asked *int) func(string) (receiver.AccessKey, bool) {
	return func(k string) (receiver.AccessKey, bool) {
		*asked++
		switch k {
		case key, otherNode:
			return receiver.AccessKey{PublicKey: fixtureKey.PublicKey()}, true
		}
		return receiver.AccessKey{}, false
	}
}

// otherNode is an access key id the lookup holds beside the fixture's: another node's.
const otherNode = "ak_f1xt0re000000001"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// digestOf is a receiver's digest of a document: any string, opaque to Forager;
// here the hex sha256 of the bytes.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256=" + hex.EncodeToString(sum[:])
}

// refusedRepository is the repository the test's run configuration hook refuses, with
// a 409 of its own code.
const refusedRepository = "acme/refused"

// handler is a receiver over a fresh store, serving the contract's fixtures as its
// documents, with its clock where the test puts it. The run configuration hook records
// the run it was last handed in lastRun and how often it was called in hooked, and
// refuses a run of refusedRepository.
func handler(t *testing.T, now int64) (*receiver.Handler, *receiver.File, *int) {
	t.Helper()
	store, err := receiver.OpenFile(filepath.Join(t.TempDir(), "received.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	asked := new(int)
	conf := fixture(t, "fixtures/configuration/with-run.json")
	run := fixture(t, "fixtures/run-configuration/enforce.json")
	lastRun, hooked = nil, 0
	h := &receiver.Handler{
		Keys:          keys(asked),
		Signer:        signingKey,
		Store:         store,
		Now:           func() time.Time { return time.Unix(now, 0) },
		Configuration: func() ([]byte, string) { return conf, digestOf(conf) },
		RunConfiguration: func(r receiver.Run) ([]byte, string, *receiver.Refusal) {
			lastRun, hooked = &r, hooked+1
			if r.Labels["repository"] == refusedRepository {
				return nil, "", &receiver.Refusal{Status: http.StatusConflict, Code: "repository_unknown"}
			}
			return run, digestOf(run), nil
		},
	}
	return h, store, asked
}

// lastRun is the run the run configuration hook was last handed, and hooked how often
// it was called. The tests that read them do not run in parallel.
var (
	lastRun *receiver.Run
	hooked  int
)

// signedGET makes a GET signed under the key as the fixture access key and instance,
// at the given timestamp.
func signedGET(target string, k *accesskey.Key, ts string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set(server.HeaderAccessKeyID, key)
	req.Header.Set(server.HeaderInstanceID, inst)
	req.Header.Set(server.HeaderContractVersion, "1")
	req.Header.Set(server.HeaderTimestamp, ts)
	sig, _ := k.SignRequest(accesskey.Request{AccessKeyID: key, InstanceID: inst, Method: http.MethodGet, Target: target, Timestamp: ts})
	req.Header.Set(server.HeaderSignature, sig)
	return req
}

// signedPOST makes a delivery signed under the key as the fixture access key and
// instance.
func signedPOST(target string, k *accesskey.Key, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(string(body)))
	req.Header.Set(server.HeaderAccessKeyID, key)
	req.Header.Set(server.HeaderInstanceID, inst)
	req.Header.Set(server.HeaderContractVersion, "1")
	req.Header.Set("Content-Type", server.ContentType)
	req.Header.Set(server.HeaderDelivery, event.NewID())
	sig, _ := k.SignRequest(accesskey.Request{AccessKeyID: key, InstanceID: inst, Method: http.MethodPost, Target: target, Body: body})
	req.Header.Set(server.HeaderSignature, sig)
	return req
}

// as signs the request again under the fixture key, as the access key id and the
// instance id given, an empty instance id sending none.
func as(id, instance string, r *http.Request) *http.Request {
	r.Header.Set(server.HeaderAccessKeyID, id)
	if instance == "" {
		r.Header.Del(server.HeaderInstanceID)
	} else {
		r.Header.Set(server.HeaderInstanceID, instance)
	}
	sr := accesskey.Request{AccessKeyID: id, InstanceID: instance, Method: r.Method, Target: r.URL.RequestURI(), Timestamp: r.Header.Get(server.HeaderTimestamp)}
	if r.Method == http.MethodPost {
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		sr.Body = b
		sr.Timestamp = ""
	}
	sig, _ := fixtureKey.SignRequest(sr)
	r.Header.Set(server.HeaderSignature, sig)
	return r
}

// registration is a registration body: the run id, its labels, nil for none, the
// interval, and the time, in Unix seconds.
func registration(runID string, labels map[string]string, interval int, at int64) []byte {
	m := map[string]any{"version": 1, "run_id": runID, "forager_version": "test", "contract_version": 1,
		"interval_seconds": interval, "events": []string{"*"}, "time": time.Unix(at, 0).UTC().Format(time.RFC3339)}
	if labels != nil {
		m["labels"] = labels
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

// signedRegister makes a registration signed under the fixture key as the fixture
// access key and instance: Content-Type application/json, and neither X-Qory-Delivery
// nor X-Qory-Timestamp.
func signedRegister(body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, receiver.DefaultRunPath, strings.NewReader(string(body)))
	req.Header.Set(server.HeaderAccessKeyID, key)
	req.Header.Set(server.HeaderInstanceID, inst)
	req.Header.Set(server.HeaderContractVersion, "1")
	req.Header.Set("Content-Type", receiver.RegistrationType)
	sig, _ := fixtureKey.SignRequest(accesskey.Request{AccessKeyID: key, InstanceID: inst, Method: http.MethodPost, Target: receiver.DefaultRunPath, Body: body})
	req.Header.Set(server.HeaderSignature, sig)
	return req
}

// reload makes the reload of a run by its id, signed at the given timestamp.
func reload(runID, ts string) *http.Request {
	return signedGET(receiver.DefaultRunPath+"/"+runID, fixtureKey, ts)
}

// signedAnswer reports whether the answer is signed under the receiver's key and
// bound to the request.
func signedAnswer(req *http.Request, rec *httptest.ResponseRecorder) bool {
	return pin.VerifyAnswer(accesskey.Answer{Status: rec.Code, RequestSignature: req.Header.Get(server.HeaderSignature), Body: rec.Body.Bytes(),
		Configuration: rec.Header().Get(server.HeaderConfiguration), RunConfiguration: rec.Header().Get(server.HeaderRunConfiguration)}, rec.Header().Get(server.HeaderSignature)) &&
		rec.Header().Get("Cache-Control") == "no-store, no-transform"
}

// runAnswer reports whether the answer is a signed 200 of the document, with its
// digest as X-Qory-Run-Configuration and the same digest quoted as the ETag.
func runAnswer(req *http.Request, rec *httptest.ResponseRecorder, doc []byte) bool {
	d := digestOf(doc)
	return rec.Code == http.StatusOK && rec.Body.String() == string(doc) && rec.Header().Get("Content-Type") == "application/json" &&
		rec.Header().Get(server.HeaderRunConfiguration) == d && rec.Header().Get("ETag") == `"`+d+`"` && signedAnswer(req, rec)
}

func serve(h *receiver.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestSignedFixturesReplay pins the receiver against the contract's signed fixtures:
// each, sent as recorded with the receiver's clock at the fixture time in the order of
// the names, gets the status and the code the fixture expects, the replayed batch stores
// nothing twice, every 401 and every refusal before verification goes out unsigned,
// and every other answer is signed under the receiver's key and bound to the request.
// The receiver admits the fixture instance only, and its hook is handed the
// registration's run: its id, labels and about.
func TestSignedFixturesReplay(t *testing.T) {
	h, store, _ := handler(t, 1700000000)
	h.Admit = func(id, instance string) bool { return id == key && instance == inst }
	names, err := fs.Glob(contracts.FS, "fixtures/signed/*.json")
	if err != nil || len(names) < 16 {
		t.Fatalf("signed fixtures: %v, %v", names, err)
	}
	sort.Strings(names)
	var first []json.RawMessage
	json.Unmarshal(fixture(t, "fixtures/batch/first.json"), &first)
	run := fixture(t, "fixtures/run-configuration/enforce.json")
	for _, name := range names {
		var f struct {
			Method     string                     `json:"method"`
			Target     string                     `json:"target"`
			Headers    map[string]json.RawMessage `json:"headers"`
			Body       *string                    `json:"body"`
			Expect     int                        `json:"expect"`
			ExpectCode string                     `json:"expect_code"`
			Note       string                     `json:"note"`
		}
		if err := json.Unmarshal(fixture(t, name), &f); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var body io.Reader
		if f.Body != nil {
			body = strings.NewReader(*f.Body)
		}
		req := httptest.NewRequest(f.Method, f.Target, body)
		twice := false
		for k, raw := range f.Headers {
			var one string
			var many []string
			if json.Unmarshal(raw, &one) == nil {
				req.Header.Set(k, one)
			} else if json.Unmarshal(raw, &many) == nil {
				twice = true
				for _, v := range many {
					req.Header.Add(k, v)
				}
			}
		}
		lastRun = nil
		rec := serve(h, req)
		if rec.Code != f.Expect {
			t.Errorf("%s: %d, want %d (%s): %s", name, rec.Code, f.Expect, f.Note, rec.Body.String())
		}
		if f.ExpectCode != "" && rec.Body.String() != `{"error":"`+f.ExpectCode+`"}` {
			t.Errorf("%s: the body %q, want the code %s", name, rec.Body.String(), f.ExpectCode)
		}
		unsigned := rec.Code == http.StatusUnauthorized || twice
		if signed := rec.Header().Get(server.HeaderSignature) != ""; signed == unsigned {
			t.Errorf("%s: signed %v", name, signed)
		}
		if !unsigned && !signedAnswer(req, rec) {
			t.Errorf("%s: the answer does not verify under the receiver's key", name)
		}
		if rec.Code == http.StatusUnauthorized && rec.Body.String() != `{"error":"unauthorized"}` {
			t.Errorf("%s: a 401 with the body %q", name, rec.Body.String())
		}
		if rec.Code == http.StatusOK && strings.HasPrefix(f.Target, server.WellKnown) && rec.Header().Get(server.HeaderConfiguration) == "" {
			t.Errorf("%s: no configuration digest on the answer", name)
		}
		if rec.Code == http.StatusOK && strings.HasPrefix(f.Target, receiver.DefaultRunPath) && !runAnswer(req, rec, run) {
			t.Errorf("%s: the run configuration answer %q, headers %v", name, rec.Body.String(), rec.Header())
		}
		// The registration accepted first, register-replayed in the order of the names,
		// hands the hook the run as it registered; register-valid, the same bytes, then
		// gets the same answer without it.
		if path.Base(name) == "register-replayed.json" {
			want := map[string]string{"forge": "github.com", "repository": "acme/shop"}
			if lastRun == nil || lastRun.ID != "0191f2a4-3c5e-7b8d-9e0f-1a2b3c4d5e6f" || lastRun.AccessKeyID != key || lastRun.InstanceID != inst ||
				!maps.Equal(lastRun.Labels, want) || string(lastRun.About) != `{"title":"Fix the failing build"}` {
				t.Errorf("%s: the hook was handed %+v", name, lastRun)
			}
		}
	}
	if store.Count() != len(first) {
		t.Errorf("the store holds %d events after the valid and the replayed batch of %d", store.Count(), len(first))
	}
}

// TestEveryFailureIsOneUnauthorized pins the failure rule: a malformed access key id
// is refused before any lookup, and an unknown access key, a timestamp that is not an
// integer, one outside the window either way, and a signature that does not verify,
// under another key, over another target, another instance id or another body, all
// get the same unsigned 401 and the same body. A header the signature depends on sent
// twice is an unsigned 400 bad_request before any of it.
func TestEveryFailureIsOneUnauthorized(t *testing.T) {
	h, _, asked := handler(t, 1700000000)
	ok := signedGET(server.WellKnown, fixtureKey, "1700000000")
	if rec := serve(h, ok); rec.Code != 200 || rec.Header().Get(server.HeaderConfiguration) == "" || !signedAnswer(ok, rec) {
		t.Fatalf("a valid GET: %d %v", rec.Code, rec.Header())
	}
	*asked = 0
	for name, req := range map[string]*http.Request{
		"a malformed access key id": func() *http.Request {
			r := signedGET(server.WellKnown, fixtureKey, "1700000000")
			r.Header.Set(server.HeaderAccessKeyID, "ak_F1XT0RE000000000")
			return r
		}(),
		"an empty access key id": func() *http.Request {
			r := signedGET(server.WellKnown, fixtureKey, "1700000000")
			r.Header.Set(server.HeaderAccessKeyID, "")
			return r
		}(),
		"no access key id at all": func() *http.Request {
			r := signedGET(server.WellKnown, fixtureKey, "1700000000")
			r.Header.Del(server.HeaderAccessKeyID)
			return r
		}(),
	} {
		if rec := serve(h, req); rec.Code != 401 || rec.Body.String() != `{"error":"unauthorized"}` || rec.Header().Get(server.HeaderSignature) != "" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if *asked != 0 {
		t.Errorf("the lookup was asked %d times for access key ids without the shape", *asked)
	}
	other := mustKey(accesskey.NewKey(make([]byte, 32)))
	body := registration(event.NewRunID(), nil, 30, 1700000000)
	for name, req := range map[string]*http.Request{
		"an unknown access key": func() *http.Request {
			r := signedGET(server.WellKnown, fixtureKey, "1700000000")
			r.Header.Set(server.HeaderAccessKeyID, "ak_0000000000000000")
			return r
		}(),
		"a timestamp that is not an integer": signedGET(server.WellKnown, fixtureKey, "1700000000.5"),
		"a signed timestamp":                 signedGET(server.WellKnown, fixtureKey, "+1700000000"),
		"a stale timestamp":                  signedGET(server.WellKnown, fixtureKey, "1699999699"),
		"a timestamp from the future":        signedGET(server.WellKnown, fixtureKey, "1700000301"),
		"another key":                        signedGET(server.WellKnown, other, "1700000000"),
		"a signature over another target": func() *http.Request {
			r := signedGET(server.WellKnown+"?x=1", fixtureKey, "1700000000")
			r.Header.Set(server.HeaderSignature, signedGET(server.WellKnown, fixtureKey, "1700000000").Header.Get(server.HeaderSignature))
			return r
		}(),
		"another instance id than the signed one": func() *http.Request {
			r := signedGET(server.WellKnown, fixtureKey, "1700000000")
			r.Header.Set(server.HeaderInstanceID, "i_other")
			return r
		}(),
		"no signature": func() *http.Request {
			r := signedGET(server.WellKnown, fixtureKey, "1700000000")
			r.Header.Del(server.HeaderSignature)
			return r
		}(),
		"a delivery under another key": signedPOST(receiver.DefaultEventsPath, other, []byte("[]")),
		"a delivery signed for another path": func() *http.Request {
			r := signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("[]"))
			r.Header.Set(server.HeaderSignature, signedPOST("/v1/other", fixtureKey, []byte("[]")).Header.Get(server.HeaderSignature))
			return r
		}(),
		"a delivery with no signature": func() *http.Request {
			r := signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("[]"))
			r.Header.Del(server.HeaderSignature)
			return r
		}(),
		"a registration under another access key id than the signed one": func() *http.Request {
			r := signedRegister(body)
			r.Header.Set(server.HeaderAccessKeyID, otherNode)
			return r
		}(),
		"a registration whose body is not the signed one": func() *http.Request {
			r := signedRegister(registration(event.NewRunID(), nil, 30, 1700000000))
			r.Header.Set(server.HeaderSignature, signedRegister(body).Header.Get(server.HeaderSignature))
			return r
		}(),
		"a reload signed for another run": func() *http.Request {
			r := reload(event.NewRunID(), "1700000000")
			r.Header.Set(server.HeaderSignature, reload(event.NewRunID(), "1700000000").Header.Get(server.HeaderSignature))
			return r
		}(),
	} {
		if rec := serve(h, req); rec.Code != 401 || rec.Body.String() != `{"error":"unauthorized"}` || rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get(server.HeaderSignature) != "" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	for _, name := range []string{server.HeaderAccessKeyID, server.HeaderInstanceID, server.HeaderSignature, server.HeaderTimestamp} {
		r := signedGET(server.WellKnown, fixtureKey, "1700000000")
		r.Header.Add(name, r.Header.Get(name))
		if rec := serve(h, r); rec.Code != 400 || rec.Body.String() != `{"error":"bad_request"}` || rec.Header().Get(server.HeaderSignature) != "" {
			t.Errorf("%s sent twice: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	for _, edge := range []string{"1699999700", "1700000300"} {
		if rec := serve(h, signedGET(server.WellKnown, fixtureKey, edge)); rec.Code != 200 {
			t.Errorf("a timestamp at the edge of the window, %s: %d", edge, rec.Code)
		}
	}
}

// TestSignedRefusalsComeInTheContractsOrder pins the refusals after verification,
// each signed and bound to its request: an instance id absent or outside its pattern
// is 400 bad_request, before another contract revision, which is 400
// unsupported_contract_version; a batch that is not one is 400 invalid_request.
func TestSignedRefusalsComeInTheContractsOrder(t *testing.T) {
	h, _, _ := handler(t, 1700000000)
	check := func(name string, req *http.Request, status int, code string) {
		t.Helper()
		rec := serve(h, req)
		want := ""
		if code != "" {
			want = `{"error":"` + code + `"}`
		}
		if rec.Code != status || rec.Body.String() != want || !signedAnswer(req, rec) {
			t.Errorf("%s: %d %s, signed %v; want %d %s", name, rec.Code, rec.Body.String(), signedAnswer(req, rec), status, code)
		}
	}
	check("no instance id", as(key, "", signedGET(server.WellKnown, fixtureKey, "1700000000")), 400, "bad_request")
	check("an instance id outside the pattern", as(key, "-i", signedGET(server.WellKnown, fixtureKey, "1700000000")), 400, "bad_request")
	check("a registration with no instance id", as(key, "", signedRegister(registration(event.NewRunID(), nil, 30, 1700000000))), 400, "bad_request")
	revision := signedGET(server.WellKnown, fixtureKey, "1700000000")
	revision.Header.Set(server.HeaderContractVersion, "2")
	check("another revision", revision, 400, "unsupported_contract_version")
	stale := signedRegister(registration(event.NewRunID(), map[string]string{"Forge": "x"}, 30, 1699999000))
	stale.Header.Set(server.HeaderContractVersion, "2")
	check("a registration of another revision", stale, 400, "unsupported_contract_version")
	check("an empty batch", signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("[]")), 400, "invalid_request")
}

// TestTheRunEndpointRefusesInItsOrder pins the run endpoint's own order after the
// shared one: a body the contract refuses is a signed 400 invalid_request, before a
// time outside the window, the unsigned 401; then a registration the receiver accepted
// with the same bytes gets the same answer again, before a run it wants nothing more
// of, a signed 410 without a code, before an instance it does not admit, a signed 409
// instance_limit, before a run id it accepted with other bytes, a signed 409
// run_id_used; then the hook's refusal, which keeps nothing of the run.
func TestTheRunEndpointRefusesInItsOrder(t *testing.T) {
	h, _, _ := handler(t, 1700000000)
	run := fixture(t, "fixtures/run-configuration/enforce.json")
	check := func(name string, req *http.Request, status int, code string) {
		t.Helper()
		rec := serve(h, req)
		want := ""
		if code != "" {
			want = `{"error":"` + code + `"}`
		}
		if rec.Code != status || rec.Body.String() != want || !signedAnswer(req, rec) {
			t.Errorf("%s: %d %s, signed %v; want %d %s", name, rec.Code, rec.Body.String(), signedAnswer(req, rec), status, code)
		}
	}
	unauthorized := func(name string, req *http.Request) {
		t.Helper()
		if rec := serve(h, req); rec.Code != 401 || rec.Body.String() != `{"error":"unauthorized"}` || rec.Header().Get(server.HeaderSignature) != "" {
			t.Errorf("%s: %d %s, want the unsigned 401", name, rec.Code, rec.Body.String())
		}
	}
	accepted := func(name string, req *http.Request) {
		t.Helper()
		if rec := serve(h, req); !runAnswer(req, rec, run) {
			t.Errorf("%s: %d %s %v", name, rec.Code, rec.Body.String(), rec.Header())
		}
	}
	id := event.NewRunID()
	shop := map[string]string{"forge": "github.com", "repository": "acme/shop"}
	hooked = 0
	for name, body := range map[string][]byte{
		"an interval over 300 seconds":                   registration(id, shop, 301, 1700000000),
		"no interval":                                    []byte(strings.Replace(string(registration(id, shop, 30, 1700000000)), `"interval_seconds":30,`, "", 1)),
		"a member the schema does not define":            []byte(strings.Replace(string(registration(id, shop, 30, 1700000000)), `"version":1`, `"version":1,"extra":true`, 1)),
		"a time with fractional seconds":                 []byte(strings.Replace(string(registration(id, shop, 30, 1700000000)), `22:13:20Z`, `22:13:20.5Z`, 1)),
		"a time that is no date":                         []byte(strings.Replace(string(registration(id, shop, 30, 1700000000)), `2023-11-14`, `2023-13-14`, 1)),
		"a run id not in the canonical form":             registration(strings.ToUpper(id), shop, 30, 1700000000),
		"labels the contract refuses":                    registration(id, map[string]string{"Forge": "x"}, 30, 1700000000),
		"a label value of 256 characters over 256 bytes": registration(id, map[string]string{"repository": strings.Repeat("é", 256)}, 30, 1700000000),
		"seventeen labels": registration(id, map[string]string{"k0": "v", "k1": "v", "k2": "v", "k3": "v", "k4": "v", "k5": "v", "k6": "v", "k7": "v",
			"k8": "v", "k9": "v", "k10": "v", "k11": "v", "k12": "v", "k13": "v", "k14": "v", "k15": "v", "k16": "v"}, 30, 1700000000),
		"an about the contract refuses":     []byte(strings.Replace(string(registration(id, shop, 30, 1700000000)), `"version":1`, `"version":1,"about":{"subjects":[{"type":"example","ref":"7"},{"type":"example","ref":"7"}]}`, 1)),
		"a body that is not JSON":           []byte("{"),
		"a refused body outside the window": registration(id, map[string]string{"Forge": "x"}, 30, 1699999000),
	} {
		check(name, signedRegister(body), 400, "invalid_request")
	}
	if hooked != 0 {
		t.Errorf("the hook was called %d times for registrations the contract refuses", hooked)
	}
	unauthorized("a stale time", signedRegister(registration(id, shop, 30, 1699999699)))
	unauthorized("a time from the future", signedRegister(registration(id, shop, 30, 1700000301)))
	accepted("a time at the edge of the window", signedRegister(registration(event.NewRunID(), shop, 30, 1699999700)))
	accepted("a time at the other edge", signedRegister(registration(event.NewRunID(), shop, 30, 1700000300)))
	accepted("a label value of 256 bytes", signedRegister(registration(event.NewRunID(), map[string]string{"repository": strings.Repeat("é", 128)}, 30, 1700000000)))

	admitted := true
	h.Admit = func(id, instance string) bool { return admitted && id == key && instance == inst }
	body := registration(id, shop, 30, 1700000000)
	accepted("a registration it admits", signedRegister(body))
	admitted = false
	accepted("the same bytes again", signedRegister(body))
	unauthorized("the same bytes outside the window", signedRegister(registration(id, shop, 30, 1699999000)))
	check("a new run of an instance it does not admit", signedRegister(registration(event.NewRunID(), shop, 30, 1700000000)), 409, "instance_limit")
	check("other bytes of the run id, from an instance it does not admit", signedRegister(registration(id, nil, 30, 1700000000)), 409, "instance_limit")
	admitted = true
	check("other labels for the run id", signedRegister(registration(id, nil, 30, 1700000000)), 409, "run_id_used")
	check("another time for the run id", signedRegister(registration(id, shop, 30, 1700000001)), 409, "run_id_used")
	h.Admit = nil
	check("the same bytes from another node", as(otherNode, inst, signedRegister(body)), 409, "run_id_used")

	stopped := event.NewRunID()
	h.Stop = func(run string) bool { return run == stopped || run == id }
	h.Admit = func(string, string) bool { return false }
	check("a run it wants nothing more of, from an instance it does not admit", signedRegister(registration(stopped, shop, 30, 1700000000)), 410, "")
	accepted("the same bytes of a run it accepted, though it wants nothing more of it", signedRegister(body))
	check("other bytes of a run it accepted and wants nothing more of", signedRegister(registration(id, nil, 30, 1700000000)), 410, "")
	h.Stop, h.Admit = nil, nil

	refused := event.NewRunID()
	check("a run the hook refuses", signedRegister(registration(refused, map[string]string{"repository": refusedRepository}, 30, 1700000000)), 409, "repository_unknown")
	accepted("the refused run id registered again with other labels", signedRegister(registration(refused, shop, 30, 1700000000)))
	h.RunConfiguration = func(receiver.Run) ([]byte, string, *receiver.Refusal) {
		return nil, "", &receiver.Refusal{Status: http.StatusGone}
	}
	check("a run the hook refuses with no code", signedRegister(registration(event.NewRunID(), shop, 30, 1700000000)), 410, "")
}

// TestRegistrationAndReload pins the run endpoint's answers: without a hook every run
// gets {"version":1}, with its digest as X-Qory-Run-Configuration and ETag; the hook
// is handed a copy of the labels, and its empty digest is the receiver's own; a reload
// by the run's id gives the run configuration again, and is answered only for a run
// registered under the same access key, a signed 404 otherwise; a run it wants
// nothing more of is a reload's 410; the content type is checked per path.
func TestRegistrationAndReload(t *testing.T) {
	h, _, _ := handler(t, 1700000000)
	h.RunConfiguration = nil
	shop := map[string]string{"forge": "github.com", "repository": "acme/shop"}
	id := event.NewRunID()
	req := signedRegister(registration(id, shop, 30, 1700000000))
	if rec := serve(h, req); !runAnswer(req, rec, []byte(`{"version":1}`)) {
		t.Errorf("a registration without a hook: %d %s %v", rec.Code, rec.Body.String(), rec.Header())
	}
	req = reload(id, "1700000000")
	if rec := serve(h, req); !runAnswer(req, rec, []byte(`{"version":1}`)) {
		t.Errorf("a reload without a hook: %d %s %v", rec.Code, rec.Body.String(), rec.Header())
	}
	notFound := func(name string, req *http.Request) {
		t.Helper()
		if rec := serve(h, req); rec.Code != http.StatusNotFound || rec.Body.Len() != 0 || !signedAnswer(req, rec) {
			t.Errorf("%s: %d %s, signed %v; want a signed 404", name, rec.Code, rec.Body.String(), signedAnswer(req, rec))
		}
	}
	notFound("a reload of a run never registered", reload(event.NewRunID(), "1700000000"))
	notFound("a reload of the run under another node's access key", as(otherNode, inst, reload(id, "1700000000")))
	if rec := serve(h, reload(id, "1699999699")); rec.Code != 401 || rec.Header().Get(server.HeaderSignature) != "" {
		t.Errorf("a reload with a stale timestamp: %d", rec.Code)
	}
	if rec := serve(h, as(key, "", reload(id, "1700000000"))); rec.Code != 400 || rec.Body.String() != `{"error":"bad_request"}` {
		t.Errorf("a reload with no instance id: %d %s", rec.Code, rec.Body.String())
	}

	var handed receiver.Run
	doc := []byte(`{"version":1,"security_policy":{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}}`)
	h.RunConfiguration = func(r receiver.Run) ([]byte, string, *receiver.Refusal) {
		handed = r
		handed.Labels = maps.Clone(r.Labels)
		r.Labels["repository"] = "changed"
		return doc, "", nil
	}
	req = reload(id, "1700000000")
	if rec := serve(h, req); !runAnswer(req, rec, doc) {
		t.Errorf("a reload once the hook gives a policy: %d %s %v", rec.Code, rec.Body.String(), rec.Header())
	}
	req = reload(id, "1700000000")
	if rec := serve(h, req); !runAnswer(req, rec, doc) || !maps.Equal(handed.Labels, shop) || handed.ID != id || handed.About != nil {
		t.Errorf("a second reload: %d, the hook handed %+v", rec.Code, handed)
	}
	h.Stop = func(run string) bool { return run == id }
	if req := reload(id, "1700000000"); func() bool {
		rec := serve(h, req)
		return rec.Code != 410 || rec.Body.Len() != 0 || !signedAnswer(req, rec)
	}() {
		t.Errorf("a reload of a run it wants nothing more of: want a signed 410")
	}
	h.Stop = nil

	body := registration(event.NewRunID(), nil, 30, 1700000000)
	for name, ct := range map[string]string{
		"the batch type": server.ContentType,
		"no type":        "",
		"text":           "text/plain",
	} {
		r := signedRegister(body)
		r.Header.Set("Content-Type", ct)
		r.Header.Del(server.HeaderSignature)
		if rec := serve(h, r); rec.Code != http.StatusUnsupportedMediaType || rec.Header().Get(server.HeaderSignature) != "" {
			t.Errorf("a registration of %s: %d", name, rec.Code)
		}
	}
	r := signedRegister(body)
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	if rec := serve(h, r); !runAnswer(r, rec, doc) || handed.Labels == nil || len(handed.Labels) != 0 {
		t.Errorf("a registration of application/json with a parameter and no labels: %d %s, the hook handed %v", rec.Code, rec.Body.String(), handed.Labels)
	}
	g := reload(id, "1700000000")
	g.Header.Set("Content-Type", server.ContentType)
	if rec := serve(h, g); rec.Code != 200 {
		t.Errorf("a reload with a content type: %d", rec.Code)
	}
	for name, req := range map[string]*http.Request{
		"a reload of a run id in upper case": reload(strings.ToUpper(id), "1700000000"),
		"a reload of no run id":              signedGET(receiver.DefaultRunPath+"/", fixtureKey, "1700000000"),
		"a reload below the run id":          signedGET(receiver.DefaultRunPath+"/"+id+"/x", fixtureKey, "1700000000"),
	} {
		if rec := serve(h, req); rec.Code != 404 || rec.Header().Get(server.HeaderSignature) != "" {
			t.Errorf("%s: %d, want the unsigned 404 of a path not served", name, rec.Code)
		}
	}
	if rec := serve(h, signedGET(receiver.DefaultRunPath, fixtureKey, "1700000000")); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Errorf("a GET of the run endpoint: %d", rec.Code)
	}
	if rec := serve(h, signedPOST(receiver.DefaultRunPath+"/"+id, fixtureKey, []byte("[]"))); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Errorf("a POST of a run: %d", rec.Code)
	}
}

// TestDeliveriesAreStoredOnceAndAnsweredWithTheDigests pins the events endpoint: the
// wrong content type is 415, before verification, a duplicate is not stored twice, a
// reopened store still knows its ids, and the answer contains the configuration
// digest and, once the run registered, the run configuration digest the hook gives
// for it, both under its signature; a run the receiver wants nothing more of is a
// signed 410 without a code. No delivery is a registration: a batch's labels reach no
// hook.
func TestDeliveriesAreStoredOnceAndAnsweredWithTheDigests(t *testing.T) {
	h, store, _ := handler(t, 1700000000)
	e := event.NewEmitter(event.NewRunID(), nil)
	started, _ := e.Make(event.RunStarted, map[string]any{"runtime": "x", "labels": map[string]string{"forge": "github.com", "repository": "acme/shop"}}).JSON()
	body := []byte("[" + string(started) + "," + string(started) + "]")
	wrong := signedPOST(receiver.DefaultEventsPath, fixtureKey, body)
	wrong.Header.Set("Content-Type", "application/json")
	wrong.Header.Del(server.HeaderSignature)
	if rec := serve(h, wrong); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("wrong content type: %d", rec.Code)
	}
	first := signedPOST(receiver.DefaultEventsPath, fixtureKey, body)
	rec := serve(h, first)
	if rec.Code != http.StatusAccepted || rec.Header().Get(server.HeaderConfiguration) == "" || rec.Header().Get(server.HeaderRunConfiguration) != "" || !signedAnswer(first, rec) || hooked != 0 {
		t.Errorf("a delivery of a run that never registered: %d %v, the hook called %d times", rec.Code, rec.Header(), hooked)
	}
	if store.Count() != 1 {
		t.Errorf("stored %d, want the duplicate dropped", store.Count())
	}
	run := fixture(t, "fixtures/run-configuration/enforce.json")
	if req := signedRegister(registration(e.RunID(), map[string]string{"forge": "github.com", "repository": "acme/shop"}, 30, 1700000000)); !runAnswer(req, serve(h, req), run) {
		t.Fatal("the registration of the run was not accepted")
	}
	beat, _ := e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30}).JSON()
	second := signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(beat)+"]"))
	rec = serve(h, second)
	if rec.Code != http.StatusAccepted || rec.Header().Get(server.HeaderRunConfiguration) != digestOf(run) || !signedAnswer(second, rec) {
		t.Errorf("a delivery of a registered run: %d %v", rec.Code, rec.Header())
	}
	h.Stop = func(run string) bool { return run == e.RunID() }
	beat2, _ := e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 60, "interval_seconds": 30}).JSON()
	stop := signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(beat2)+"]"))
	if rec := serve(h, stop); rec.Code != http.StatusGone || rec.Body.Len() != 0 || !signedAnswer(stop, rec) {
		t.Errorf("a delivery of a run it wants nothing more of: %d %s", rec.Code, rec.Body.String())
	}
	h.Stop = nil
	if rec := serve(h, signedGET("/elsewhere", fixtureKey, "1700000000")); rec.Code != 404 {
		t.Errorf("a path the receiver does not serve: %d", rec.Code)
	}
	if rec := serve(h, signedGET(receiver.DefaultEventsPath, fixtureKey, "1700000000")); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("a GET of the events endpoint: %d", rec.Code)
	}
	path := filepath.Join(t.TempDir(), "received.jsonl")
	f, _ := receiver.OpenFile(path)
	f.Append("one", []byte(`{"id":"one"}`))
	f.Close()
	reopened, err := receiver.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reopened.Seen("one") || reopened.Count() != 1 {
		t.Errorf("reopened store holds %d ids", reopened.Count())
	}
	fh, _ := os.Open(path)
	defer fh.Close()
	n := 0
	for s := bufio.NewScanner(fh); s.Scan(); {
		n++
	}
	if n != 1 {
		t.Errorf("%d lines in the file", n)
	}
}

// TestAboutIsStoredAsReceived pins that a run.started with about is stored as
// Forager sent it, byte for byte. The receiver reads nothing of about and holds it to no
// bound: one with two subjects of the same type and ref is stored all the same.
func TestAboutIsStoredAsReceived(t *testing.T) {
	h, _, _ := handler(t, 1700000000)
	path := filepath.Join(t.TempDir(), "received.jsonl")
	store, err := receiver.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h.Store = store
	about := json.RawMessage(`{"kind":"example","title":"Example","subjects":[` +
		`{"type":"example","ref":"7","url":"https://qory.example/examples/7"},` +
		`{"type":"example","ref":"7"}],"details":{"a":[1,{"b":null}]}}`)
	e := event.NewEmitter(event.NewRunID(), nil)
	data := map[string]any{"runtime": "x", "about": about}
	line, err := e.Make(event.RunStarted, data).JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), `"about":`+string(about)) {
		t.Fatalf("the event does not contain the about as given:\n%s", line)
	}
	req := signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(line)+"]"))
	if rec := serve(h, req); rec.Code != http.StatusAccepted || !signedAnswer(req, rec) {
		t.Fatalf("a delivery of run.started with about: %d", rec.Code)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(line)+"\n" {
		t.Errorf("stored\n%s\nwant\n%s", b, line)
	}
}

// TestAKeyOfSmallOrderVerifiesNoRequest pins that a public key the key checks refuse,
// listed in the receiver's configuration, verifies no request: the forged signature
// R = identity, S = 0 under the identity key is an unsigned 401.
func TestAKeyOfSmallOrderVerifiesNoRequest(t *testing.T) {
	h, _, _ := handler(t, 1700000000)
	identity, err := accesskey.ParsePublicKey("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	h.Keys = func(string) (receiver.AccessKey, bool) { return receiver.AccessKey{PublicKey: identity}, true }
	forged := make([]byte, 64)
	forged[0] = 1
	r := signedGET(server.WellKnown, fixtureKey, "1700000000")
	r.Header.Set(server.HeaderSignature, base64.RawURLEncoding.EncodeToString(forged))
	if rec := serve(h, r); rec.Code != 401 || rec.Header().Get(server.HeaderSignature) != "" {
		t.Errorf("a forged request under the identity key: %d", rec.Code)
	}
}
