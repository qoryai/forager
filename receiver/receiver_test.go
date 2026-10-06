package receiver_test

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	"github.com/qoryai/runner/accesskey"
	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/internal/event"
	"github.com/qoryai/runner/internal/server"
	"github.com/qoryai/runner/receiver"
)

const (
	key     = "ak_f1xt0re000000000"
	pending = "ak_pend1ng000000000"
	inst    = "i_gYKDhIWGh4iJiouMjY6PkA"
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

// keys is a lookup that knows the fixture access key, approved, and the same public key
// under a second id awaiting approval, and counts how often it is asked.
func keys(asked *int) func(string) (receiver.AccessKey, bool) {
	return func(k string) (receiver.AccessKey, bool) {
		*asked++
		switch k {
		case key:
			return receiver.AccessKey{PublicKey: fixtureKey.PublicKey()}, true
		case pending:
			return receiver.AccessKey{PublicKey: fixtureKey.PublicKey(), Pending: true}, true
		}
		return receiver.AccessKey{}, false
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// digestOf is a receiver's digest of a document: any string, opaque to the runner;
// here the hex sha256 of the bytes.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256=" + hex.EncodeToString(sum[:])
}

// handler is a receiver over a fresh store, serving the contract's fixtures as its
// documents, with its clock where the test puts it. The run configuration hook records
// the labels it was last handed in asked.
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
	h := &receiver.Handler{
		Keys:          keys(asked),
		Signer:        signingKey,
		Store:         store,
		Now:           func() time.Time { return time.Unix(now, 0) },
		Configuration: func() ([]byte, string) { return conf, digestOf(conf) },
		RunConfiguration: func(labels map[string]string) ([]byte, string, bool) {
			lastLabels = maps.Clone(labels)
			if labels["forge"] == "none.example" {
				return nil, "", false
			}
			return run, digestOf(run), true
		},
	}
	return h, store, asked
}

// lastLabels are the labels the run configuration hook was last handed. The tests
// that read it do not run in parallel.
var lastLabels map[string]string

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

// signedAnswer reports whether the answer is signed under the receiver's key and
// bound to the request.
func signedAnswer(req *http.Request, rec *httptest.ResponseRecorder) bool {
	return pin.VerifyAnswer(accesskey.Answer{Status: rec.Code, RequestSignature: req.Header.Get(server.HeaderSignature), Body: rec.Body.Bytes(),
		Configuration: rec.Header().Get(server.HeaderConfiguration), RunConfiguration: rec.Header().Get(server.HeaderRunConfiguration)}, rec.Header().Get(server.HeaderSignature)) &&
		rec.Header().Get("Cache-Control") == "no-store, no-transform"
}

func serve(h *receiver.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestSignedFixturesReplay pins the receiver against the contract's signed fixtures:
// each, sent as recorded with the receiver's clock at the fixture time, gets the
// status and the code the fixture expects, the replayed batch stores nothing twice,
// every 401 and every refusal before verification goes out unsigned, and every other
// answer is signed under the receiver's key and bound to the request.
func TestSignedFixturesReplay(t *testing.T) {
	h, store, _ := handler(t, 1700000000)
	names, err := fs.Glob(contracts.FS, "fixtures/signed/*.json")
	if err != nil || len(names) < 12 {
		t.Fatalf("signed fixtures: %v, %v", names, err)
	}
	sort.Strings(names)
	var first []json.RawMessage
	json.Unmarshal(fixture(t, "fixtures/batch/first.json"), &first)
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
		if rec.Code == http.StatusOK && strings.HasPrefix(f.Target, receiver.DefaultRunPath) && (rec.Header().Get(server.HeaderRunConfiguration) == "" || rec.Header().Get("ETag") != `"`+rec.Header().Get(server.HeaderRunConfiguration)+`"`) {
			t.Errorf("%s: the run configuration answer's headers %v", name, rec.Header())
		}
		// Each run configuration fetch hands the hook every label its query carries.
		if want, ok := map[string]map[string]string{
			"get-run-configuration-valid.json":        {"forge": "github.com", "repository": "acme/shop"},
			"get-run-configuration-labels-valid.json": {"forge": "github.com", "issue": "77", "repository": "acme/shop"},
		}[path.Base(name)]; ok && !maps.Equal(lastLabels, want) {
			t.Errorf("%s: the hook was handed %v, want %v", name, lastLabels, want)
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
			r.Header.Set(server.HeaderSignature, signedPOST("/v1/secrets", fixtureKey, []byte("[]")).Header.Get(server.HeaderSignature))
			return r
		}(),
		"a delivery with no signature": func() *http.Request {
			r := signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("[]"))
			r.Header.Del(server.HeaderSignature)
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
// is 400 bad_request, before an access key that awaits approval, which is 409
// key_pending on every endpoint, a stale timestamp's 401 coming later, before another
// contract revision, which is 400 unsupported_contract_version; a batch that is not
// one, or a ping with an interval over 300 seconds, is 400 invalid_request; and on
// the events endpoint, a closed run is 410 run_closed, a run the receiver wants
// nothing more of 410 without a code, and a ping from an instance it does not admit 409
// instance_limit, while a retried ping it already accepted gets its 202 again.
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
	as := func(id string, r *http.Request) *http.Request {
		r.Header.Set(server.HeaderAccessKeyID, id)
		target := r.URL.RequestURI()
		sr := accesskey.Request{AccessKeyID: id, InstanceID: r.Header.Get(server.HeaderInstanceID), Method: r.Method, Target: target, Timestamp: r.Header.Get(server.HeaderTimestamp)}
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(b)))
			sr.Body = b
		}
		sig, _ := fixtureKey.SignRequest(sr)
		r.Header.Set(server.HeaderSignature, sig)
		return r
	}
	instance := func(id string, r *http.Request) *http.Request {
		if id == "" {
			r.Header.Del(server.HeaderInstanceID)
		} else {
			r.Header.Set(server.HeaderInstanceID, id)
		}
		return as(r.Header.Get(server.HeaderAccessKeyID), r)
	}
	check("no instance id", instance("", signedGET(server.WellKnown, fixtureKey, "1700000000")), 400, "bad_request")
	check("an instance id outside the pattern", instance("-i", signedGET(server.WellKnown, fixtureKey, "1700000000")), 400, "bad_request")
	check("no instance id, pending", instance("", as(pending, signedGET(server.WellKnown, fixtureKey, "1700000000"))), 400, "bad_request")
	check("a pending key at discovery", as(pending, signedGET(server.WellKnown, fixtureKey, "1700000000")), 409, "key_pending")
	check("a pending key at the run configuration", as(pending, signedGET(receiver.DefaultRunPath, fixtureKey, "1700000000")), 409, "key_pending")
	check("a pending key at the events endpoint", as(pending, signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("[]"))), 409, "key_pending")
	check("a pending key with a stale timestamp", as(pending, signedGET(server.WellKnown, fixtureKey, "1699999000")), 409, "key_pending")
	revision := signedGET(server.WellKnown, fixtureKey, "1700000000")
	revision.Header.Set(server.HeaderContractVersion, "2")
	check("another revision", revision, 400, "unsupported_contract_version")
	check("an empty batch", signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("[]")), 400, "invalid_request")
	check("labels the contract refuses", signedGET(receiver.DefaultRunPath+"?Forge=x", fixtureKey, "1700000000"), 400, "invalid_request")

	e := event.NewEmitter(event.NewRunID(), nil)
	ping, _ := e.Make(event.Ping, map[string]any{"runner_version": "test", "events": []string{"*"}, "contract_version": 1, "interval_seconds": 30}).JSON()
	pingBody := []byte("[" + string(ping) + "]")
	long, _ := e.Make(event.Ping, map[string]any{"runner_version": "test", "events": []string{"*"}, "contract_version": 1, "interval_seconds": 301}).JSON()
	check("a ping with an interval over 300 seconds", signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(long)+"]")), 400, "invalid_request")
	admitted := true
	h.Admit = func(id, instance string) bool { return admitted && id == key && instance == inst }
	check("a ping it admits", signedPOST(receiver.DefaultEventsPath, fixtureKey, pingBody), 202, "")
	admitted = false
	check("the same ping again", signedPOST(receiver.DefaultEventsPath, fixtureKey, pingBody), 202, "")
	other, _ := event.NewEmitter(event.NewRunID(), nil).Make(event.Ping, map[string]any{"runner_version": "test", "events": []string{"*"}, "contract_version": 1, "interval_seconds": 30}).JSON()
	check("a ping it does not admit", signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(other)+"]")), 409, "instance_limit")

	beat, _ := e.Make(event.RunHeartbeat, map[string]any{"elapsed_seconds": 30, "interval_seconds": 30}).JSON()
	h.Stop = func(run string) bool { return run == e.RunID() }
	check("a run it wants nothing more of", signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(beat)+"]")), 410, "")
	h.Closed = func(run string) bool { return run == e.RunID() }
	check("a closed run", signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(beat)+"]")), 410, "run_closed")
}

// TestDeliveriesAreStoredOnceAndAnsweredWithTheDigests pins the events endpoint: the
// wrong content type is 415, before verification, a duplicate is not stored twice, a
// reopened store still knows its ids, and the answer contains the configuration digest
// and, once the run's run.started named its labels, the run configuration digest for
// all of them, both under its signature. It pins the run configuration endpoint too:
// the query is the run's labels, and one that is not, once the request verifies, is a
// signed 400 invalid_request the hook never sees.
func TestDeliveriesAreStoredOnceAndAnsweredWithTheDigests(t *testing.T) {
	h, store, _ := handler(t, 1700000000)
	e := event.NewEmitter(event.NewRunID(), nil)
	started, _ := e.Make(event.RunStarted, map[string]any{"runtime": "x", "labels": map[string]string{"forge": "none.example", "repository": "acme/shop"}}).JSON()
	body := []byte("[" + string(started) + "," + string(started) + "]")
	wrong := signedPOST(receiver.DefaultEventsPath, fixtureKey, body)
	wrong.Header.Set("Content-Type", "application/json")
	wrong.Header.Del(server.HeaderSignature)
	if rec := serve(h, wrong); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("wrong content type: %d", rec.Code)
	}
	first := signedPOST(receiver.DefaultEventsPath, fixtureKey, body)
	rec := serve(h, first)
	if rec.Code != http.StatusAccepted || rec.Header().Get(server.HeaderConfiguration) == "" || rec.Header().Get(server.HeaderRunConfiguration) != "" || !signedAnswer(first, rec) {
		t.Errorf("a delivery for a forge with no run configuration: %d %v", rec.Code, rec.Header())
	}
	if store.Count() != 1 {
		t.Errorf("stored %d, want the duplicate dropped", store.Count())
	}
	other := event.NewEmitter(event.NewRunID(), nil)
	labels := map[string]string{"forge": "github.com", "issue": "77", "repository": "acme/shop"}
	line, _ := other.Make(event.RunStarted, map[string]any{"runtime": "x", "labels": labels}).JSON()
	second := signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(line)+"]"))
	rec = serve(h, second)
	run := fixture(t, "fixtures/run-configuration/enforce.json")
	if rec.Code != http.StatusAccepted || rec.Header().Get(server.HeaderRunConfiguration) != digestOf(run) || !maps.Equal(lastLabels, labels) || !signedAnswer(second, rec) {
		t.Errorf("a delivery for a forge with a run configuration: %d %v, the hook handed %v", rec.Code, rec.Header(), lastLabels)
	}
	lastLabels = nil
	if rec := serve(h, signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(line)+"]"))); rec.Code != http.StatusAccepted || !maps.Equal(lastLabels, labels) {
		t.Errorf("a later delivery of the run: %d, the hook handed %v", rec.Code, lastLabels)
	}
	unknown := event.NewEmitter(event.NewRunID(), nil)
	log, _ := unknown.Make(event.RunLog, map[string]any{"stream": "stdout", "bytes": "eA=="}).JSON()
	if rec := serve(h, signedPOST(receiver.DefaultEventsPath, fixtureKey, []byte("["+string(log)+"]"))); rec.Code != http.StatusAccepted || lastLabels == nil || len(lastLabels) != 0 {
		t.Errorf("a delivery of a run whose run.started was not seen: %d, the hook handed %v", rec.Code, lastLabels)
	}
	if rec := serve(h, signedGET(receiver.DefaultRunPath+"?forge=github.com&repository=acme%2Fshop", fixtureKey, "1700000000")); rec.Code != 200 || rec.Header().Get("ETag") != `"`+digestOf(run)+`"` || rec.Body.String() != string(run) {
		t.Errorf("the run configuration: %d %v", rec.Code, rec.Header())
	}
	if rec := serve(h, signedGET(receiver.DefaultRunPath+"?forge=none.example", fixtureKey, "1700000000")); rec.Code != 404 {
		t.Errorf("the run configuration of a forge without one: %d", rec.Code)
	}
	if rec := serve(h, signedGET(receiver.DefaultRunPath, fixtureKey, "1700000000")); rec.Code != 200 || lastLabels == nil || len(lastLabels) != 0 {
		t.Errorf("the run configuration of a run with no label: %d, the hook handed %v", rec.Code, lastLabels)
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = fmt.Sprintf("k%d=v", i)
	}
	for name, query := range map[string]string{
		"a key sent twice":       "forge=github.com&forge=gitlab.com",
		"an upper-case key":      "Forge=github.com",
		"an empty key":           "=github.com",
		"a value over 256 bytes": "note=" + strings.Repeat("v", 257),
		"a value not UTF-8":      "note=%FF",
		"a malformed escape":     "note=%zz",
		"seventeen labels":       strings.Join(many, "&"),
	} {
		lastLabels = nil
		rec := serve(h, signedGET(receiver.DefaultRunPath+"?"+query, fixtureKey, "1700000000"))
		if rec.Code != http.StatusBadRequest || lastLabels != nil {
			t.Errorf("%s: %d, the hook handed %v", name, rec.Code, lastLabels)
		}
	}
	bad := signedGET(receiver.DefaultRunPath+"?Forge=github.com", fixtureKey, "1700000000")
	bad.Header.Set(server.HeaderSignature, signedGET(receiver.DefaultRunPath, fixtureKey, "1700000000").Header.Get(server.HeaderSignature))
	if rec := serve(h, bad); rec.Code != 401 {
		t.Errorf("a query that is not labels under a signature that does not verify: %d, want the 401 first", rec.Code)
	}
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

// TestAKeyOfSmallOrderVerifiesNoRequest pins that a public key the key checks refuse,
// pasted into the receiver's configuration, verifies no request: the forged signature
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
