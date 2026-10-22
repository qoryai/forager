package runkey_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/runkey/internal/knownanswers"
)

// read reads a file of the contract.
func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(contracts.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestKnownAnswersAreCurrent pins that the known answers of a run through a gateway
// under the contract's fixtures are what package knownanswers writes: go generate
// ./runkey writes them again.
func TestKnownAnswersAreCurrent(t *testing.T) {
	files, err := knownanswers.Files()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		if got := read(t, path.Join(knownanswers.Dir, name)); !bytes.Equal(got, want) {
			t.Errorf("%s differs from what package knownanswers writes; run go generate ./runkey", name)
		}
	}
}

// TestTheFixtureGatewayKey pins the fixture gateway key of keys.json: its secret is
// qak_ and the seed, bytes 97 to 128, its public key and fingerprint are the seed's,
// its id is in its form, and the accesskey package reports it as a published fixture
// key, which qory and the server refuse.
func TestTheFixtureGatewayKey(t *testing.T) {
	var keys struct {
		GatewayKey struct {
			Secret      string `json:"secret"`
			AccessKeyID string `json:"access_key_id"`
			PublicKey   string `json:"public_key"`
			Fingerprint string `json:"fingerprint"`
		} `json:"gateway_key"`
	}
	if err := json.Unmarshal(read(t, "fixtures/known-answers/keys.json"), &keys); err != nil {
		t.Fatal(err)
	}
	g := keys.GatewayKey
	want := knownanswers.GatewayKey()
	if g.Secret != want.Secret() || g.PublicKey != want.PublicKey().String() || g.Fingerprint != want.Fingerprint() {
		t.Errorf("keys.json gateway_key %s, %s; want the key of bytes 97 to 128, %s, %s", g.PublicKey, g.Fingerprint, want.PublicKey(), want.Fingerprint())
	}
	if g.AccessKeyID != knownanswers.GatewayAccessKeyID || accesskey.CheckID(g.AccessKeyID) != nil {
		t.Errorf("gateway key id %q; want %s, in its form", g.AccessKeyID, knownanswers.GatewayAccessKeyID)
	}
	if !want.PublicKey().Fixture() {
		t.Error("the fixture gateway key is not reported as a fixture")
	}
}

// vectors is through-gateway.json.
func vectors(t *testing.T) knownanswers.Vectors {
	t.Helper()
	var v knownanswers.Vectors
	if err := json.Unmarshal(read(t, "fixtures/known-answers/through-gateway.json"), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestTheRunKeyKnownAnswer pins the run key of through-gateway.json: its message is the
// domain line, a line feed and the payload file's bytes, its signature verifies under
// the fixture signing key, the run key is qrk_ and the two parts, Verify reads the
// fixture's members from it under a pin of the fixture signing key, and Parse reads
// them unverified.
func TestTheRunKeyKnownAnswer(t *testing.T) {
	v := vectors(t).RunKey
	p := read(t, v.Payload)
	if len(p) != v.PayloadLength || len(v.Lines) != 2 || v.Lines[0] != runkey.Domain || v.Lines[1] != string(p) {
		t.Fatalf("the vector's lines are not the domain line and the payload file")
	}
	m := strings.Join(v.Lines, "\n")
	if len(m) != v.Length {
		t.Errorf("message of %d bytes; want %d", len(m), v.Length)
	}
	signing := knownanswers.SigningKey()
	if !(accesskey.Pin{{Alg: "ed25519", PublicKey: signing.PublicKey().String()}}).Verify([]byte(m), v.Signature) {
		t.Error("the signature does not verify under the fixture signing key")
	}
	if !strings.HasPrefix(v.RunKey, runkey.Prefix) || !strings.HasSuffix(v.RunKey, "."+v.Signature) {
		t.Errorf("the run key is not qrk_, the payload, a dot and the signature")
	}
	k, err := runkey.Verify(v.RunKey, pinOf(signing))
	if err != nil {
		t.Fatal(err)
	}
	want := knownanswers.Key()
	if !k.Verified() || k.RunID != want.RunID || k.NodeID != want.NodeID || k.Gateway != want.Gateway ||
		k.GatewayURL != want.GatewayURL || len(k.GatewayKeys) != 1 || k.GatewayKeys[0] != want.GatewayKeys[0] ||
		k.Signer != signing.Fingerprint() {
		t.Errorf("verified %+v; want the fixture's", k)
	}
	parsed, err := runkey.Parse(v.RunKey)
	if err != nil || parsed.Verified() || parsed.RunID != want.RunID {
		t.Errorf("parsed %+v, %v; want the fixture's, unverified", parsed, err)
	}
}

// TestTheRequestAndAnswerKnownAnswers pins the requests of through-gateway.json, the
// registration through a gateway, the attach and the outcome, each signed by its access
// key, the attach by the fixture gateway key, over six lines whose last is its body
// file; and their answers, each signed by the fixture signing key over six lines bound
// to its request's signature, the fourth its body file's SHA-256. The registration's
// answer carries the run key of the vector, and the attach carries it too.
func TestTheRequestAndAnswerKnownAnswers(t *testing.T) {
	v := vectors(t)
	if len(v.Requests) != 3 || len(v.Answers) != 3 {
		t.Fatalf("%d requests and %d answers; want 3 of each", len(v.Requests), len(v.Answers))
	}
	signers := map[string]*accesskey.Key{
		knownanswers.AccessKeyID:        knownanswers.AccessKey(),
		knownanswers.GatewayAccessKeyID: knownanswers.GatewayKey(),
	}
	for i, r := range v.Requests {
		body := read(t, r.Body)
		k := signers[r.AccessKeyID]
		if k == nil || len(r.Lines) != 6 || r.Lines[1] != r.AccessKeyID || r.Lines[2] != knownanswers.InstanceID || r.Lines[5] != string(body) {
			t.Errorf("%s: lines are not its access key's request string over its body", r.Note)
			continue
		}
		req := accesskey.Request{AccessKeyID: r.AccessKeyID, InstanceID: r.Lines[2], Method: r.Lines[3], Target: r.Lines[4], Body: body}
		m, _ := req.Message()
		if string(m) != strings.Join(r.Lines, "\n") || len(m) != r.Length {
			t.Errorf("%s: message of %d bytes is not its lines", r.Note, len(m))
		}
		if !k.PublicKey().VerifyRequest(req, r.Signature) {
			t.Errorf("%s: the signature does not verify", r.Note)
		}
		a := v.Answers[i]
		ab := read(t, a.Body)
		sum := sha256.Sum256(ab)
		if len(ab) != a.BodyLength || len(a.Lines) != 6 || a.Lines[0] != accesskey.AnswerDomain || a.Lines[1] != "200" ||
			a.Lines[2] != r.Signature || a.Lines[3] != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: lines %q are not a 200 bound to its request over its body", a.Note, a.Lines)
			continue
		}
		ans := accesskey.Answer{Status: 200, RequestSignature: r.Signature, Body: ab, Configuration: a.Lines[4], RunConfiguration: a.Lines[5]}
		if string(ans.Message()) != strings.Join(a.Lines, "\n") || len(ans.Message()) != a.Length {
			t.Errorf("%s: message is not its lines", a.Note)
		}
		if !pinOf(knownanswers.SigningKey()).VerifyAnswer(ans, a.Signature) {
			t.Errorf("%s: the signature does not verify", a.Note)
		}
	}
	for _, f := range []string{v.Answers[0].Body, v.Requests[1].Body} {
		var doc struct {
			RunKey string `json:"run_key"`
		}
		if err := json.Unmarshal(read(t, f), &doc); err != nil || doc.RunKey != v.RunKey.RunKey {
			t.Errorf("%s does not carry the run key of the vector", f)
		}
	}
}

// TestTheRelayedEnrolmentKnownAnswer pins run_enrolment.relay of through-gateway.json:
// the redemption's request file as the gateway's relay signs it, six lines under the
// fixture gateway key's id and the gateway's instance id, a POST to the enrolment
// endpoint whose last line is the file's bytes, white space and trailing line feed
// included; the signature verifies under the fixture gateway key, and over no other
// body, the file without its white space at the ends among them.
func TestTheRelayedEnrolmentKnownAnswer(t *testing.T) {
	e := vectors(t).RunEnrolment
	r := e.Relay
	body := read(t, r.Body)
	if r.Body != e.Request || !bytes.HasSuffix(body, []byte("}\n")) || !bytes.Contains(body, []byte("\n  \"")) {
		t.Fatalf("%s is not the redemption's request file, indented and with a trailing line feed", r.Body)
	}
	want := []string{accesskey.RequestDomain, knownanswers.GatewayAccessKeyID, knownanswers.InstanceID, "POST", accesskey.EnrolmentPath, string(body)}
	if r.AccessKeyID != knownanswers.GatewayAccessKeyID || !slices.Equal(r.Lines, want) {
		t.Fatalf("the lines %q are not the gateway's request string over the file", r.Lines)
	}
	req := accesskey.Request{AccessKeyID: r.AccessKeyID, InstanceID: knownanswers.InstanceID, Method: "POST", Target: accesskey.EnrolmentPath, Body: body}
	m, err := req.Message()
	if err != nil || string(m) != strings.Join(r.Lines, "\n") || len(m) != r.Length {
		t.Errorf("the message of %d bytes is not its lines: %v", len(m), err)
	}
	g := knownanswers.GatewayKey()
	if s, err := g.SignRequest(req); err != nil || s != r.Signature {
		t.Errorf("the fixture gateway key signs %s, %v; want %s", s, err, r.Signature)
	}
	if !g.PublicKey().VerifyRequest(req, r.Signature) {
		t.Error("the signature does not verify under the fixture gateway key")
	}
	if req.Body = bytes.TrimSpace(body); g.PublicKey().VerifyRequest(req, r.Signature) {
		t.Error("the signature verifies over the body without its white space at the ends")
	}
}

// TestTheBindingKnownAnswer pins the binding of through-gateway.json: for its fixed
// exporter value, link.BindingMessage of the fixture gateway key's fingerprint is its
// three lines, the fixture gateway key signs them to its signature, which verifies, and
// link.BoundLine is its bound line, under the exporter label link.BindingLabel.
func TestTheBindingKnownAnswer(t *testing.T) {
	b := vectors(t).Binding
	ekm, err := hex.DecodeString(b.EKM)
	if err != nil || !bytes.Equal(ekm, knownanswers.BindingEKM()) || len(ekm) != link.BindingSize {
		t.Fatalf("ekm %s is not the fixed exporter value", b.EKM)
	}
	g := knownanswers.GatewayKey()
	if b.Label != link.BindingLabel || b.Fingerprint != g.Fingerprint() {
		t.Errorf("label %s, fingerprint %s; want %s, the fixture gateway key's %s", b.Label, b.Fingerprint, link.BindingLabel, g.Fingerprint())
	}
	m := link.BindingMessage(ekm, b.Fingerprint)
	if len(b.Lines) != 3 || b.Lines[0] != link.BindingDomain || string(m) != strings.Join(b.Lines, "\n") || len(m) != b.Length {
		t.Errorf("link.BindingMessage is %q; want the vector's lines %q", m, b.Lines)
	}
	if got := base64.RawURLEncoding.EncodeToString(g.Sign(m)); got != b.Signature {
		t.Errorf("the fixture gateway key signs %s; want %s", got, b.Signature)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(b.Signature)
	if err != nil || !g.PublicKey().Verify(m, sig) {
		t.Error("the signature does not verify under the fixture gateway key")
	}
	if got := link.BoundLine(b.Fingerprint, b.Signature); got != b.BoundLine || got != link.BoundWord+" "+b.Fingerprint+" "+b.Signature+"\n" {
		t.Errorf("link.BoundLine is %q; want %q", got, b.BoundLine)
	}
}

// TestTheLinkAnswerKnownAnswer pins the link answer of through-gateway.json: its four
// request lines are the exporter value, the method, the target and its body file,
// link.AnswerRequest is their SHA-256 and the answer's third line, the answer's message
// with Link set is its six lines under the link answer's domain line, the fixture
// gateway key signs them to its signature, and VerifyAnswer accepts it, as a key and in
// a pin.
func TestTheLinkAnswerKnownAnswer(t *testing.T) {
	la := vectors(t).LinkAnswer
	ekm, err := hex.DecodeString(la.EKM)
	if err != nil || !bytes.Equal(ekm, knownanswers.BindingEKM()) {
		t.Fatalf("ekm %s is not the fixed exporter value", la.EKM)
	}
	body := read(t, la.RequestBody)
	if len(la.Request) != 4 || la.Request[0] != la.EKM || la.Request[1] != la.Method || la.Request[2] != la.RequestURI || la.Request[3] != string(body) {
		t.Fatalf("the request lines are not the exporter value, the method, the target and the body file")
	}
	sum := sha256.Sum256([]byte(strings.Join(la.Request, "\n")))
	hash := link.AnswerRequest(ekm, la.Method, la.RequestURI, body)
	if hash != hex.EncodeToString(sum[:]) {
		t.Errorf("link.AnswerRequest is %s; want the SHA-256 of the request lines, %s", hash, hex.EncodeToString(sum[:]))
	}
	empty := sha256.Sum256(nil)
	if len(la.Lines) != 6 || la.Lines[0] != accesskey.LinkAnswerDomain || la.Lines[1] != "202" || la.Status != 202 ||
		la.Lines[2] != hash || la.Lines[3] != hex.EncodeToString(empty[:]) || la.BodyLength != 0 {
		t.Fatalf("lines %q are not a 202 with no body bound to the request", la.Lines)
	}
	a := accesskey.Answer{Link: true, Status: la.Status, RequestSignature: hash, Configuration: la.Lines[4], RunConfiguration: la.Lines[5]}
	if m := a.Message(); string(m) != strings.Join(la.Lines, "\n") || len(m) != la.Length {
		t.Errorf("the answer's message %q is not its lines", m)
	}
	g := knownanswers.GatewayKey()
	if got := g.SignAnswer(a); got != la.Signature {
		t.Errorf("the fixture gateway key signs %s; want %s", got, la.Signature)
	}
	if !g.PublicKey().VerifyAnswer(a, la.Signature) || !pinOf(g).VerifyAnswer(a, la.Signature) {
		t.Error("the signature does not verify under the fixture gateway key")
	}
	if a.Link = false; g.PublicKey().VerifyAnswer(a, la.Signature) {
		t.Error("the signature verifies as an answer of the server")
	}
}
