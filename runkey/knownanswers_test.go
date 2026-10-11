package runkey_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
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
