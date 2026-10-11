// Package knownanswers writes the known answers of a run through a gateway, the files
// of contracts/forager/v1/fixtures/known-answers that through-gateway.json lists: one
// run key, one registration through a gateway and its answer carrying the run key, one
// attach and its answer, and one outcome and its answer, each request signed under its
// fixture access key and each answer under the fixture signing key of the server.
//
// Everything is derived from the published fixture seeds of keys.json, and Ed25519
// signs deterministically, so the files are the same on every run. go generate
// ./runkey writes them, and package runkey's tests fail while the files differ from
// what Files returns.
package knownanswers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/server"
)

// The fixture values of the run.
const (
	RunID      = "0192f0c1-7d4e-7a2b-8c3d-4e5f6a7b8c9d"
	Workspace  = "ws_f1xt0re000000000"
	NodeID     = "np_f1xt0re000000000"
	Gateway    = "ng_f1xt0re000000000"
	GatewayURL = "https://gateway.example:8443"
	// AccessKeyID and InstanceID are the fixture access key's, which registers the run
	// and gives its outcome.
	AccessKeyID = "ak_f1xt0re000000000"
	InstanceID  = "i_gYKDhIWGh4iJiouMjY6PkA"
	// GatewayAccessKeyID is the fixture gateway key's id, which attaches the run; the
	// gateway's instance id is InstanceID.
	GatewayAccessKeyID = "ak_f1xt0re00000000g"
	// RunURL is the run endpoint of the fixture discovery.
	RunURL = "https://qory.example/v1/runs"
)

// The fixture times: the registration and the run key's issue, the end of the attach
// window, the attach and the outcome.
var (
	Issued      = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	AttachBy    = Issued.Add(600 * time.Second)
	AttachTime  = Issued.Add(5 * time.Second)
	OutcomeTime = Issued.Add(30 * time.Minute)
)

// counting returns the 32 bytes counting up from first: a fixture seed.
func counting(first int) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(first + i)
	}
	return b
}

// key returns the fixture key whose seed counts up from first.
func key(first int) *accesskey.Key {
	k, err := accesskey.NewKey(counting(first))
	if err != nil {
		panic(err)
	}
	return k
}

// AccessKey is the fixture access key, the seed being bytes 1 to 32.
func AccessKey() *accesskey.Key { return key(1) }

// SigningKey is the fixture signing key of the server, the seed being bytes 65 to 96.
func SigningKey() *accesskey.Key { return key(65) }

// GatewayKey is the fixture gateway key, the seed being bytes 97 to 128.
func GatewayKey() *accesskey.Key { return key(97) }

// Key is the fixture run key's payload, before it is signed.
func Key() runkey.Key {
	return runkey.Key{
		RunID: RunID, Workspace: Workspace, NodeID: NodeID, Gateway: Gateway, InstanceID: InstanceID,
		GatewayURL: GatewayURL, GatewayKeys: []accesskey.PublicKey{GatewayKey().PublicKey()},
		Issued: Issued, AttachBy: AttachBy,
	}
}

// Labels and About are what the registration carries, and the attach answer gives back.
var (
	Labels = map[string]string{"repository": "acme/shop"}
	About  = &server.About{Title: "Fix the failing build"}
)

// RunKeyVector is the run key's known answer.
type RunKeyVector struct {
	Note          string   `json:"note"`
	Payload       string   `json:"payload"`
	PayloadLength int      `json:"payload_length"`
	Lines         []string `json:"lines"`
	Length        int      `json:"length"`
	Signature     string   `json:"signature"`
	RunKey        string   `json:"run_key"`
}

// Request is a signed request's known answer: its six lines, the last the raw body of
// the file Body names, and its signature under the access key AccessKeyID names.
type Request struct {
	Note        string   `json:"note"`
	AccessKeyID string   `json:"access_key_id"`
	Body        string   `json:"body"`
	Lines       []string `json:"lines"`
	Length      int      `json:"length"`
	Signature   string   `json:"signature"`
}

// Answer is a signed answer's known answer: its six lines, the fourth the SHA-256 of
// the file Body names, and its signature under the fixture signing key.
type Answer struct {
	Note       string   `json:"note"`
	Body       string   `json:"body"`
	BodyLength int      `json:"body_length"`
	Lines      []string `json:"lines"`
	Length     int      `json:"length"`
	Signature  string   `json:"signature"`
}

// Vectors is through-gateway.json.
type Vectors struct {
	Note     string       `json:"note"`
	RunKey   RunKeyVector `json:"run_key"`
	Requests []Request    `json:"requests"`
	Answers  []Answer     `json:"answers"`
}

// Dir is where the files go, under contracts/forager/v1.
const Dir = "fixtures/known-answers"

// hexSHA256 is the lower-case hex SHA-256 of b.
func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Files returns the known answers by file name, under [Dir].
func Files() (map[string][]byte, error) {
	files := map[string][]byte{}
	access, signing, gateway := AccessKey(), SigningKey(), GatewayKey()
	discovery, err := fs.ReadFile(contracts.FS, Dir+"/discovery.json")
	if err != nil {
		return nil, err
	}
	configuration := "sha256=" + hexSHA256(bytes.TrimSpace(discovery))

	rk, err := Key().Sign(signing)
	if err != nil {
		return nil, err
	}
	rest := strings.TrimPrefix(rk, runkey.Prefix)
	payload, err := base64.RawURLEncoding.DecodeString(rest[:strings.LastIndexByte(rest, '.')])
	if err != nil {
		return nil, err
	}
	files["run-key-payload.json"] = payload
	sig := rk[strings.LastIndexByte(rk, '.')+1:]
	v := Vectors{
		Note: "The known answers of a run through a gateway: the run key, a registration through a gateway and its answer, an attach and its answer, and an outcome and its answer. go generate ./runkey writes them from the fixture keys of keys.json.",
		RunKey: RunKeyVector{
			Note:          "The run key of run-key-payload.json, signed under the fixture signing key of the server: the signed message is the domain line, a line feed, then the payload bytes; the run key is qrk_, the payload in base64url without padding, a dot, and the signature in base64url without padding.",
			Payload:       Dir + "/run-key-payload.json",
			PayloadLength: len(payload),
			Lines:         []string{runkey.Domain, string(payload)},
			Length:        len(runkey.Domain) + 1 + len(payload),
			Signature:     sig,
			RunKey:        rk,
		},
	}

	request := func(note, name string, k *accesskey.Key, id, target string, body []byte) (string, error) {
		files[name] = body
		r := accesskey.Request{AccessKeyID: id, InstanceID: InstanceID, Method: "POST", Target: target, Body: body}
		m, err := r.Message()
		if err != nil {
			return "", err
		}
		s, err := k.SignRequest(r)
		if err != nil {
			return "", err
		}
		v.Requests = append(v.Requests, Request{
			Note: note, AccessKeyID: id, Body: Dir + "/" + name,
			Lines: strings.SplitN(string(m), "\n", 6), Length: len(m), Signature: s,
		})
		return s, nil
	}
	answer := func(note, name string, a accesskey.Answer) {
		files[name] = a.Body
		m := a.Message()
		v.Answers = append(v.Answers, Answer{
			Note: note, Body: Dir + "/" + name, BodyLength: len(a.Body),
			Lines: strings.Split(string(m), "\n"), Length: len(m), Signature: signing.SignAnswer(a),
		})
	}

	// The registration through a gateway, and its answer with the run key.
	reg, err := server.GatewayRegistration{RunID: RunID, Labels: Labels, About: About, AttachSeconds: 600, Time: server.RegistrationTime(Issued)}.Body()
	if err != nil {
		return nil, err
	}
	regSig, err := request("A registration through a gateway, the gateway shape of run-registration.schema.json, a POST to the run endpoint signed under the fixture access key secret; the last line is the raw body.",
		"registration-gateway.json", access, AccessKeyID, "/v1/runs", reg)
	if err != nil {
		return nil, err
	}
	regAnswer, err := json.Marshal(server.RegistrationAnswer{Version: 1, RunID: RunID, RunKey: rk})
	if err != nil {
		return nil, err
	}
	answer("200 to the registration through a gateway above, signed under the fixture signing key: the run's id and its run key, with the X-Qory-Configuration of the fixture discovery and no run-configuration digest.",
		"registration-gateway-answer.json", accesskey.Answer{Status: 200, RequestSignature: regSig, Body: regAnswer, Configuration: configuration})

	// The attach, and its answer with the run configuration, the labels and about.
	att, err := server.Attach{RunKey: rk, IntervalSeconds: 30, Events: []string{"*"}, ForagerVersion: "v0.7.0-dev", ContractVersion: 1, Time: server.RegistrationTime(AttachTime)}.Body()
	if err != nil {
		return nil, err
	}
	attSig, err := request("The attach of the run, a POST to the run endpoint, the run's id and /attach, signed under the fixture gateway key secret as the gateway's access key; the last line is the raw body.",
		"attach.json", gateway, GatewayAccessKeyID, "/v1/runs/"+RunID+"/attach", att)
	if err != nil {
		return nil, err
	}
	attAnswer, err := json.Marshal(struct {
		Version        int               `json:"version"`
		SecurityPolicy json.RawMessage   `json:"security_policy"`
		Labels         map[string]string `json:"labels"`
		About          *server.About     `json:"about"`
	}{1, json.RawMessage(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`), Labels, About})
	if err != nil {
		return nil, err
	}
	answer("200 to the attach above, signed under the fixture signing key: the run configuration, with the registration's labels and about, no X-Qory-Configuration, and X-Qory-Run-Configuration sha256= and the hex SHA-256 of the body.",
		"attach-answer.json", accesskey.Answer{Status: 200, RequestSignature: attSig, Body: attAnswer, RunConfiguration: "sha256=" + hexSHA256(attAnswer)})

	// The outcome, and its answer.
	out, err := json.Marshal(struct {
		Version int    `json:"version"`
		State   string `json:"state"`
		Reason  string `json:"reason"`
		Time    string `json:"time"`
	}{1, "succeeded", "all_checks_passed", server.RegistrationTime(OutcomeTime)})
	if err != nil {
		return nil, err
	}
	outSig, err := request("The run's starter's outcome, a POST to the run endpoint, the run's id and /outcome, signed under the fixture access key secret, a key of the node that registered the run; the last line is the raw body.",
		"outcome.json", access, AccessKeyID, "/v1/runs/"+RunID+"/outcome", out)
	if err != nil {
		return nil, err
	}
	answer("200 to the outcome above, signed under the fixture signing key: {\"version\": 1}, with the X-Qory-Configuration of the fixture discovery and no run-configuration digest.",
		"outcome-answer.json", accesskey.Answer{Status: 200, RequestSignature: outSig, Body: []byte(`{"version":1}`), Configuration: configuration})

	doc, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	files["through-gateway.json"] = append(doc, '\n')
	return files, nil
}
