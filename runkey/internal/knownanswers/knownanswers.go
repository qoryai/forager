// Package knownanswers writes the known answers of a run through a gateway, the files
// of contracts/forager/v1/fixtures/known-answers that through-gateway.json lists: one
// run key, one registration through a gateway and its answer with the run key, one
// redemption of a run code and its answer with the run key and the run's documents,
// that redemption as the gateway's relay signs it,
// one attach and its answer, and one outcome and its answer, each request signed under
// its fixture access key and each answer under the fixture signing key of the server;
// and, for a fixed exporter value, one binding of a connection to the gateway and one answer
// of the gateway on its link, each signed under the fixture gateway key.
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
	"github.com/qoryai/forager/link"
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

// BindingEKM is the fixed exporter value of the binding's and the link answer's known
// answers, the 32 bytes counting up from 129, in place of the value a TLS connection
// derives.
func BindingEKM() []byte { return counting(129) }

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

// RunCode is the fixture run code: qecr_, the fixture characters and the fingerprint of
// the fixture signing key of the server.
func RunCode() string {
	return "qecr_F1XT0RE0000000000000000000." + SigningKey().Fingerprint()
}

// RunDocuments is the run's documents of the run code's answer: a JSON object in
// neutral example data. Forager checks that it is an object and reads none of its
// members.
var RunDocuments = json.RawMessage(`{"example":"f1xt0re"}`)

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

// RunEnrolment is the known answer of a run code's redemption: the request's file, the
// five lines its proof signs and the proof under the fixture access key, then the
// 201's file, its six lines and its signature under the fixture signing key; and Relay,
// the request as the gateway's relay passes it on, signed under the fixture gateway key.
type RunEnrolment struct {
	Note        string   `json:"note"`
	Request     string   `json:"request"`
	ProofLines  []string `json:"proof_lines"`
	ProofLength int      `json:"proof_length"`
	Proof       string   `json:"proof"`
	Answer      string   `json:"answer"`
	BodyLength  int      `json:"body_length"`
	Lines       []string `json:"lines"`
	Length      int      `json:"length"`
	Signature   string   `json:"signature"`
	Relay       Request  `json:"relay"`
}

// Binding is the binding's known answer: the exporter value in lower-case hex, the
// exporter's label, the fixture gateway key's fingerprint, the three lines the gateway
// signs, its signature under that key and the line it answers QORY-BIND with, its
// newline included.
type Binding struct {
	Note        string   `json:"note"`
	EKM         string   `json:"ekm"`
	Label       string   `json:"label"`
	Fingerprint string   `json:"fingerprint"`
	Lines       []string `json:"lines"`
	Length      int      `json:"length"`
	Signature   string   `json:"signature"`
	BoundLine   string   `json:"bound_line"`
}

// LinkAnswer is the known answer of a separate gateway's answer on its link: the
// exporter value in lower-case hex, the request's method, its target as sent and the
// file of its body; the four lines whose SHA-256 is the answer's third line, the last
// the raw body; the answer's status and body length, its six lines and its signature
// under the fixture gateway key.
type LinkAnswer struct {
	Note        string   `json:"note"`
	EKM         string   `json:"ekm"`
	Method      string   `json:"method"`
	RequestURI  string   `json:"request_uri"`
	RequestBody string   `json:"request_body"`
	Request     []string `json:"request"`
	Status      int      `json:"status"`
	BodyLength  int      `json:"body_length"`
	Lines       []string `json:"lines"`
	Length      int      `json:"length"`
	Signature   string   `json:"signature"`
}

// Vectors is through-gateway.json.
type Vectors struct {
	Note         string       `json:"note"`
	RunKey       RunKeyVector `json:"run_key"`
	Requests     []Request    `json:"requests"`
	Answers      []Answer     `json:"answers"`
	RunEnrolment RunEnrolment `json:"run_enrolment"`
	Binding      Binding      `json:"binding"`
	LinkAnswer   LinkAnswer   `json:"link_answer"`
}

// LinkBatch is the file of the link answer's request body, a batch of the run, and
// LinkDiscovery the discovery of the gateway's one address whose digest the answer
// carries; both are fixtures of the link, under contracts/forager/v1.
const (
	LinkBatch     = "fixtures/link/link-batch.json"
	LinkDiscovery = "fixtures/link/link-discovery-separate.json"
)

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
	// The discovery of the fixture gateway key, whose digest the gateway's answers carry.
	gatewayDiscovery, err := fs.ReadFile(contracts.FS, Dir+"/discovery-gateway.json")
	if err != nil {
		return nil, err
	}
	gatewayConfiguration := "sha256=" + hexSHA256(bytes.TrimSpace(gatewayDiscovery))

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
		Note: "The known answers of a run through a gateway: the run key, a registration through a gateway and its answer, a run code's redemption and its answer, that redemption as the gateway's relay signs it, an attach and its answer, an outcome and its answer, a binding of a connection to the gateway, and an answer of the gateway on its link. go generate ./runkey writes them from the fixture keys of keys.json.",
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
	// The answer's own struct: a server.RegistrationAnswer writes its run key redacted.
	regAnswer, err := json.Marshal(struct {
		Version int    `json:"version"`
		RunID   string `json:"run_id"`
		RunKey  string `json:"run_key"`
	}{1, RunID, rk})
	if err != nil {
		return nil, err
	}
	answer("200 to the registration through a gateway above, signed under the fixture signing key: the run's id and its run key, with the X-Qory-Configuration of the fixture discovery and no run-configuration digest.",
		"registration-gateway-answer.json", accesskey.Answer{Status: 200, RequestSignature: regSig, Body: regAnswer, Configuration: configuration})

	// The run code's redemption, and its answer with the run key.
	er, err := accesskey.NewEnrolmentRequest(access, RunCode(), "run-01", Issued)
	if err != nil {
		return nil, err
	}
	erBody, err := json.MarshalIndent(er, "", "  ")
	if err != nil {
		return nil, err
	}
	erFile := append(erBody, '\n')
	files["enrolment-run-request.json"] = erFile
	// The relay signs the request under the gateway's access key, over the body byte for
	// byte as it came: the file's bytes, its white space and trailing line feed included.
	relayed := accesskey.Request{AccessKeyID: GatewayAccessKeyID, InstanceID: InstanceID, Method: "POST", Target: accesskey.EnrolmentPath, Body: erFile}
	rm, err := relayed.Message()
	if err != nil {
		return nil, err
	}
	rs, err := gateway.SignRequest(relayed)
	if err != nil {
		return nil, err
	}
	runAnswer, err := json.Marshal(struct {
		Version         int                   `json:"version"`
		RunID           string                `json:"run_id"`
		RunKey          string                `json:"run_key"`
		ApiaryPublicKey []accesskey.ServerKey `json:"apiary_public_key"`
		Documents       json.RawMessage       `json:"documents"`
	}{1, RunID, rk, []accesskey.ServerKey{{Alg: "ed25519", PublicKey: signing.PublicKey().String()}}, RunDocuments})
	if err != nil {
		return nil, err
	}
	files["enrolment-run-answer.json"] = runAnswer
	ea := accesskey.Answer{Enrolment: true, Status: 201, RequestSignature: er.Proof, Body: runAnswer}
	pm, am := er.ProofMessage(), ea.Message()
	v.RunEnrolment = RunEnrolment{
		Note:        "The redemption of a run code: the request of enrolment-run-request.json, its proof under the fixture access key secret over the five lines qory-enrol-ed25519-v1, the code, the public key, the name and the timestamp; then the 201 of enrolment-run-answer.json, the run's id, the run key of run-key-payload.json and the run's documents, signed under the fixture signing key with the domain line qory-enrol-answer-ed25519-v1 and the request's proof as line 3.",
		Request:     Dir + "/enrolment-run-request.json",
		ProofLines:  strings.Split(string(pm), "\n"),
		ProofLength: len(pm),
		Proof:       er.Proof,
		Answer:      Dir + "/enrolment-run-answer.json",
		BodyLength:  len(runAnswer),
		Lines:       strings.Split(string(am), "\n"),
		Length:      len(am),
		Signature:   signing.SignAnswer(ea),
		Relay: Request{
			Note:        "The request of enrolment-run-request.json as the gateway's relay passes it to the server: a POST to /.well-known/qory-enrolment, signed under the fixture gateway key secret as the gateway's access key with the gateway's instance id; the last line is the raw body, the file's bytes, its white space and its trailing line feed included. The relay deletes every X-Qory-Access-Key-Id, X-Qory-Instance-Id, X-Qory-Instance-Name, X-Qory-Signature-Ed25519 and X-Qory-Timestamp the machine sent, and sends access_key_id as X-Qory-Access-Key-Id, line 3 as X-Qory-Instance-Id and signature as X-Qory-Signature-Ed25519.",
			AccessKeyID: GatewayAccessKeyID,
			Body:        Dir + "/enrolment-run-request.json",
			Lines:       strings.SplitN(string(rm), "\n", 6),
			Length:      len(rm),
			Signature:   rs,
		},
	}

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
	// The run's run configuration, as a reload of the run answers it, whose digest the
	// attach's answer carries; the answer is that document with the registration's labels
	// and about.
	policy := json.RawMessage(`{"version":1,"egress":{"mode":"enforce","allow":["api.example"]}}`)
	rc, err := json.Marshal(struct {
		Version        int             `json:"version"`
		SecurityPolicy json.RawMessage `json:"security_policy"`
	}{1, policy})
	if err != nil {
		return nil, err
	}
	files["attach-run-configuration.json"] = rc
	attAnswer, err := json.Marshal(struct {
		Version        int               `json:"version"`
		SecurityPolicy json.RawMessage   `json:"security_policy"`
		Labels         map[string]string `json:"labels"`
		About          *server.About     `json:"about"`
	}{1, policy, Labels, About})
	if err != nil {
		return nil, err
	}
	answer("200 to the attach above, signed under the fixture signing key: the run configuration, with the registration's labels and about; X-Qory-Configuration sha256= and the hex SHA-256 of discovery-gateway.json, the fixture gateway key's discovery, and X-Qory-Run-Configuration, which ETag carries quoted, sha256= and the hex SHA-256 of attach-run-configuration.json, the run configuration without the labels and about, as a reload of the run answers it.",
		"attach-answer.json", accesskey.Answer{Status: 200, RequestSignature: attSig, Body: attAnswer, Configuration: gatewayConfiguration, RunConfiguration: "sha256=" + hexSHA256(rc)})

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

	// The binding, for the fixed exporter value: what the gateway signs and the line it
	// answers QORY-BIND with.
	ekm := BindingEKM()
	fp := gateway.Fingerprint()
	bm := link.BindingMessage(ekm, fp)
	bsig := base64.RawURLEncoding.EncodeToString(gateway.Sign(bm))
	v.Binding = Binding{
		Note:        "The binding of a connection to the gateway, for the fixed exporter value ekm, the 32 bytes counting up from 129, in place of the one a connection derives with the label: the gateway signs the three lines under the fixture gateway key, and answers QORY-BIND with bound_line, QORY-BOUND, a space, the fingerprint, a space, the signature in base64url without padding, and a newline.",
		EKM:         hex.EncodeToString(ekm),
		Label:       link.BindingLabel,
		Fingerprint: fp,
		Lines:       strings.Split(string(bm), "\n"),
		Length:      len(bm),
		Signature:   bsig,
		BoundLine:   link.BoundLine(fp, bsig),
	}

	// An answer of the gateway on its link, on that connection: a 202 to a batch of the
	// run, with no body.
	batch, err := fs.ReadFile(contracts.FS, LinkBatch)
	if err != nil {
		return nil, err
	}
	linkDiscovery, err := fs.ReadFile(contracts.FS, LinkDiscovery)
	if err != nil {
		return nil, err
	}
	const target = "/qory-link/events"
	la := accesskey.Answer{
		Link: true, Status: 202, RequestSignature: link.AnswerRequest(ekm, "POST", target, batch),
		Configuration: "sha256=" + hexSHA256(bytes.TrimSpace(linkDiscovery)), RunConfiguration: "sha256=" + hexSHA256(rc),
	}
	lm := la.Message()
	v.LinkAnswer = LinkAnswer{
		Note:        "202 to a batch of the run on the gateway's link, on the connection of the binding above, signed under the fixture gateway key with the domain line qory-link-answer-ed25519-v1: the third line is the lower-case hex SHA-256 of request, the exporter value in lower-case hex, the method, the request target as sent and the raw body of request_body, joined by line feeds; the answer has no body; X-Qory-Configuration is sha256= and the hex SHA-256 of link-discovery-separate.json, a discovery of the gateway's one address, and X-Qory-Run-Configuration sha256= and the hex SHA-256 of attach-run-configuration.json, the run's reload answer.",
		EKM:         hex.EncodeToString(ekm),
		Method:      "POST",
		RequestURI:  target,
		RequestBody: LinkBatch,
		Request:     []string{hex.EncodeToString(ekm), "POST", target, string(batch)},
		Status:      la.Status,
		BodyLength:  len(la.Body),
		Lines:       strings.Split(string(lm), "\n"),
		Length:      len(lm),
		Signature:   gateway.SignAnswer(la),
	}

	doc, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	files["through-gateway.json"] = append(doc, '\n')
	return files, nil
}
