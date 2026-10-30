package accesskey

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/forager/contracts"
)

// EnrolmentPath is where enrolment is served under the server's URL, beside discovery,
// because the access key has no id yet.
const EnrolmentPath = "/.well-known/qory-enrolment"

// The prefixes of an enrolment code: one for each kind of key it enrols, and one for a
// run code, which enrols no key and redeems a run's run key. A prefix is read in any
// case and written in lower case in the normalised form.
const (
	// CodePrefixNode starts the enrolment code of a node's access key.
	CodePrefixNode = "qecn_"
	// CodePrefixPool starts the enrolment code of a node pool's access key.
	CodePrefixPool = "qecp_"
	// CodePrefixGateway starts the enrolment code of a gateway's access key.
	CodePrefixGateway = "qecg_"
	// CodePrefixAdapter starts the enrolment code of an adapter's access key.
	CodePrefixAdapter = "qeci_"
	// CodePrefixDiagnostics starts the enrolment code of a diagnostics access key.
	CodePrefixDiagnostics = "qecd_"
	// CodePrefixRun starts a run code: the code a provisioner puts in a machine's start
	// data in place of the run key. It enrols no access key: its 201 contains the
	// run's run key, [EnrolmentRequest.VerifyRunAnswer].
	CodePrefixRun = "qecr_"
)

// kindRun is the kind [CodeKind] returns for a run code.
const kindRun = "run"

// codeKinds maps each prefix of an enrolment code to the node_kind of the key the code
// enrols, and the run code's prefix to run.
var codeKinds = []struct{ prefix, kind string }{
	{CodePrefixNode, "node"},
	{CodePrefixPool, "pool"},
	{CodePrefixGateway, "gateway"},
	{CodePrefixAdapter, "adapter"},
	{CodePrefixDiagnostics, "diagnostics"},
	{CodePrefixRun, kindRun},
}

// errCodeShape is the error of a code without one of the prefixes or without a dot,
// the prefixes written as qec, a class of the letters of codeKinds, and _. The text
// contains none of the prefixes, so ShownError keeps it.
var errCodeShape = func() error {
	var letters strings.Builder
	for _, k := range codeKinds {
		letters.WriteString(k.prefix[len("qec") : len(k.prefix)-1])
	}
	return fmt.Errorf("use an enrolment code of the form qec[%s]_ and 26 characters, then a dot and a fingerprint",
		letters.String())
}()

// codePrefix returns the prefix of codeKinds that starts head in any case, and the
// kind it names.
func codePrefix(head string) (prefix, kind string, ok bool) {
	for _, k := range codeKinds {
		if len(head) >= len(k.prefix) && strings.EqualFold(head[:len(k.prefix)], k.prefix) {
			return k.prefix, k.kind, true
		}
	}
	return "", "", false
}

// MaxAnswer is the most of an answer's body the client reads before it counts the
// answer as unsigned, for an access key's code: an answer and a refusal body are at
// most 64 KiB. A 201 to a run code is at most [MaxRunAnswer].
const MaxAnswer = 64 << 10

// crockford maps a character a person may type in an enrolment code to the character
// of its normalised form: the digits and the upper-case letters of Crockford's base32,
// a lower-case letter as its upper case, I and L as 1, and O as 0. U and anything else
// map to nothing.
func crockford(c rune) (rune, bool) {
	if c >= 'a' && c <= 'z' {
		c -= 'a' - 'A'
	}
	switch {
	case c == 'I' || c == 'L':
		return '1', true
	case c == 'O':
		return '0', true
	case c == 'U':
		return 0, false
	case c >= '0' && c <= '9', c >= 'A' && c <= 'Z':
		return c, true
	}
	return 0, false
}

// NormaliseCode returns an enrolment code in the form the request sends and the proof
// covers: its prefix in lower case, [CodePrefixNode], [CodePrefixPool],
// [CodePrefixGateway], [CodePrefixAdapter], [CodePrefixDiagnostics] or [CodePrefixRun],
// the 26 characters of the code in upper case with I and L read as 1, O as 0 and
// hyphens removed, then "." and the fingerprint of the server's key, and during a
// rotation of it a second "." and the next key's fingerprint, each as issued. So a
// person may type the code in either case and in groups. Another prefix, U, and every
// character outside Crockford's alphabet, is refused.
func NormaliseCode(code string) (string, error) {
	head, fingerprints, ok := strings.Cut(code, ".")
	prefix, _, known := codePrefix(head)
	if !ok || !known {
		return "", errCodeShape
	}
	var b strings.Builder
	b.WriteString(prefix)
	n := 0
	for _, c := range head[len(prefix):] {
		if c == '-' {
			continue
		}
		m, ok := crockford(c)
		if !ok {
			return "", fmt.Errorf("the enrolment code contains %q, which is not a character of Crockford's base32", c)
		}
		b.WriteRune(m)
		n++
	}
	if n != 26 {
		return "", fmt.Errorf("the enrolment code has %d characters before its first dot where 26 belong", n)
	}
	parts := strings.Split(fingerprints, ".")
	if len(parts) > 2 {
		return "", errors.New("an enrolment code carries one or two fingerprints")
	}
	for _, f := range parts {
		if _, err := decode(f, 16); err != nil {
			return "", fmt.Errorf("the enrolment code's fingerprint %s: %w", shown(f), err)
		}
		b.WriteString("." + f)
	}
	return b.String(), nil
}

// CodeKind returns the node_kind of the key an enrolment code enrols, as its prefix
// names it: node, pool, gateway, adapter or diagnostics; for a run code,
// [CodePrefixRun], it returns run. A code [NormaliseCode] refuses is an error.
func CodeKind(code string) (string, error) {
	normal, err := NormaliseCode(code)
	if err != nil {
		return "", err
	}
	_, kind, _ := codePrefix(normal)
	return kind, nil
}

// CodeFingerprints returns the fingerprints of the server's keys an enrolment code
// carries, current then next, or none for a code that is not one.
func CodeFingerprints(code string) []string {
	normal, err := NormaliseCode(code)
	if err != nil {
		return nil
	}
	return strings.Split(normal, ".")[1:]
}

// CheckCode refuses an enrolment code from another server than the pin's: with a pin,
// one of the code's fingerprints must be one of its keys'. An empty pin accepts every
// code, since enrolment then writes the pin. qory checks this before it generates a
// key.
func (p Pin) CheckCode(code string) error {
	if len(p) == 0 {
		return nil
	}
	for _, f := range CodeFingerprints(code) {
		for _, k := range p.Keys() {
			if k.Fingerprint() == f {
				return nil
			}
		}
	}
	return errors.New("the enrolment code is for a server whose key this machine does not pin: the code is from another server, or the pin is out of date")
}

// EnrolmentRequest is the body of the enrolment POST: the new key's public key, a name
// for the access key, a timestamp, the code, and the proof of possession under the new
// key. It carries no access key id and no request signature; the code and the proof
// authenticate it.
type EnrolmentRequest struct {
	Version   int    `json:"version"`
	Code      string `json:"code"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
	Proof     string `json:"proof"`
}

// NewEnrolmentRequest builds the enrolment request of a new key: the code in its
// normalised form, the name, which [CheckName] must pass, the key's public key, the
// time in Unix seconds, and the proof.
func NewEnrolmentRequest(k *Key, code, name string, now time.Time) (*EnrolmentRequest, error) {
	normal, err := NormaliseCode(code)
	if err != nil {
		return nil, err
	}
	if err := CheckName(name); err != nil {
		return nil, fmt.Errorf("the access key's name: %w", err)
	}
	if now.Unix() < 0 {
		return nil, errors.New("the clock is before 1970")
	}
	r := &EnrolmentRequest{Version: 1, Code: normal, Name: name, PublicKey: k.PublicKey().String(), Timestamp: now.Unix()}
	r.Proof = encodeSignature(k.Sign(r.ProofMessage()))
	return r, nil
}

// ProofMessage returns the five lines the proof signs, joined by a line feed with none
// after the last: the domain line, the code, the public key as in the body, the name,
// and the timestamp in decimal.
func (r *EnrolmentRequest) ProofMessage() []byte {
	return []byte(EnrolDomain + "\n" + r.Code + "\n" + r.PublicKey + "\n" + r.Name + "\n" + strconv.FormatInt(r.Timestamp, 10))
}

// VerifyProof reports whether the request's proof verifies under its public key.
func (r *EnrolmentRequest) VerifyProof() bool {
	pub, err := ParsePublicKey(r.PublicKey)
	if err != nil {
		return false
	}
	sig, err := decode(r.Proof, 64)
	return err == nil && pub.Verify(r.ProofMessage(), sig)
}

// EnrolmentAnswer is the server's 201 to an enrolment: the access key's id, the id of
// its node, node pool, gateway, adapter or diagnostics key with its kind, node, pool,
// gateway, adapter or diagnostics, its stored-secrets flag and the server's keys. The
// key is active from the 201 on.
type EnrolmentAnswer struct {
	Version       int    `json:"version"`
	AccessKeyID   string `json:"access_key_id"`
	NodeID        string `json:"node_id"`
	NodeKind      string `json:"node_kind"`
	StoredSecrets bool   `json:"stored_secrets"`
	// ApiaryPublicKey are the server's keys as it lists them, current then next.
	ApiaryPublicKey Pin `json:"apiary_public_key"`
	// Pin are the keys of ApiaryPublicKey whose fingerprints the code carries: what
	// the machine pins, and only where it has no pin yet.
	Pin Pin `json:"-"`
}

// enrolmentRefusals are the codes of a signed refusal at enrolment, by its status.
var enrolmentRefusals = map[int][]string{
	http.StatusConflict:        {CodeKeyInvalid, CodeKeyLimit},
	http.StatusTooManyRequests: {CodeRateLimited},
}

// KindError is the error of a verified 201 that is not of the kind of its code's
// prefix, [CodeKind]: an access key's enrolment of another node_kind, a run's run key to
// an access key's code, or an access key's enrolment to a run code. The server
// accepted the code, so the code is used, and the client installs nothing of the
// answer. When the answer enrols an access key, that key is active.
type KindError struct {
	// Kind is the answer's node_kind, or run for a run's run key; AccessKeyID and
	// NodeID are an access key's answer's, and RunID a run's answer's.
	Kind, AccessKeyID, NodeID, RunID string
	// codeKind is the kind the code's prefix names.
	codeKind string
}

// Error returns the answer's kind and the kind of the code's prefix.
func (e *KindError) Error() string {
	switch {
	case e.codeKind == kindRun:
		return fmt.Sprintf("use another run code: the server's 201 to the run code enrols an access key of node_kind %q and contains no run key; the code is used", e.Kind)
	case e.Kind == kindRun:
		return fmt.Sprintf("use another enrolment code: the server's 201 to the code of node_kind %q contains a run's run key and no access key id; the code is used", e.codeKind)
	}
	return fmt.Sprintf("the enrolment answer: node_kind %q does not match the code's kind %q", e.Kind, e.codeKind)
}

// errRunCode is the error of an access key's enrolment method for a run code. Its
// text contains no qecr_, so ShownError keeps it.
var errRunCode = errors.New("redeem a run code with PostRunVia or VerifyRunAnswer: the request's code is a run code, and PostVia, Post and VerifyAnswer enrol an access key")

// forKey refuses a request whose code is a run code: an access key's enrolment method
// reads no run's answer.
func (r *EnrolmentRequest) forKey() error {
	if kind, err := CodeKind(r.Code); err == nil && kind == kindRun {
		return errRunCode
	}
	return nil
}

// forRun refuses a request whose code enrols an access key: a run code's method reads
// no access key's answer.
func (r *EnrolmentRequest) forRun() error {
	if kind, err := CodeKind(r.Code); err == nil && kind != kindRun {
		return fmt.Errorf("enrol an access key with PostVia, Post or VerifyAnswer: the request's code enrols an access key of node_kind %q, and PostRunVia and VerifyRunAnswer redeem a run code", kind)
	}
	return nil
}

// VerifyAnswer reads the server's answer to the request. A 201, a signed 409 and a
// signed 429 are verified alike, as enrolment answers, under EnrolAnswerDomain with the
// request's proof as the third line: each lists the server's keys in apiary_public_key,
// and the answer verifies under the entry whose fingerprint the code carries first, or
// it is answer_unsigned. A 409 the server sends unsigned, to a key the checks refuse or
// a proof that does not verify under it, is answer_unsigned too, and so is a 429 sent
// unsigned, per source address. A 201's pin is then the entries whose fingerprints the
// code carries. A verified 201 whose node_kind is not the kind the code's prefix names,
// [CodeKind], is a [*KindError], and so is a verified run's answer, [RunAnswer]. A verified 409 is a [*Refusal] with its code, key_invalid or key_limit,
// and a verified 429 one with rate_limited, too many attempts with the code; a verified
// refusal with another code is an error. A 401, unsigned, is unauthorized: the code was
// used, has expired or was cancelled. Any other answer is answer_unsigned. A caller acts
// on a refusal's code, and never on the status of an answer_unsigned: an answer that
// does not verify may come from anyone on the path. A request with a run code is an
// error, and nothing is read: [EnrolmentRequest.VerifyRunAnswer] reads its answer.
func (r *EnrolmentRequest) VerifyAnswer(a Answer, signature string) (*EnrolmentAnswer, error) {
	if err := r.forKey(); err != nil {
		return nil, err
	}
	verified, unsigned, err := r.created(&a, signature)
	if err != nil {
		return nil, err
	}
	var ans EnrolmentAnswer
	if err := jsonv2.Unmarshal(a.Body, &ans, jsonv2.RejectUnknownMembers(true)); err != nil || !verified(ans.ApiaryPublicKey) {
		var run RunAnswer
		if jsonv2.Unmarshal(a.Body, &run, jsonv2.RejectUnknownMembers(true)) == nil && verified(run.ApiaryPublicKey) {
			kind, _ := CodeKind(r.Code)
			return nil, &KindError{Kind: kindRun, RunID: run.RunID, codeKind: kind}
		}
		return nil, unsigned
	}
	if err := ans.check(); err != nil {
		return nil, fmt.Errorf("the enrolment answer: %w", err)
	}
	if kind, _ := CodeKind(r.Code); ans.NodeKind != kind {
		return nil, &KindError{Kind: ans.NodeKind, AccessKeyID: ans.AccessKeyID, NodeID: ans.NodeID, codeKind: kind}
	}
	if ans.Pin, err = r.pinOf(ans.ApiaryPublicKey); err != nil {
		return nil, fmt.Errorf("the enrolment answer: %w", err)
	}
	return &ans, nil
}

// created reads what every enrolment answer shares and returns, for a 201, verified,
// which reports whether the answer verifies under the listed key whose fingerprint is
// the code's first, and unsigned, the answer_unsigned of this answer. Every other
// status is an error: a 401 unauthorized, a signed 409 or 429 a [*Refusal] with its
// code, and the rest answer_unsigned.
func (r *EnrolmentRequest) created(a *Answer, signature string) (verified func(Pin) bool, unsigned *Refusal, err error) {
	// The answer is an enrolment answer whatever the caller passed: only a signature
	// under the enrolment answer's own domain line verifies.
	a.Enrolment, a.RequestSignature = true, r.Proof
	fingerprints := CodeFingerprints(r.Code)
	if len(fingerprints) == 0 {
		return nil, nil, errors.New("the request's code is not an enrolment code")
	}
	unsigned = &Refusal{Code: CodeAnswerUnsigned, Status: a.Status, Detail: "enrolment"}
	verified = func(keys Pin) bool {
		for _, k := range keys {
			if pub, err := ParsePublicKey(k.PublicKey); err == nil && k.Alg == "ed25519" && pub.Fingerprint() == fingerprints[0] {
				return (Pin{k}).VerifyAnswer(*a, signature)
			}
		}
		return false
	}
	switch a.Status {
	case http.StatusUnauthorized:
		return nil, nil, &Refusal{Code: CodeUnauthorized, Status: a.Status, Detail: "enrolment: the code was used, has expired or was cancelled"}
	case http.StatusConflict, http.StatusTooManyRequests:
		var ref struct {
			Error           string   `json:"error"`
			Names           []string `json:"names"`
			ApiaryPublicKey Pin      `json:"apiary_public_key"`
		}
		if len(a.Body) > MaxAnswer || jsonv2.Unmarshal(a.Body, &ref, jsonv2.RejectUnknownMembers(true)) != nil || !verified(ref.ApiaryPublicKey) {
			return nil, nil, unsigned
		}
		if !slices.Contains(enrolmentRefusals[a.Status], ref.Error) {
			return nil, nil, fmt.Errorf("enrolment: a signed %d with a code this package does not read",
				a.Status)
		}
		return nil, nil, &Refusal{Code: ref.Error, Status: a.Status, Names: ref.Names, Detail: "enrolment", From: FromApiary}
	case http.StatusCreated:
		return verified, unsigned, nil
	}
	return nil, nil, unsigned
}

// pinOf returns the keys of a verified 201's apiary_public_key whose fingerprints are in
// the code, after [Pin.Check].
func (r *EnrolmentRequest) pinOf(listed Pin) (Pin, error) {
	fingerprints := CodeFingerprints(r.Code)
	var pin Pin
	for _, k := range listed {
		if pub, err := ParsePublicKey(k.PublicKey); err == nil && slices.Contains(fingerprints, pub.Fingerprint()) {
			pin = append(pin, k)
		}
	}
	if err := pin.Check(); err != nil {
		return nil, err
	}
	return pin, nil
}

// check refuses an answer the schema refuses.
func (a *EnrolmentAnswer) check() error {
	if a.Version != 1 {
		return fmt.Errorf("version %d; 1 is the one this package reads", a.Version)
	}
	if err := CheckID(a.AccessKeyID); err != nil {
		return err
	}
	if err := CheckNodeID(a.NodeID); err != nil {
		return err
	}
	if want := map[string]string{"node": "nd_", "pool": "np_", "gateway": "ng_", "adapter": "na_", "diagnostics": "dg_"}[a.NodeKind]; want == "" || !strings.HasPrefix(a.NodeID, want) {
		return fmt.Errorf("node_kind %s does not match the node id %s", ShownName(a.NodeKind, true), a.NodeID)
	}
	if n := len(a.ApiaryPublicKey); n < 1 || n > 2 {
		return fmt.Errorf("apiary_public_key lists %d keys; one or two belong", n)
	}
	return a.ApiaryPublicKey.Check()
}

// Post sends the request to the server's enrolment endpoint and returns its verified
// answer, as [EnrolmentRequest.VerifyAnswer] reads it. serverURL is the server's
// origin, https or http to a loopback address; hc is the client, nil for one with a
// ten-second timeout, and in either case one that follows no redirect and keeps no
// cookie; userAgent is sent as User-Agent. A request with a run code is an error, and
// nothing is sent: [EnrolmentRequest.PostRunVia] redeems one.
func (r *EnrolmentRequest) Post(ctx context.Context, hc *http.Client, serverURL, userAgent string) (*EnrolmentAnswer, error) {
	if err := r.forKey(); err != nil {
		return nil, err
	}
	a, sig, err := r.direct(ctx, hc, serverURL, userAgent, MaxAnswer)
	if err != nil {
		return nil, err
	}
	return r.VerifyAnswer(a, sig)
}

// PostVia sends the request to the server's enrolment endpoint through the gateway at
// viaURL, the server document's via, and returns its verified answer as [Post] does:
// the request goes to viaURL's origin with the target /.well-known/qory-enrolment, and
// the gateway relays it to the server and passes the answer back byte for byte, so the
// answer verifies under the server's key as without the gateway. serverURL is the
// server's origin, which errors name; viaURL is the gateway's https origin. hc is the
// client, and is required: it carries the gateway's trust, so the caller builds it
// with the transport of the server package's Via.Transport, which uses no proxy of the
// environment, TLS 1.3 alone and the via's ca_file and pin. A nil hc is an error, and
// nothing is sent. The copy of hc used follows no redirect and keeps no cookie. A
// request with a run code is an error, and nothing is sent:
// [EnrolmentRequest.PostRunVia] redeems one.
func (r *EnrolmentRequest) PostVia(ctx context.Context, hc *http.Client, serverURL, viaURL, userAgent string) (*EnrolmentAnswer, error) {
	if err := r.forKey(); err != nil {
		return nil, err
	}
	a, sig, err := r.via(ctx, hc, serverURL, viaURL, userAgent, MaxAnswer)
	if err != nil {
		return nil, err
	}
	return r.VerifyAnswer(a, sig)
}

// direct checks serverURL and sends the request to the server's enrolment endpoint,
// reading at most limit bytes of the answer's body.
func (r *EnrolmentRequest) direct(ctx context.Context, hc *http.Client, serverURL, userAgent string, limit int) (Answer, string, error) {
	if err := checkOrigin(serverURL); err != nil {
		return Answer{}, "", err
	}
	return r.send(ctx, hc, serverURL, serverURL, userAgent, limit)
}

// via checks hc, serverURL and viaURL and sends the request to the server's enrolment
// endpoint through the gateway at viaURL, reading at most limit bytes of the answer's
// body.
func (r *EnrolmentRequest) via(ctx context.Context, hc *http.Client, serverURL, viaURL, userAgent string, limit int) (Answer, string, error) {
	if hc == nil {
		return Answer{}, "", errors.New("an enrolment through a gateway needs a client with the gateway's trust, built from the server package's Via.Transport")
	}
	if err := checkOrigin(serverURL); err != nil {
		return Answer{}, "", err
	}
	if err := checkOrigin(viaURL); err != nil || !strings.HasPrefix(viaURL, "https://") {
		return Answer{}, "", fmt.Errorf("the via URL %s is not an https origin, scheme and host only", shown(viaURL))
	}
	return r.send(ctx, hc, serverURL, viaURL, userAgent, limit)
}

// send sends the request to the enrolment endpoint under sendTo, the server's origin
// or a gateway's, and returns the answer unread, at most limit bytes of its body and
// one more so that a longer body is seen, and its signature header; errors name the
// endpoint under serverURL.
func (r *EnrolmentRequest) send(ctx context.Context, hc *http.Client, serverURL, sendTo, userAgent string, limit int) (Answer, string, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return Answer{}, "", err
	}
	u := strings.TrimSuffix(serverURL, "/") + EnrolmentPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(sendTo, "/")+EnrolmentPath, bytes.NewReader(body))
	if err != nil {
		return Answer{}, "", ShownError(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Qory-Contract-Version", strconv.Itoa(contracts.Revision))
	client := &http.Client{Timeout: 10 * time.Second}
	if hc != nil {
		cp := *hc
		client = &cp
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Jar = nil
	resp, err := client.Do(req)
	if err != nil {
		return Answer{}, "", fmt.Errorf("enrolment %s: %w", ShownValue(u, false), ShownError(err))
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return Answer{}, "", fmt.Errorf("enrolment %s: %w", ShownValue(u, false), ShownError(err))
	}
	sig := ""
	if v := resp.Header.Values(HeaderSignature); len(v) == 1 {
		sig = v[0]
	}
	return Answer{
		Status: resp.StatusCode, Body: answer,
		Configuration:    resp.Header.Get(HeaderConfiguration),
		RunConfiguration: resp.Header.Get(HeaderRunConfiguration),
	}, sig, nil
}

// checkOrigin refuses a server URL that is not an origin, https or http to a loopback
// address, as the server document's url is.
func checkOrigin(s string) error {
	if containsAccessKeySecret(s) {
		return errors.New("remove the access key secret from the server URL: the URL is a scheme, a host and an optional port")
	}
	if containsRunKey(s) {
		return errors.New("remove the run key from the server URL: the URL is a scheme, a host and an optional port")
	}
	if containsRunCode(s) {
		return errors.New("remove the run code from the server URL: the URL is a scheme, a host and an optional port")
	}
	if containsEnrolmentCode(s) {
		return errors.New("remove the enrolment code from the server URL: the URL is a scheme, a host and an optional port")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("the server URL %s is not an origin, scheme and host only", shown(s))
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		// The loopback hosts server.schema.json allows: localhost, 127.0.0.1 and [::1].
		if host := u.Hostname(); host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
	}
	return fmt.Errorf("the server URL %s is neither https nor http to a loopback address", shown(s))
}
