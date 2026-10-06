package accesskey

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/qoryai/runner/contracts"
)

// EnrolmentPath is where enrolment is served under the server's URL, beside discovery,
// because the access key has no id yet.
const EnrolmentPath = "/.well-known/qory-enrolment"

// CodePrefix starts every enrolment code.
const CodePrefix = "qec_"

// MaxAnswer is the most of an answer's body the client reads before it counts the
// answer as unsigned: a refusal body is at most 64 KiB.
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
// covers: "qec_", the 26 characters of the code in upper case with I and L read as 1,
// O as 0 and hyphens removed, then "." and the fingerprint of the server's key, and
// during a rotation of it a second "." and the next key's fingerprint, each as issued.
// So a person may type the code in either case and in groups. U, and every character
// outside Crockford's alphabet, is refused.
func NormaliseCode(code string) (string, error) {
	head, fingerprints, ok := strings.Cut(code, ".")
	prefix := len(CodePrefix)
	if !ok || len(head) < prefix || !strings.EqualFold(head[:prefix], CodePrefix) {
		return "", errors.New("an enrolment code is qec_, 26 characters, then a dot and a fingerprint")
	}
	var b strings.Builder
	b.WriteString(CodePrefix)
	n := 0
	for _, c := range head[prefix:] {
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
// its node or node pool with its kind, whether it is approved, its stored-secrets flag,
// and the server's keys.
type EnrolmentAnswer struct {
	Version       int    `json:"version"`
	AccessKeyID   string `json:"access_key_id"`
	NodeID        string `json:"node_id"`
	NodeKind      string `json:"node_kind"`
	Approved      bool   `json:"approved"`
	StoredSecrets bool   `json:"stored_secrets"`
	// ApiaryPublicKey are the server's keys as it lists them, current then next.
	ApiaryPublicKey Pin `json:"apiary_public_key"`
	// Pin are the keys of ApiaryPublicKey whose fingerprints the code carries: what
	// the machine pins, and only where it has no pin yet.
	Pin Pin `json:"-"`
}

// VerifyAnswer reads the server's answer to the request. A 201 is verified under the
// entry of its apiary_public_key whose fingerprint the code carries first, and its pin
// is the entries whose fingerprints the code carries. Any other answer is a
// [*Refusal]: a 401, unsigned, is unauthorized, the code used, expired or cancelled; a
// signed answer is the code its body contains, key_invalid or key_limit say; an answer
// that does not verify is answer_unsigned. A refusal verifies under the keys of pin the
// code's fingerprints select, the machine's pin when it has one: a machine without a
// pin reads such a refusal's status alone.
func (r *EnrolmentRequest) VerifyAnswer(a Answer, signature string, pin Pin) (*EnrolmentAnswer, error) {
	a.RequestSignature = r.Proof
	fingerprints := CodeFingerprints(r.Code)
	if len(fingerprints) == 0 {
		return nil, errors.New("the request's code is not an enrolment code")
	}
	unsigned := &Refusal{Code: CodeAnswerUnsigned, Status: a.Status, Detail: "enrolment"}
	switch a.Status {
	case http.StatusUnauthorized:
		return nil, &Refusal{Code: CodeUnauthorized, Status: a.Status, Detail: "enrolment: the code was used or has expired"}
	case http.StatusCreated:
	default:
		var selected Pin
		for _, k := range pin {
			if pub, err := ParsePublicKey(k.PublicKey); err == nil && slices.Contains(fingerprints, pub.Fingerprint()) {
				selected = append(selected, k)
			}
		}
		if len(selected) == 0 || len(a.Body) > MaxAnswer || !selected.VerifyAnswer(a, signature) {
			return nil, unsigned
		}
		if ref := ReadRefusal(a.Status, a.Body); ref != nil {
			ref.Detail = "enrolment"
			return nil, ref
		}
		return nil, fmt.Errorf("enrolment: status %d, signed, without a code", a.Status)
	}
	var ans EnrolmentAnswer
	if err := jsonv2.Unmarshal(a.Body, &ans, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, unsigned
	}
	var first *ServerKey
	for i, k := range ans.ApiaryPublicKey {
		if pub, err := ParsePublicKey(k.PublicKey); err == nil && pub.Fingerprint() == fingerprints[0] {
			first = &ans.ApiaryPublicKey[i]
		}
	}
	if first == nil || first.Alg != "ed25519" || !(Pin{*first}).VerifyAnswer(a, signature) {
		return nil, unsigned
	}
	if err := ans.check(); err != nil {
		return nil, fmt.Errorf("the enrolment answer: %w", err)
	}
	for _, k := range ans.ApiaryPublicKey {
		if pub, err := ParsePublicKey(k.PublicKey); err == nil && slices.Contains(fingerprints, pub.Fingerprint()) {
			ans.Pin = append(ans.Pin, k)
		}
	}
	if err := ans.Pin.Check(); err != nil {
		return nil, fmt.Errorf("the enrolment answer: %w", err)
	}
	return &ans, nil
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
	if want := map[string]string{"node": "nd_", "pool": "np_"}[a.NodeKind]; want == "" || !strings.HasPrefix(a.NodeID, want) {
		return fmt.Errorf("node_kind %q does not match the node id %s", a.NodeKind, a.NodeID)
	}
	if n := len(a.ApiaryPublicKey); n < 1 || n > 2 {
		return fmt.Errorf("apiary_public_key lists %d keys; one or two belong", n)
	}
	return a.ApiaryPublicKey.Check()
}

// Post sends the request to the server's enrolment endpoint and returns its verified
// answer, as [EnrolmentRequest.VerifyAnswer] reads it. serverURL is the server's
// origin, https or http to a loopback address; hc is the client, nil for one with a
// ten-second timeout, and in either case one that follows no redirect; userAgent is
// sent as User-Agent; pin is the machine's pin, empty when it has none.
func (r *EnrolmentRequest) Post(ctx context.Context, hc *http.Client, serverURL, userAgent string, pin Pin) (*EnrolmentAnswer, error) {
	if err := checkOrigin(serverURL); err != nil {
		return nil, err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	u := strings.TrimSuffix(serverURL, "/") + EnrolmentPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
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
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrolment %s: %w", u, err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, MaxAnswer+1))
	if err != nil {
		return nil, fmt.Errorf("enrolment %s: %w", u, err)
	}
	sig := ""
	if v := resp.Header.Values(HeaderSignature); len(v) == 1 {
		sig = v[0]
	}
	return r.VerifyAnswer(Answer{
		Status: resp.StatusCode, Body: answer,
		Configuration:    resp.Header.Get(HeaderConfiguration),
		RunConfiguration: resp.Header.Get(HeaderRunConfiguration),
	}, sig, pin)
}

// checkOrigin refuses a server URL that is not an origin, https or http to a loopback
// address, as the server document's url is.
func checkOrigin(s string) error {
	if looksSecret(s) {
		return errors.New("the server URL contains an access key secret")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("the server URL %s is not an origin, scheme and host only", shown(s))
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("the server URL %s is neither https nor http to a loopback address", shown(s))
}
