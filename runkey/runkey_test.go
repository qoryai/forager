package runkey_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/runkey"
	"github.com/qoryai/forager/runkey/internal/knownanswers"
)

// pinOf is a pin of the keys.
func pinOf(keys ...*accesskey.Key) accesskey.Pin {
	var p accesskey.Pin
	for _, k := range keys {
		p = append(p, accesskey.ServerKey{Alg: "ed25519", PublicKey: k.PublicKey().String()})
	}
	return p
}

// signed is a run key of the payload bytes p signed under k over the domain line
// domain, built by hand, so a test makes run keys Sign refuses to make.
func signed(k *accesskey.Key, domain string, p []byte) string {
	sig := k.Sign(append([]byte(domain+"\n"), p...))
	return runkey.Prefix + base64.RawURLEncoding.EncodeToString(p) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// payload is the fixture run key's payload, as a map a test changes.
func payload(t *testing.T) map[string]any {
	t.Helper()
	rk, err := knownanswers.Key().Sign(knownanswers.SigningKey())
	if err != nil {
		t.Fatal(err)
	}
	rest := strings.TrimPrefix(rk, runkey.Prefix)
	b, err := base64.RawURLEncoding.DecodeString(rest[:strings.LastIndexByte(rest, '.')])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSignVerifyAndParse pins the round trip: a run key Sign makes verifies under a pin
// that holds its signer, among other keys, and reads back every member, its signer the
// signing key's fingerprint whatever the Key held; Parse reads the same members and
// reports the run key unverified.
func TestSignVerifyAndParse(t *testing.T) {
	signing, next := knownanswers.SigningKey(), mustKey(t, 161)
	k := knownanswers.Key()
	k.Signer = "ignored"
	k.Issued = k.Issued.In(time.FixedZone("x", 3600))
	rk, err := k.Sign(signing)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rk, "qrk_") || len(rk) > runkey.MaxLength {
		t.Fatalf("run key of %d characters, %.8s…", len(rk), rk)
	}
	got, err := runkey.Verify(rk, pinOf(next, signing))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verified() {
		t.Error("a verified run key reports itself unverified")
	}
	want := knownanswers.Key()
	if got.RunID != want.RunID || got.Workspace != want.Workspace || got.NodeID != want.NodeID ||
		got.Gateway != want.Gateway || got.InstanceID != want.InstanceID || got.GatewayURL != want.GatewayURL ||
		!slices.Equal(got.GatewayKeys, want.GatewayKeys) || !got.Issued.Equal(want.Issued) || !got.AttachBy.Equal(want.AttachBy) {
		t.Errorf("verified %+v; want %+v", got, want)
	}
	if got.Signer != signing.Fingerprint() {
		t.Errorf("signer %s; want the signing key's fingerprint %s", got.Signer, signing.Fingerprint())
	}
	parsed, err := runkey.Parse(rk)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Verified() {
		t.Error("a parsed run key reports itself verified")
	}
	parsed.Signer, got.Signer = "", ""
	if parsed.RunID != got.RunID || parsed.GatewayURL != got.GatewayURL || !slices.Equal(parsed.GatewayKeys, got.GatewayKeys) {
		t.Errorf("parsed %+v; want %+v", parsed, got)
	}
	if (runkey.Key{}).Verified() {
		t.Error("the zero Key reports itself verified")
	}
}

func mustKey(t *testing.T, first int) *accesskey.Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(first + i)
	}
	k, err := accesskey.NewKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestTheUnverifiedParseIsNeverVerified pins that Parse grants nothing: a run key
// signed by a key nobody pins, or tampered with after signing, still parses when its
// payload passes the schema, and reports itself unverified, while Verify refuses it.
func TestTheUnverifiedParseIsNeverVerified(t *testing.T) {
	stranger := mustKey(t, 33)
	p := marshal(t, payload(t))
	for name, rk := range map[string]string{
		"signed by a stranger": signed(stranger, runkey.Domain, p),
		"another domain line":  signed(knownanswers.SigningKey(), accesskey.AnswerDomain, p),
	} {
		k, err := runkey.Parse(rk)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if k.Verified() {
			t.Errorf("%s: the parse reports itself verified", name)
		}
		if _, err := runkey.Verify(rk, pinOf(knownanswers.SigningKey())); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// TestVerifyRefuses pins every way Verify refuses a run key, each an error that matches
// ErrInvalid and names the part, never the run key's value: a payload changed after
// signing, a signature under another domain line, a signer the pin does not hold, a
// signer that names a pinned key while another key signed, an empty pin, and a
// signature of another length.
func TestVerifyRefuses(t *testing.T) {
	signing := knownanswers.SigningKey()
	pin := pinOf(signing)
	good, err := knownanswers.Key().Sign(signing)
	if err != nil {
		t.Fatal(err)
	}
	m := payload(t)
	m["gateway_url"] = "https://elsewhere.example"
	other := marshal(t, m)
	_, goodSig, _ := strings.Cut(strings.TrimPrefix(good, runkey.Prefix), ".")
	tampered := runkey.Prefix + base64.RawURLEncoding.EncodeToString(other) + "." + goodSig
	sig := []byte(goodSig)
	sig[3] ^= 1
	flipped := good[:len(good)-len(goodSig)] + string(sig)
	stranger := mustKey(t, 33)
	cases := map[string]struct {
		rk     string
		pin    accesskey.Pin
		reason string
	}{
		"a tampered payload":       {tampered, pin, "its signature does not verify"},
		"a changed signature":      {flipped, pin, "its signature does not verify"},
		"the wrong domain line":    {signed(signing, accesskey.RequestDomain, marshal(t, payload(t))), pin, "its signature does not verify"},
		"no domain line":           {signed(signing, "", marshal(t, payload(t))[0:]), pin, "its signature does not verify"},
		"an unknown fingerprint":   {good, pinOf(mustKey(t, 161)), "a server key this side does not pin"},
		"an empty pin":             {good, nil, "a server key this side does not pin"},
		"a stranger as the signer": {signed(stranger, runkey.Domain, marshal(t, payload(t))), pin, "its signature does not verify"},
		"a short signature":        {good[:len(good)-2], pin, "its signature is not 64 bytes"},
	}
	for name, c := range cases {
		_, err := runkey.Verify(c.rk, c.pin)
		if err == nil {
			t.Errorf("%s: verified", name)
			continue
		}
		if !errors.Is(err, runkey.ErrInvalid) || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: %v; want ErrInvalid saying %q", name, err, c.reason)
		}
		leaks(t, name, err, c.rk)
	}
}

// leaks fails the test when the error contains the run key or a part of its value.
func leaks(t *testing.T, name string, err error, rk string) {
	t.Helper()
	rest := strings.TrimPrefix(rk, runkey.Prefix)
	for _, part := range strings.Split(rest, ".") {
		if len(part) >= 8 && strings.Contains(err.Error(), part[:8]) {
			t.Errorf("%s: the error %q contains a part of the run key", name, err)
		}
	}
}

// TestParseRefuses pins the form a run key must have, for Parse and Verify alike: the
// prefix, at most 2048 characters, no white space, two parts of base64url without
// padding split on a dot, a signature of 64 bytes, and a payload run-key.schema.json
// accepts with each member name once and gateway keys the key checks pass.
func TestParseRefuses(t *testing.T) {
	signing := knownanswers.SigningKey()
	good, err := knownanswers.Key().Sign(signing)
	if err != nil {
		t.Fatal(err)
	}
	with := func(change func(map[string]any)) string {
		m := payload(t)
		change(m)
		return signed(signing, runkey.Domain, marshal(t, m))
	}
	p := marshal(t, payload(t))
	duplicate := append(append([]byte(nil), p[:len(p)-1]...), []byte(`,"run_id":"0192f0c1-7d4e-7a2b-8c3d-000000000000"}`)...)
	cases := map[string]struct{ rk, reason string }{
		"no prefix":            {strings.TrimPrefix(good, "qrk_"), "does not start with qrk_"},
		"an upper-case prefix": {"QRK_" + strings.TrimPrefix(good, "qrk_"), "does not start with qrk_"},
		"a trailing line feed": {good + "\n", "outside base64url"},
		"a space inside":       {good[:20] + " " + good[20:], "outside base64url"},
		"padding":              {good + "==", "outside base64url"},
		"no dot":               {strings.Replace(good, ".", "", 1), "no dot"},
		"an empty payload":     {"qrk_." + strings.SplitN(good, ".", 2)[1], "payload is not base64url"},
		"a standard alphabet":  {good[:10] + "+" + good[11:], "outside base64url"},
		"an unknown member":    {with(func(m map[string]any) { m["labels"] = map[string]string{"a": "b"} }), "run-key.schema.json"},
		"a missing attach_by":  {with(func(m map[string]any) { delete(m, "attach_by") }), "run-key.schema.json"},
		"version 2":            {with(func(m map[string]any) { m["version"] = 2 }), "run-key.schema.json"},
		"three gateway keys":   {with(func(m map[string]any) { m["gateway_public_key"] = []any{gk(t, 97), gk(t, 65), gk(t, 161)} }), "run-key.schema.json"},
		"a URL with a path":    {with(func(m map[string]any) { m["gateway_url"] = "https://gateway.example/x" }), "run-key.schema.json"},
		"a key of small order": {with(func(m map[string]any) {
			m["gateway_public_key"] = []any{map[string]string{"alg": "ed25519", "public_key": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
		}), "gateway_public_key/0"},
		"a member name twice":    {signed(signing, runkey.Domain, duplicate), "each member name once"},
		"a payload that is text": {signed(signing, runkey.Domain, []byte("not json")), "each member name once"},
	}
	for name, c := range cases {
		for fn, read := range map[string]func(string) (runkey.Key, error){
			"Parse":  runkey.Parse,
			"Verify": func(s string) (runkey.Key, error) { return runkey.Verify(s, pinOf(signing)) },
		} {
			_, err := read(c.rk)
			if err == nil {
				t.Errorf("%s: %s accepted it", name, fn)
				continue
			}
			if !errors.Is(err, runkey.ErrInvalid) || !strings.Contains(err.Error(), c.reason) {
				t.Errorf("%s: %s: %v; want ErrInvalid saying %q", name, fn, err, c.reason)
			}
			leaks(t, name, err, c.rk)
		}
	}
}

// TestTheGatewayURL pins the form of gateway_url, at most 300 characters: https://, a
// host of DNS labels joined by dots or an IPv6 address in brackets, and an optional port
// from 1 to 65535 with no leading zero, and nothing after them. Sign makes a run key of
// each accepted URL, which Verify reads back; Sign, Parse and Verify refuse each refused
// URL.
func TestTheGatewayURL(t *testing.T) {
	signing := knownanswers.SigningKey()
	pin := pinOf(signing)
	for name, u := range map[string]string{
		"a name":              "https://gateway.example",
		"a name with a port":  "https://gateway.example:8443",
		"the highest port":    "https://gateway.example:65535",
		"a dotted IPv4":       "https://192.0.2.10:8443",
		"an IPv6 with a port": "https://[::1]:8443",
		"a full IPv6":         "https://[2001:db8:0:0:0:0:0:1]",
		"a host with no dot":  "https://gateway",
		"300 characters":      "https://" + longHost(292),
	} {
		k := knownanswers.Key()
		k.GatewayURL = u
		rk, err := k.Sign(signing)
		if err != nil {
			t.Errorf("%s: Sign: %v", name, err)
			continue
		}
		got, err := runkey.Verify(rk, pin)
		if err != nil || got.GatewayURL != u {
			t.Errorf("%s: Verify: %q, %v; want %q", name, got.GatewayURL, err, u)
		}
	}
	for name, u := range map[string]string{
		"no host":               "https://:443",
		"a colon with no port":  "https://gateway.example:",
		"port 0":                "https://gateway.example:0",
		"port 99999":            "https://gateway.example:99999",
		"a leading zero":        "https://gateway.example:0443",
		"an underscore":         "https://gate_way.example",
		"a trailing dot":        "https://gateway.example.",
		"angle brackets":        "https://<>",
		"a control character":   "https://gateway.example\x01",
		"a trailing line feed":  "https://gateway.example\n",
		"user information":      "https://user@gateway.example",
		"a path":                "https://gateway.example:8443/qory-link",
		"a percent-encoding":    "https://gate%41way.example",
		"a label of 64":         "https://" + strings.Repeat("g", 64) + ".example",
		"text after an IPv6":    "https://[::1]0",
		"301 characters":        "https://" + longHost(293),
		"http":                  "http://gateway.example",
		"an IPv6 with no colon": "https://[gateway]",
	} {
		k := knownanswers.Key()
		k.GatewayURL = u
		if _, err := k.Sign(signing); !errors.Is(err, runkey.ErrInvalid) {
			t.Errorf("%s: Sign: %v; want ErrInvalid", name, err)
		}
		m := payload(t)
		m["gateway_url"] = u
		rk := signed(signing, runkey.Domain, marshal(t, m))
		for fn, read := range map[string]func(string) (runkey.Key, error){
			"Parse":  runkey.Parse,
			"Verify": func(s string) (runkey.Key, error) { return runkey.Verify(s, pin) },
		} {
			if _, err := read(rk); !errors.Is(err, runkey.ErrInvalid) || !strings.Contains(err.Error(), "/gateway_url") {
				t.Errorf("%s: %s: %v; want ErrInvalid at /gateway_url", name, fn, err)
			}
		}
	}
}

// longHost is a host name of n characters, n at least 1: labels of 62 g's and a last,
// shorter label, joined by dots.
func longHost(n int) string {
	var b strings.Builder
	for b.Len()+63 < n {
		b.WriteString(strings.Repeat("g", 62) + ".")
	}
	b.WriteString(strings.Repeat("g", n-b.Len()))
	return b.String()
}

// gk is the gateway key entry of the fixture key whose seed counts up from first.
func gk(t *testing.T, first int) map[string]string {
	return map[string]string{"alg": "ed25519", "public_key": mustKey(t, first).PublicKey().String()}
}

// TestTheLengthCap pins D-1: a run key of up to 2048 characters passes the length
// check, and a longer one is refused by Parse and Verify before anything else, though
// its signature verifies. Only a gateway_url over its 300 characters makes a run key
// that long, so run-key.schema.json refuses the run key of 2048 characters; the longest
// run key the schema accepts, with a gateway_url of 300 characters and two gateway keys,
// is under the cap, and Sign refuses a gateway_url of 1608 characters.
func TestTheLengthCap(t *testing.T) {
	signing := knownanswers.SigningKey()
	pin := pinOf(signing)
	of := func(n int) string {
		m := payload(t)
		m["gateway_url"] = "https://" + longHost(n)
		return signed(signing, runkey.Domain, marshal(t, m))
	}
	var longest, over string
	for n := 1; n < 2048 && (longest == "" || over == ""); n++ {
		switch rk := of(n); {
		case len(rk) <= runkey.MaxLength:
			longest = rk
		case over == "":
			over = rk
		}
	}
	if len(longest) < runkey.MaxLength-3 || len(over) > runkey.MaxLength+3 {
		t.Fatalf("lengths %d and %d do not straddle the cap", len(longest), len(over))
	}
	for fn, read := range map[string]func(string) (runkey.Key, error){
		"Parse":  runkey.Parse,
		"Verify": func(s string) (runkey.Key, error) { return runkey.Verify(s, pin) },
	} {
		if _, err := read(longest); err == nil || !strings.Contains(err.Error(), "/gateway_url (maxLength)") {
			t.Errorf("%s of a run key of %d characters: %v; want it past the length check and refused by the schema", fn, len(longest), err)
		}
		if _, err := read(over); err == nil || !strings.Contains(err.Error(), "longer than 2048") {
			t.Errorf("%s of a run key of %d characters: %v; want it refused as too long", fn, len(over), err)
		}
	}
	most := knownanswers.Key()
	most.GatewayURL = "https://" + longHost(292)
	most.GatewayKeys = []accesskey.PublicKey{mustKey(t, 65).PublicKey(), mustKey(t, 161).PublicKey()}
	rk, err := most.Sign(signing)
	if err != nil {
		t.Fatalf("Sign of the longest run key the schema accepts: %v", err)
	}
	if len(rk) > runkey.MaxLength {
		t.Errorf("the longest run key the schema accepts has %d characters, over the cap", len(rk))
	}
	if _, err := runkey.Verify(rk, pin); err != nil {
		t.Errorf("a run key of %d characters: %v", len(rk), err)
	}
	k := knownanswers.Key()
	k.GatewayURL = "https://" + strings.Repeat("g", 1600) + ".example"
	if _, err := k.Sign(signing); err == nil || !errors.Is(err, runkey.ErrInvalid) {
		t.Errorf("Sign of a gateway_url of %d characters: %v; want ErrInvalid", len(k.GatewayURL), err)
	}
}

// TestSignRefusesAPayloadTheSchemaRefuses pins that Sign makes no run key Parse would
// refuse: no gateway key, an id outside its form, and no signing key.
func TestSignRefusesAPayloadTheSchemaRefuses(t *testing.T) {
	for name, change := range map[string]func(*runkey.Key){
		"no gateway key":  func(k *runkey.Key) { k.GatewayKeys = nil },
		"a node id ng_":   func(k *runkey.Key) { k.NodeID = "ng_f1xt0re000000000" },
		"an http gateway": func(k *runkey.Key) { k.GatewayURL = "http://gateway.example" },
		"no run id":       func(k *runkey.Key) { k.RunID = "" },
	} {
		k := knownanswers.Key()
		change(&k)
		if _, err := k.Sign(knownanswers.SigningKey()); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	if _, err := knownanswers.Key().Sign(nil); err == nil {
		t.Error("signed under no key")
	}
}

// TestARunKeyIsASecretToAccesskey pins that package accesskey, which cannot import this
// one, treats Prefix as it treats an access key secret's.
func TestARunKeyIsASecretToAccesskey(t *testing.T) {
	if !accesskey.ContainsSecret(runkey.Prefix) || accesskey.SecretInDocument(runkey.Prefix) != accesskey.ErrRunKeyInDocument {
		t.Errorf("accesskey does not treat %s as a run key", runkey.Prefix)
	}
}
