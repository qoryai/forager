package accesskey_test

import (
	"crypto/sha256"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"strconv"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/contracts"
)

// fakeSecret is a made-up access key secret, and fakeRunKey a made-up run key.
const (
	fakeSecret = "qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	fakeRunKey = "qrk_eyJ2ZXJzaW9uIjoxfQ.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
)

// keyWith returns a public key in base64url that has sub from its ninth character on
// and that ParsePublicKey reads and Check passes when valid is true, or Check refuses
// when it is false.
func keyWith(t *testing.T, sub string, valid bool) string { return keyAt(t, 8, sub, valid) }

// keyAt returns a public key in base64url that has sub from index at on and that
// ParsePublicKey reads and Check passes when valid is true, or Check refuses when it
// is false: the first of base64url of SHA-256 of sub and a counter, with sub written
// over it, that does.
func keyAt(t *testing.T, at int, sub string, valid bool) string {
	t.Helper()
	for i := range 1000 {
		h := sha256.Sum256([]byte(sub + strconv.Itoa(i)))
		b := []byte(base64.RawURLEncoding.EncodeToString(h[:]))
		copy(b[at:], sub)
		if p, err := accesskey.ParsePublicKey(string(b)); err == nil && (p.Check() == nil) == valid {
			return string(b)
		}
	}
	t.Fatalf("no key has %s", sub)
	return ""
}

// entry is a pin's entry of an alg and a public key, as JSON.
func entry(alg, key string) string { return `{"alg":"` + alg + `","public_key":"` + key + `"}` }

// TestParsePinLeavesOutItsKeys pins that a pin whose key contains qak_ or QRK_ by chance
// is read, and that a secret beside such a key, in alg, another member or escaped, or in
// a public_key that is not one valid key, is still refused.
func TestParsePinLeavesOutItsKeys(t *testing.T) {
	qak, qrk := keyWith(t, "qak_", true), keyWith(t, "QRK_", true)
	escaped := "\\" + "u0071" + fakeSecret[1:]
	for _, k := range []string{qak, qrk} {
		if _, err := accesskey.ParsePin([]byte("[" + entry("ed25519", k) + "]")); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	for name, doc := range map[string]string{
		"a secret in alg":             `[` + entry(fakeSecret, qak) + `]`,
		"a secret in another member":  `[{"alg":"ed25519","public_key":"` + qak + `","x":"` + fakeSecret + `"}]`,
		"an escaped secret beside":    `[{"alg":"ed25519","public_key":"` + qak + `","x":"` + escaped + `"}]`,
		"an escaped secret in alg":    `[` + entry(escaped, qak) + `]`,
		"a key a character short":     `[` + entry("ed25519", qak[:42]) + `]`,
		"a key with padding":          `[` + entry("ed25519", qak+"=") + `]`,
		"a key after a space":         `[` + entry("ed25519", " "+qak) + `]`,
		"a key in a list":             `[{"alg":"ed25519","public_key":["` + qak + `"]}]`,
		"a key that is not a point":   `[` + entry("ed25519", keyWith(t, "qak_", false)) + `]`,
		"a second key with a secret":  `[` + entry("ed25519", qrk) + `,` + entry("ed25519", qak[:42]) + `]`,
		"the secret as the key":       `[` + entry("ed25519", fakeSecret) + `]`,
		"a secret in a member's name": `[{"alg":"ed25519","public_key":"` + qak + `","` + fakeSecret + `":1}]`,
	} {
		if _, err := accesskey.ParsePin([]byte(doc)); err != accesskey.ErrSecretInDocument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := accesskey.ParsePin([]byte(`[` + entry(fakeRunKey, qrk) + `]`)); err != accesskey.ErrRunKeyInDocument {
		t.Errorf("a run key in alg: %v", err)
	}
}

// scanPin checks a document as a reader does: SecretInPinDocument of its bytes, then of
// the document contracts.Decode decodes, by name's extension.
func scanPin(name, raw, member string) error {
	if err := accesskey.SecretInPinDocument(raw, member); err != nil {
		return err
	}
	doc, err := contracts.Decode(name, []byte(raw))
	if err != nil {
		return err
	}
	return accesskey.SecretInPinDocument(doc, member)
}

// TestSecretInPinDocument pins which keys of a pin are left out of the secret check:
// each entry's public_key that is one valid key, where the pin writes it, once. A
// secret in alg, in another member or field, in a member of the same name elsewhere,
// in the value of a member written twice, in a YAML comment, or escaped, is refused, and
// so is a public_key that is not one valid key.
func TestSecretInPinDocument(t *testing.T) {
	qak, qrk, mixed := keyWith(t, "qak_", true), keyWith(t, "QRK_", true), keyWith(t, "QaK_", true)
	other := "rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc"
	u := "\\" + "u0071"
	x := "\\" + "x71"
	server := func(pin string) string {
		return `{"version":1,"url":"https://qory.example","apiary_public_key":[` + pin + `]}`
	}
	const member = "apiary_public_key"
	for _, c := range []struct {
		name, file, doc, member string
		want                    error
	}{
		{"a key with qak_", "s.json", server(entry("ed25519", qak)), member, nil},
		{"a key with QRK_", "s.json", server(entry("ed25519", qrk)), member, nil},
		{"a key with QaK_", "s.json", server(entry("ed25519", mixed)), member, nil},
		{"a pin alone", "p.json", "[" + entry("ed25519", qak) + "]", "", nil},
		{"two keys", "s.json", server(entry("ed25519", qak) + "," + entry("ed25519", qrk)), member, nil},
		{"a valid key and one that is not", "s.json", server(entry("ed25519", qrk) + "," + entry("ed25519", qak[:42])), member, accesskey.ErrSecretInDocument},
		{"an escaped key that decodes to a valid key", "s.json", server(entry("ed25519", qak[:8]+u+qak[9:])), member, nil},
		{"an escaped key that is not a valid key", "s.json", server(entry("ed25519", qak[:8]+u+qak[9:42])), member, accesskey.ErrSecretInDocument},
		{"an escaped secret in another field", "s.json", `{"url":"` + u + fakeSecret[1:] + `","apiary_public_key":[` + entry("ed25519", qak) + `]}`, member, accesskey.ErrSecretInDocument},
		{"a secret in alg", "s.json", server(entry(fakeSecret, qak)), member, accesskey.ErrSecretInDocument},
		{"a secret in another member", "s.json", server(`{"alg":"ed25519","public_key":"` + qak + `","x":"` + fakeSecret + `"}`), member, accesskey.ErrSecretInDocument},
		{"a secret in a member's name", "s.json", server(`{"alg":"ed25519","public_key":"` + qak + `","` + fakeSecret + `":1}`), member, accesskey.ErrSecretInDocument},
		{"the same key in another field", "s.json", `{"url":"https://qory.example/` + qak + `","apiary_public_key":[` + entry("ed25519", qak) + `]}`, member, accesskey.ErrSecretInDocument},
		{"the pin twice, a secret first", "s.json", `{"apiary_public_key":[` + entry("ed25519", fakeSecret) + `],"apiary_public_key":[` + entry("ed25519", qak) + `]}`, member, accesskey.ErrSecretInDocument},
		{"the pin twice, a secret last", "s.json", `{"apiary_public_key":[` + entry("ed25519", qak) + `],"apiary_public_key":[` + entry("ed25519", fakeSecret) + `]}`, member, accesskey.ErrSecretInDocument},
		{"public_key twice, a secret first", "s.json", server(`{"alg":"ed25519","public_key":"` + fakeSecret + `","public_key":"` + qak + `"}`), member, accesskey.ErrSecretInDocument},
		{"public_key twice, a secret last", "s.json", server(`{"alg":"ed25519","public_key":"` + qak + `","public_key":"` + fakeSecret + `"}`), member, accesskey.ErrSecretInDocument},
		{"the pin's name nested deeper", "s.json", `{"x":{"apiary_public_key":[` + entry("ed25519", qak) + `]},"apiary_public_key":[` + entry("ed25519", other) + `]}`, member, accesskey.ErrSecretInDocument},
		{"public_key nested in an entry", "s.json", server(`{"alg":"ed25519","public_key":"` + other + `","x":{"public_key":"` + qak + `"}}`), member, accesskey.ErrSecretInDocument},
		{"a pin nested in a pin", "p.json", "[[" + entry("ed25519", qak) + "]]", "", accesskey.ErrSecretInDocument},
		{"a pin under another member", "s.json", `{"pin":[` + entry("ed25519", qak) + `]}`, member, accesskey.ErrSecretInDocument},
		{"a key after a space", "s.json", server(entry("ed25519", " "+qak)), member, accesskey.ErrSecretInDocument},
		{"a key with padding", "s.json", server(entry("ed25519", qak+"=")), member, accesskey.ErrSecretInDocument},
		{"a key in a list", "s.json", server(`{"alg":"ed25519","public_key":["` + qak + `"]}`), member, accesskey.ErrSecretInDocument},
		{"a key that is not a point", "s.json", server(entry("ed25519", keyWith(t, "qak_", false))), member, accesskey.ErrSecretInDocument},
		{"a run key beside a key with QRK_", "s.json", `{"url":"` + fakeRunKey + `","apiary_public_key":[` + entry("ed25519", qrk) + `]}`, member, accesskey.ErrRunKeyInDocument},
		{"a secret in alg beside a key with QRK_", "s.json", server(entry(fakeSecret, qrk)), member, accesskey.ErrSecretInDocument},
		{"YAML, flow", "s.yaml", "url: https://qory.example\napiary_public_key:\n  - {alg: ed25519, public_key: " + qak + "}\n", member, nil},
		{"YAML, block", "s.yaml", "apiary_public_key:\n  - alg: ed25519\n    public_key: " + qak + "\n  - alg: ed25519\n    public_key: " + qrk + "\n", member, nil},
		{"YAML, quoted", "s.yaml", "apiary_public_key:\n  - {alg: ed25519, public_key: '" + qak + "'}\n  - {alg: ed25519, public_key: \"" + qrk + "\"}\n", member, nil},
		{"YAML, an escape that decodes to a valid key", "s.yaml", "apiary_public_key:\n  - {alg: ed25519, public_key: \"" + qak[:8] + x + qak[9:] + "\"}\n", member, nil},
		{"YAML, a byte order mark, CRLF and a comment", "s.yaml", "\xef\xbb\xbf# \xc3\xa9 \xc3\xbc\r\nurl: https://qory.example\r\napiary_public_key:\r\n  - {alg: ed25519, public_key: " + qak + "} # pinned\r\n", member, nil},
		{"YAML, a secret in a comment", "s.yaml", "# " + fakeSecret + "\napiary_public_key:\n  - {alg: ed25519, public_key: " + qak + "}\n", member, accesskey.ErrSecretInDocument},
		{"YAML, the same key in a comment", "s.yaml", "apiary_public_key:\n  - {alg: ed25519, public_key: " + qak + "} # " + qak + "\n", member, accesskey.ErrSecretInDocument},
		{"YAML, an escaped secret in another field", "s.yaml", "url: \"" + x + fakeSecret[1:] + "\"\napiary_public_key:\n  - {alg: ed25519, public_key: " + qak + "}\n", member, accesskey.ErrSecretInDocument},
		{"YAML, a secret in alg", "s.yaml", "apiary_public_key:\n  - {alg: " + fakeSecret + ", public_key: " + qak + "}\n", member, accesskey.ErrSecretInDocument},
		{"YAML, public_key twice", "s.yaml", "apiary_public_key:\n  - {alg: ed25519, public_key: " + fakeSecret + ", public_key: " + qak + "}\n", member, accesskey.ErrSecretInDocument},
		{"YAML, a key with an anchor", "s.yaml", "apiary_public_key:\n  - {alg: ed25519, public_key: &k " + qak + "}\n", member, accesskey.ErrSecretInDocument},
		{"YAML, a key through an alias", "s.yaml", "k: &k " + other + "\napiary_public_key:\n  - {alg: ed25519, public_key: *k}\nx: " + qak + "\n", member, accesskey.ErrSecretInDocument},
		{"YAML, a key with a tag", "s.yaml", "apiary_public_key:\n  - {alg: ed25519, public_key: !!str " + qak + "}\n", member, accesskey.ErrSecretInDocument},
		{"YAML, an entry through a merge key", "s.yaml", "e: &e {alg: ed25519}\napiary_public_key:\n  - {<<: *e, public_key: " + qak + "}\n", member, accesskey.ErrSecretInDocument},
	} {
		if err := scanPin(c.file, c.doc, c.member); err != c.want {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// TestSecretInPinDocumentDecoded pins that a decoded document has the pin's valid keys
// left out and is not changed, and that a secret beside them is refused.
func TestSecretInPinDocumentDecoded(t *testing.T) {
	qak := keyWith(t, "qak_", true)
	var doc any
	if err := jsonv2.Unmarshal([]byte(`{"apiary_public_key":[`+entry("ed25519", qak)+`]}`), &doc); err != nil {
		t.Fatal(err)
	}
	if err := accesskey.SecretInPinDocument(doc, "apiary_public_key"); err != nil {
		t.Error(err)
	}
	if err := accesskey.SecretInPinDocument(doc, "pin"); err != accesskey.ErrSecretInDocument {
		t.Errorf("another member: %v", err)
	}
	if err := accesskey.SecretInDocument(doc); err != accesskey.ErrSecretInDocument {
		t.Errorf("the document was changed: %v", err)
	}
	doc.(map[string]any)["x"] = fakeSecret
	if err := accesskey.SecretInPinDocument(doc, "apiary_public_key"); err != accesskey.ErrSecretInDocument {
		t.Errorf("a secret beside: %v", err)
	}
}

// TestSecretInPinEntry pins the check of one entry: its alg always, its public key
// unless it is one valid key.
func TestSecretInPinEntry(t *testing.T) {
	qak, qrk, qecr := keyWith(t, "qak_", true), keyWith(t, "QRK_", true), keyWith(t, "qecr_", true)
	for _, c := range []struct {
		name, alg, key string
		want           error
	}{
		{"a key with qak_", "ed25519", qak, nil},
		{"a key with QRK_", "ed25519", qrk, nil},
		{"a key with qecr_", "ed25519", qecr, nil},
		{"a run code in alg", "QECR_F1XT0RE0000000000000000000.x", qak, accesskey.ErrRunCodeInDocument},
		{"a secret in alg", fakeSecret, qak, accesskey.ErrSecretInDocument},
		{"a run key in alg", fakeRunKey, qak, accesskey.ErrRunKeyInDocument},
		{"a key a character short", "ed25519", qak[:42], accesskey.ErrSecretInDocument},
		{"a key after a space", "ed25519", " " + qak, accesskey.ErrSecretInDocument},
		{"a key that is not a point", "ed25519", keyWith(t, "qak_", false), accesskey.ErrSecretInDocument},
		{"the secret as the key", "ed25519", fakeSecret, accesskey.ErrSecretInDocument},
	} {
		if err := accesskey.SecretInPinEntry(c.alg, c.key); err != c.want {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// TestAKeyThatStartsWithASecretPrefixIsChecked pins that a valid key that starts with
// qak_, qrk_ or qecr_, in any case, is not left out, since a secret cut to 43
// characters can read as a key, and that a valid key with qak_ further in still is.
func TestAKeyThatStartsWithASecretPrefixIsChecked(t *testing.T) {
	for prefix, want := range map[string]error{
		"qak_":  accesskey.ErrSecretInDocument,
		"QAK_":  accesskey.ErrSecretInDocument,
		"qrk_":  accesskey.ErrRunKeyInDocument,
		"QrK_":  accesskey.ErrRunKeyInDocument,
		"qecr_": accesskey.ErrRunCodeInDocument,
		"QECR_": accesskey.ErrRunCodeInDocument,
	} {
		k := keyAt(t, 0, prefix, true)
		if _, err := accesskey.ParsePin([]byte("[" + entry("ed25519", k) + "]")); err != want {
			t.Errorf("ParsePin, %s: %v", prefix, err)
		}
		if err := accesskey.SecretInPinEntry("ed25519", k); err != want {
			t.Errorf("SecretInPinEntry, %s: %v", prefix, err)
		}
		yaml := "apiary_public_key:\n  - {alg: ed25519, public_key: " + k + "}\n"
		if err := scanPin("s.yaml", yaml, "apiary_public_key"); err != want {
			t.Errorf("YAML, %s: %v", prefix, err)
		}
		var doc any
		if err := jsonv2.Unmarshal([]byte("["+entry("ed25519", k)+"]"), &doc); err != nil {
			t.Fatal(err)
		}
		if err := accesskey.SecretInPinDocument(doc, ""); err != want {
			t.Errorf("decoded, %s: %v", prefix, err)
		}
	}
	k := keyAt(t, 1, "qak_", true)
	if _, err := accesskey.ParsePin([]byte("[" + entry("ed25519", k) + "]")); err != nil {
		t.Errorf("qak_ from the second character: %v", err)
	}
	if err := accesskey.SecretInPinEntry("ed25519", k); err != nil {
		t.Errorf("SecretInPinEntry, qak_ from the second character: %v", err)
	}
}
