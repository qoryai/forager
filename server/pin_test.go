package server_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/server"
)

// keyWith returns a public key in base64url that has sub from its ninth character on
// and that ParsePublicKey reads and Check passes: the first of base64url of SHA-256 of
// sub and a counter, with sub written over it, that does.
func keyWith(t *testing.T, sub string) string {
	t.Helper()
	for i := range 1000 {
		h := sha256.Sum256([]byte(sub + strconv.Itoa(i)))
		b := []byte(base64.RawURLEncoding.EncodeToString(h[:]))
		copy(b[8:], sub)
		if p, err := accesskey.ParsePublicKey(string(b)); err == nil && p.Check() == nil {
			return string(b)
		}
	}
	t.Fatalf("no key has %s", sub)
	return ""
}

// TestAPinKeyWithASecretPrefixReads pins that a server document whose pin lists a key
// that contains qak_ or QRK_ by chance reads, as JSON and as YAML, and that the same
// document with a secret in the entry's alg or another member, an escaped secret in
// another field, a secret in a comment, or a public_key that is not one valid key, is
// still refused.
func TestAPinKeyWithASecretPrefixReads(t *testing.T) {
	const secret = "qak_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	qak, qrk := keyWith(t, "qak_"), keyWith(t, "QRK_")
	jsonDoc := func(id, entry string) string {
		return `{"version":1,"url":"https://qory.example","access_key_id":"` + id + `","apiary_public_key":[` + entry + `]}`
	}
	entry := func(alg, key string) string { return `{"alg":"` + alg + `","public_key":"` + key + `"}` }
	yamlDoc := func(id, entry string) string {
		return "version: 1\nurl: https://qory.example\naccess_key_id: " + id + "\napiary_public_key:\n  - " + entry + "\n"
	}
	yamlEntry := func(alg, key string) string { return "{alg: " + alg + ", public_key: " + key + "}" }
	for _, k := range []string{qak, qrk} {
		for name, doc := range map[string]string{
			"server.json": jsonDoc(accessKeyID, entry("ed25519", k)),
			"server.yaml": yamlDoc(accessKeyID, yamlEntry("ed25519", k)),
		} {
			c, err := server.Read(name, []byte(doc))
			if err != nil || c.ApiaryPublicKey[0].PublicKey != k {
				t.Errorf("%s, %s: %v", name, k, err)
			}
		}
	}
	escaped := "\\" + "u0071" + secret[1:]
	for name, doc := range map[string]string{
		"a secret in alg":                 jsonDoc(accessKeyID, entry(secret, qak)),
		"a secret in another member":      jsonDoc(accessKeyID, `{"alg":"ed25519","public_key":"`+qak+`","x":"`+secret+`"}`),
		"an escaped secret in a field":    jsonDoc(escaped, entry("ed25519", qak)),
		"a key that is not a valid key":   jsonDoc(accessKeyID, entry("ed25519", qak[:42])),
		"a second key that is not valid":  jsonDoc(accessKeyID, entry("ed25519", qrk)+","+entry("ed25519", "x"+qak)),
		"YAML, a secret in alg":           yamlDoc(accessKeyID, yamlEntry(secret, qak)),
		"YAML, a secret in a comment":     yamlDoc(accessKeyID, yamlEntry("ed25519", qak)+" # "+secret),
		"YAML, an escaped secret":         yamlDoc(`"`+"\\"+"x71"+secret[1:]+`"`, yamlEntry("ed25519", qak)),
		"YAML, a key that is not a valid": yamlDoc(accessKeyID, yamlEntry("ed25519", qak+"=")),
	} {
		file := "server.json"
		if name[:4] == "YAML" {
			file = "server.yaml"
		}
		if _, err := server.Read(file, []byte(doc)); !errors.Is(err, accesskey.ErrSecretInDocument) || errors.Is(err, accesskey.ErrRunKeyInDocument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	const rk = "qrk_eyJ2ZXJzaW9uIjoxfQ.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	if _, err := server.Read("server.json", []byte(jsonDoc(accessKeyID, entry(rk, qrk)))); !errors.Is(err, accesskey.ErrRunKeyInDocument) {
		t.Errorf("a run key in alg: %v", err)
	}
}
