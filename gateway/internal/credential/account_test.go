package credential

import (
	"encoding/base64"
	"strings"
	"testing"
)

// fakeJWT is a token of three parts whose payload is payload, base64url without
// padding, with a fake header and signature: no key signed it.
func fakeJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(payload)) + ".fake-signature"
}

// accountPointer is the pointer of the account id in fakePayload: a member name with
// slashes, written with ~1.
const accountPointer = "/https:~1~1auth.model.example~1auth/account_id"

// fakePayload has the account id acct-fake-0001 under a member whose name has
// slashes, a list, and member names with ~ and /.
const fakePayload = `{"https://auth.model.example/auth":{"account_id":"acct-fake-0001","plan":"team"},"list":["a","b"],"a~b":{"c/d":"x"},"n":5}`

// TestAccountClaimReadsThePointer pins how the claim is read: the member names of the
// pointer, ~1 for / and ~0 for ~ inside them, an index of a list, and a payload with
// base64 padding.
func TestAccountClaimReadsThePointer(t *testing.T) {
	token := fakeJWT(fakePayload)
	for pointer, want := range map[string]string{
		accountPointer: "acct-fake-0001",
		"/list/1":      "b",
		"/a~0b/c~1d":   "x",
	} {
		got, err := AccountClaim([]byte(token), pointer)
		if err != nil || got != want {
			t.Errorf("AccountClaim at %s = %q, %v; want %q", pointer, got, err, want)
		}
	}
	parts := strings.Split(token, ".")
	padded := parts[0] + "." + base64.URLEncoding.EncodeToString([]byte(fakePayload)) + "." + parts[2]
	if got, err := AccountClaim([]byte(padded), accountPointer); err != nil || got != "acct-fake-0001" {
		t.Errorf("a padded payload: %q, %v", got, err)
	}
}

// TestAccountClaimRefusesWhatHasNoClaim pins the errors: a value of two parts, a
// payload over MaxClaimPayload bytes, one that is no base64url, no JSON object or has a
// member twice, a pointer that reaches nothing, a number or an object, a list index with
// a leading zero or past the end, and a claim that is empty or has a control
// character. No error contains the token or the claim.
func TestAccountClaimRefusesWhatHasNoClaim(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	over := `{"https://auth.model.example/auth":{"account_id":"acct-fake-0001"},"pad":"` + strings.Repeat("p", MaxClaimPayload) + `"}`
	for name, c := range map[string]struct {
		token, pointer, want string
	}{
		"two parts":           {enc([]byte(`{}`)) + "." + enc([]byte(fakePayload)), accountPointer, "it is not three parts separated by dots"},
		"over 8 KiB":          {fakeJWT(over), accountPointer, "its JWT payload is over 8192 bytes"},
		"no base64url":        {"e30.not*base64.sig", accountPointer, "its JWT payload is not base64url"},
		"no JSON":             {fakeJWT(`acct-fake-0001`), accountPointer, "not one JSON object"},
		"a list":              {fakeJWT(`["acct-fake-0001"]`), "/0", "not one JSON object"},
		"null":                {fakeJWT(`null`), accountPointer, "not one JSON object"},
		"a member twice":      {fakeJWT(`{"id":"acct-fake-0001","id":"acct-fake-0002"}`), "/id", "not one JSON object with each member name once"},
		"no such member":      {fakeJWT(fakePayload), "/https:~1~1auth.model.example~1auth/org_id", "has no string at account_claim"},
		"a number":            {fakeJWT(fakePayload), "/n", "has no string at account_claim"},
		"an object":           {fakeJWT(fakePayload), "/https:~1~1auth.model.example~1auth", "has no string at account_claim"},
		"through a string":    {fakeJWT(fakePayload), accountPointer + "/x", "has no string at account_claim"},
		"a leading zero":      {fakeJWT(fakePayload), "/list/01", "has no string at account_claim"},
		"past the list":       {fakeJWT(fakePayload), "/list/2", "has no string at account_claim"},
		"an empty claim":      {fakeJWT(`{"id":""}`), "/id", "is empty"},
		"a line feed":         {fakeJWT(`{"id":"acct-fake\n0001"}`), "/id", "has a control character"},
		"a trailing space":    {fakeJWT(`{"id":"acct-fake-0001 "}`), "/id", "starts or ends with a space"},
		"no pointer":          {fakeJWT(fakePayload), "id", "is no JSON pointer"},
		"an empty value":      {"", accountPointer, "it is not three parts"},
		"a missing signature": {fakeJWT(fakePayload) + ".extra", accountPointer, "it is not three parts"},
	} {
		got, err := AccountClaim([]byte(c.token), c.pointer)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %q, %v; want an error with %q", name, got, err, c.want)
			continue
		}
		if c.token != "" && strings.Contains(err.Error(), c.token) || strings.Contains(err.Error(), "acct-fake") {
			t.Errorf("%s: the error contains the token or the claim: %v", name, err)
		}
	}
	// The bound is on the decoded payload: one of exactly MaxClaimPayload bytes is read.
	head := `{"id":"acct-fake-0001","pad":"`
	exact := head + strings.Repeat("p", MaxClaimPayload-len(head)-2) + `"}`
	if got, err := AccountClaim([]byte(fakeJWT(exact)), "/id"); err != nil || got != "acct-fake-0001" {
		t.Errorf("a payload of %d bytes: %q, %v", len(exact), got, err)
	}
	if _, err := AccountClaim([]byte(fakeJWT(exact+" ")), "/id"); err == nil {
		t.Errorf("a payload of %d bytes was read", len(exact)+1)
	}
}

// TestAnAccountHeaderSplitsTheKeyGroup pins that the key group compares the account
// header, case ignored, and the account claim: a key with another claim, or none, is
// outside the start key's group.
func TestAnAccountHeaderSplitsTheKeyGroup(t *testing.T) {
	key := func(name, header, claim string) KeyEntry {
		return KeyEntry{Name: name, Format: "openai-responses", Endpoint: "https://chat.model.example/backend-api/codex", Scheme: "bearer", OAuth: true,
			AccountHeader: header, AccountClaim: claim}
	}
	entries := []KeyEntry{
		key("one", "account-id", accountPointer),
		key("two", "Account-Id", accountPointer),
		key("other-claim", "account-id", "/https:~1~1auth.model.example~1auth/org_id"),
		key("no-header", "", ""),
	}
	if got := KeyGroup(entries, "one"); strings.Join(got, ",") != "one,two" {
		t.Errorf("KeyGroup %v; want one and two", got)
	}
}

// TestAccountClaimReadsTheWayAlone pins that the payload's members off the pointer's
// way do not count: a number out of range, invalid UTF-8 and spaces around values
// elsewhere leave the claim readable. On the way, a member name twice is refused, and
// a claim that is not UTF-8 is no header value.
func TestAccountClaimReadsTheWayAlone(t *testing.T) {
	for name, payload := range map[string]string{
		"a number out of range":    `{"big":1e400,"https://auth.model.example/auth":{"account_id":"acct-fake-0001"}}`,
		"invalid UTF-8":            "{\"name\":\"bad-\xff-name\",\"https://auth.model.example/auth\":{\"account_id\":\"acct-fake-0001\"}}",
		"spaces":                   ` { "https://auth.model.example/auth" : { "account_id" : "acct-fake-0001" } } `,
		"a name twice off the way": `{"other":{"a":1,"a":2},"https://auth.model.example/auth":{"account_id":"acct-fake-0001"}}`,
	} {
		if got, err := AccountClaim([]byte(fakeJWT(payload)), accountPointer); err != nil || got != "acct-fake-0001" {
			t.Errorf("%s: %q, %v; want acct-fake-0001", name, got, err)
		}
	}
	list := `{"https://auth.model.example/auth":[{"x":1} , {"account_id":"acct-fake-0001"}]}`
	if got, err := AccountClaim([]byte(fakeJWT(list)), "/https:~1~1auth.model.example~1auth/1/account_id"); err != nil || got != "acct-fake-0001" {
		t.Errorf("a list on the way: %q, %v", got, err)
	}
	twice := `{"https://auth.model.example/auth":{"account_id":"acct-fake-0001","account_id":"acct-fake-0002"}}`
	if got, err := AccountClaim([]byte(fakeJWT(twice)), accountPointer); err == nil || !strings.Contains(err.Error(), "an object with a member name twice on the way to account_claim") {
		t.Errorf("a member twice on the way: %q, %v", got, err)
	}
	bad := "{\"https://auth.model.example/auth\":{\"account_id\":\"acct-\xff\"}}"
	if got, err := AccountClaim([]byte(fakeJWT(bad)), accountPointer); err == nil || !strings.Contains(err.Error(), "is not UTF-8") {
		t.Errorf("a claim that is not UTF-8: %q, %v", got, err)
	}
}
