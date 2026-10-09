package runcredential

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/refusal"
)

// now is the clock of the claim tests.
var now = time.Unix(1700000000, 0)

// validClaims are the neutral example claims, valid at now.
func validClaims() map[string]any {
	return map[string]any{
		"iss":       exampleIssuer,
		"aud":       exampleAudience,
		"sub":       "rk-0001",
		"iat":       float64(now.Unix() - 60),
		"exp":       float64(now.Unix() + 600),
		"namespace": "example-namespace",
		"project":   "project",
		"requester": "example-requester",
	}
}

// reason is the reason of a refusal, and fails the test for any other error.
func reason(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	var r *refused
	if !errors.As(err, &r) {
		t.Fatalf("%v is not a refusal of the run credential", err)
	}
	if !errors.Is(err, ErrRefused) || err.Error() != ErrRefused.Error() {
		t.Errorf("a refusal reads %q and is ErrRefused %v; want the one opaque text", err, errors.Is(err, ErrRefused))
	}
	return r.reason
}

func TestSelectKey(t *testing.T) {
	two := issuer()
	two.Algorithms = []string{ES256, EdDSA}
	two.Keys = []Key{{KID: "k-es256", Alg: ES256, PublicKeyFile: "es256.pem"}, {KID: "k-eddsa", Alg: EdDSA, PublicKeyFile: "eddsa.pem"}}
	for _, c := range []struct {
		name   string
		i      Issuer
		header map[string]any
		want   int
		reason string
	}{
		{"one key, no kid", issuer(), map[string]any{"alg": "RS256", "typ": "JWT"}, 0, ""},
		{"two keys, the second by kid", two, map[string]any{"alg": "EdDSA", "kid": "k-eddsa"}, 1, ""},
		{"two keys, the first by kid", two, map[string]any{"alg": "ES256", "kid": "k-es256"}, 0, ""},
		{"jwk is never followed", two, map[string]any{"alg": "ES256", "kid": "k-es256", "jwk": map[string]any{"kty": "EC"}, "jku": "https://elsewhere.example"}, 0, ""},
		{"alg none", issuer(), map[string]any{"alg": "none"}, 0, "alg is not among the issuer's algorithms"},
		{"alg HS256", issuer(), map[string]any{"alg": "HS256"}, 0, "alg is not among the issuer's algorithms"},
		{"alg in lower case", issuer(), map[string]any{"alg": "rs256"}, 0, "alg is not among the issuer's algorithms"},
		{"alg not the issuer's", two, map[string]any{"alg": "RS256", "kid": "k-es256"}, 0, "alg is not among the issuer's algorithms"},
		{"alg missing", issuer(), map[string]any{"typ": "JWT"}, 0, "alg is not a string"},
		{"alg a number", issuer(), map[string]any{"alg": 256.0}, 0, "alg is not a string"},
		{"crit", issuer(), map[string]any{"alg": "RS256", "crit": []any{"exp"}}, 0, "crit is present"},
		{"kid unknown", two, map[string]any{"alg": "ES256", "kid": "k-unknown"}, 0, "kid names no pinned key"},
		{"kid empty", two, map[string]any{"alg": "ES256", "kid": ""}, 0, "kid names no pinned key"},
		{"kid with one key without kid", issuer(), map[string]any{"alg": "RS256", "kid": "k1"}, 0, "kid names no pinned key"},
		{"kid a number", two, map[string]any{"alg": "ES256", "kid": 1.0}, 0, "kid is not a string"},
		{"no kid, two keys", two, map[string]any{"alg": "ES256"}, 0, "no kid, and the issuer pins more than one key"},
		{"alg differs from the key's", two, map[string]any{"alg": "EdDSA", "kid": "k-es256"}, 0, "alg is not the selected key's alg"},
	} {
		t.Run(c.name, func(t *testing.T) {
			n, err := c.i.SelectKey(c.header)
			if got := reason(t, err); got != c.reason {
				t.Errorf("SelectKey refuses with %q; want %q", got, c.reason)
			}
			if err == nil && n != c.want {
				t.Errorf("SelectKey selects key %d; want %d", n, c.want)
			}
		})
	}
	// An Issuer built in Go with none among its algorithms still selects nothing for it.
	odd := issuer()
	odd.Algorithms = []string{"none", "HS256"}
	odd.Keys = []Key{{Alg: "none"}}
	for _, alg := range []string{"none", "HS256"} {
		if _, err := odd.SelectKey(map[string]any{"alg": alg}); err == nil {
			t.Errorf("an issuer that lists %s selects a key for it", alg)
		}
	}
}

func TestCheckClaims(t *testing.T) {
	bounded := issuer()
	bounded.MaxLifetime = d(time.Hour)
	tight := issuer()
	tight.Leeway = d(0)
	noAudience := issuer()
	noAudience.Audience = ""
	unix := now.Unix()
	for _, c := range []struct {
		name   string
		i      Issuer
		change map[string]any // nil removes the claim
		reason string
	}{
		{"valid", issuer(), nil, ""},
		{"valid, numbers as json.Number", issuer(), map[string]any{"exp": json.Number(fmt.Sprint(unix + 600)), "iat": json.Number(fmt.Sprint(unix - 60))}, ""},
		{"valid, numbers as int64", issuer(), map[string]any{"exp": unix + 600, "iat": unix - 60}, ""},
		{"valid, a fractional exp", issuer(), map[string]any{"exp": float64(unix) + 0.5}, ""},
		{"valid, aud an array", issuer(), map[string]any{"aud": []any{"another-service", exampleAudience}}, ""},
		{"valid, no iat", issuer(), map[string]any{"iat": nil}, ""},
		{"valid, exp within the leeway", issuer(), map[string]any{"exp": float64(unix - 59)}, ""},
		{"valid, iat within the leeway", issuer(), map[string]any{"iat": float64(unix + 60)}, ""},
		{"valid, nbf within the leeway", issuer(), map[string]any{"nbf": float64(unix + 60)}, ""},
		{"valid, lifetime at max", bounded, map[string]any{"iat": float64(unix - 60), "exp": float64(unix - 60 + 3600)}, ""},
		{"no exp", issuer(), map[string]any{"exp": nil}, "exp is missing or not a NumericDate"},
		{"exp a string", issuer(), map[string]any{"exp": "1700000600"}, "exp is missing or not a NumericDate"},
		{"exp negative", issuer(), map[string]any{"exp": -1.0}, "exp is missing or not a NumericDate"},
		{"exp beyond the year 9999", issuer(), map[string]any{"exp": 1e300}, "exp is missing or not a NumericDate"},
		{"exp at the leeway", issuer(), map[string]any{"exp": float64(unix - 60)}, "exp has passed"},
		{"exp now, no leeway", tight, map[string]any{"exp": float64(unix)}, "exp has passed"},
		{"expired", issuer(), map[string]any{"exp": float64(unix - 120), "iat": float64(unix - 720)}, "exp has passed"},
		{"iat a string", issuer(), map[string]any{"iat": "now"}, "iat is not a NumericDate"},
		{"iat in the future", issuer(), map[string]any{"iat": float64(unix + 61)}, "iat is in the future"},
		{"nbf in the future", issuer(), map[string]any{"nbf": float64(unix + 61)}, "nbf is in the future"},
		{"nbf a string", issuer(), map[string]any{"nbf": "later"}, "nbf is not a NumericDate"},
		{"lifetime above max", bounded, map[string]any{"iat": float64(unix - 60), "exp": float64(unix - 60 + 3601)}, "the lifetime is above max_lifetime"},
		{"no iat, max set", bounded, map[string]any{"iat": nil}, "no iat, and max_lifetime is set"},
		{"iss another", issuer(), map[string]any{"iss": "https://other-issuer.example"}, "iss is not the issuer"},
		{"iss with a trailing slash", issuer(), map[string]any{"iss": exampleIssuer + "/"}, "iss is not the issuer"},
		{"no iss", issuer(), map[string]any{"iss": nil}, "iss is not the issuer"},
		{"aud another", issuer(), map[string]any{"aud": "another-service"}, "aud does not contain the audience"},
		{"aud an array without it", issuer(), map[string]any{"aud": []any{"another-service"}}, "aud does not contain the audience"},
		{"aud an empty array", issuer(), map[string]any{"aud": []any{}}, "aud does not contain the audience"},
		{"aud an array with a number", issuer(), map[string]any{"aud": []any{exampleAudience, 1.0}}, "aud does not contain the audience"},
		{"no aud", issuer(), map[string]any{"aud": nil}, "aud does not contain the audience"},
		{"an issuer without an audience, aud empty", noAudience, map[string]any{"aud": ""}, "the issuer has no audience"},
		{"an issuer without an audience, aud an array with empty", noAudience, map[string]any{"aud": []any{""}}, "the issuer has no audience"},
		{"no sub", issuer(), map[string]any{"sub": nil}, "sub is missing"},
		{"sub empty", issuer(), map[string]any{"sub": ""}, "sub is missing"},
		{"sub a number", issuer(), map[string]any{"sub": 1.0}, "sub is missing"},
	} {
		t.Run(c.name, func(t *testing.T) {
			claims := validClaims()
			for k, v := range c.change {
				if v == nil {
					delete(claims, k)
				} else {
					claims[k] = v
				}
			}
			if got := reason(t, c.i.CheckClaims(claims, now)); got != c.reason {
				t.Errorf("CheckClaims refuses with %q; want %q", got, c.reason)
			}
		})
	}
}

func TestRefusedIsOpaque(t *testing.T) {
	secret := "eyJhbGciOiJSUzI1NiJ9.c2VjcmV0.c2ln"
	claims := validClaims()
	claims["sub"] = secret
	claims["namespace"] = secret
	claims["aud"] = secret
	errs := []error{issuer().CheckClaims(claims, now)}
	_, err := issuer().SelectKey(map[string]any{"alg": secret, "kid": secret})
	errs = append(errs, err)
	claims = validClaims()
	claims["project"] = secret + "/" + secret
	_, err = issuer().Labels(claims)
	errs = append(errs, err)
	for _, err := range errs {
		if err == nil {
			t.Fatal("a refusal is nil")
		}
		for _, s := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
			if strings.Contains(s, secret) || strings.Contains(s, "c2VjcmV0") {
				t.Errorf("a refusal shows a claim value: %s", s)
			}
		}
	}
	r := Refused()
	if r.Code != refusal.RunCredentialRefused || len(r.Names) != 0 {
		t.Errorf("Refused is %+v; want run_credential_refused with no names", r)
	}
	var ar *accesskey.Refusal
	if !errors.As(error(r), &ar) {
		t.Error("Refused is not an *accesskey.Refusal")
	}
}
