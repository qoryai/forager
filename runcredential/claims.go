package runcredential

import (
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/refusal"
)

// ErrRefused is every failure of a run credential: its header, its claims, its scope
// and its mapping. It is one opaque error, so neither a log nor an answer tells a
// client which check refused the run credential, and it names no claim value. A gateway
// answers it with [Refused] to a session and with 407 to a client with no session.
var ErrRefused = errors.New("the gateway refused this run credential")

// refused is a failure of a run credential. Its step and its reason, constants, are for
// this package's tests; Error returns [ErrRefused]'s text whatever they are.
type refused struct {
	// step is the step of the verification that refused it, as the known answers name
	// them: serialisation, header, signature, claims, scope or mapping; "" when the
	// function that refused it is not [Verifier.Verify].
	step   string
	reason string
}

func (r *refused) Error() string { return ErrRefused.Error() }

// Is reports that a refused is [ErrRefused].
func (r *refused) Is(target error) bool { return target == ErrRefused }

// refuse is a failure of a run credential for a reason.
func refuse(reason string) error { return &refused{reason: reason} }

// refuseAt is a failure of a run credential at a step of the verification.
func refuseAt(step, reason string) error { return &refused{step: step, reason: reason} }

// at sets the step of a failure of a run credential that has none, and returns it.
func at(step string, err error) error {
	var r *refused
	if errors.As(err, &r) && r.step == "" {
		r.step = step
	}
	return err
}

// Refused is the refusal a gateway answers a session with for any [ErrRefused]: the
// code run_credential_refused, with no names.
func Refused() *accesskey.Refusal {
	return refusal.New(refusal.RunCredentialRefused, nil, "the gateway refused this run credential")
}

// SelectKey selects the pinned key a run credential's protected header names, step 1
// of the verification, and returns its index in the issuer's keys. The header is the
// decoded JSON object of the JWS protected header. It is refused, as [ErrRefused],
// when:
//
//   - alg is not a string, or not among the issuer's algorithms (none and every HMAC
//     algorithm never are);
//   - kid is present and not a string, or names no pinned key;
//   - kid is absent and the issuer pins more than one key;
//   - the selected key's alg is not the header's alg;
//   - crit is present: the gateway understands no extension of RFC 7515 §4.1.11;
//   - typ is present and not the string JWT, compared without regard to case (RFC 7519
//     §5.1).
//
// Nothing else of the header selects a key: jku, jwk, x5u and x5c are never followed.
// The header is read before the signature is verified, so SelectKey only narrows; the
// signature over the exact bytes received is verified next, under the key it returns.
func (i Issuer) SelectKey(header map[string]any) (int, error) {
	alg, ok := header["alg"].(string)
	if !ok {
		return 0, refuse("alg is not a string")
	}
	if !supported(alg) || !slices.Contains(i.Algorithms, alg) {
		return 0, refuse("alg is not among the issuer's algorithms")
	}
	if _, ok := header["crit"]; ok {
		return 0, refuse("crit is present")
	}
	if v, present := header["typ"]; present {
		if typ, ok := v.(string); !ok || !strings.EqualFold(typ, "JWT") {
			return 0, refuse("typ is not JWT")
		}
	}
	n := -1
	if v, present := header["kid"]; present {
		kid, ok := v.(string)
		if !ok {
			return 0, refuse("kid is not a string")
		}
		for j, k := range i.Keys {
			if k.KID != "" && k.KID == kid {
				n = j
				break
			}
		}
		if n < 0 {
			return 0, refuse("kid names no pinned key")
		}
	} else {
		if len(i.Keys) != 1 {
			return 0, refuse("no kid, and the issuer pins more than one key")
		}
		n = 0
	}
	if i.Keys[n].Alg != alg {
		return 0, refuse("alg is not the selected key's alg")
	}
	return n, nil
}

// maxNumericDate is the latest NumericDate a time claim may hold, 9999-12-31T23:59:59Z,
// so no claim overflows a time.Time.
const maxNumericDate = 253402300799

// CheckClaims checks the claims of a run credential whose signature a verifier has
// already verified under the key [Issuer.SelectKey] selected, step 3 of the
// verification, at now. Every failure is [ErrRefused]:
//
//   - the issuer and its audience are not empty, so an Issuer built in Go without
//     [Issuer.Check] never matches an iss or an aud of "", and its leeway is not
//     negative and at most [MaxLeeway];
//   - exp is required, a NumericDate, and now is before exp plus the leeway;
//   - iat, when present, is a NumericDate no later than now plus the leeway;
//   - nbf, when present, is a NumericDate no later than now plus the leeway (RFC 7519
//     §4.1.5);
//   - when max_lifetime is set, iat is required and exp minus iat is at most
//     max_lifetime;
//   - iss is a string equal to the issuer;
//   - aud is a string equal to the audience, or an array of strings that contains it;
//   - sub, the run key, is a non-empty string.
//
// A NumericDate is a JSON number of seconds since the epoch, not negative, at most the
// year 9999: a float64, a json.Number, an int or an int64 as a JSON decoder gives it.
func (i Issuer) CheckClaims(claims map[string]any, now time.Time) error {
	if i.Issuer == "" {
		return refuse("the issuer is empty")
	}
	if i.Audience == "" {
		return refuse("the issuer has no audience")
	}
	leeway := i.LeewayOrDefault()
	if leeway < 0 || leeway > MaxLeeway {
		return refuse("the leeway is outside 0 to MaxLeeway")
	}
	exp, ok, err := numericDate(claims, "exp")
	if err != nil || !ok {
		return refuse("exp is missing or not a NumericDate")
	}
	if !now.Before(exp.Add(leeway)) {
		return refuse("exp has passed")
	}
	iat, hasIAT, err := numericDate(claims, "iat")
	if err != nil {
		return refuse("iat is not a NumericDate")
	}
	if hasIAT && iat.After(now.Add(leeway)) {
		return refuse("iat is in the future")
	}
	nbf, hasNBF, err := numericDate(claims, "nbf")
	if err != nil {
		return refuse("nbf is not a NumericDate")
	}
	if hasNBF && nbf.After(now.Add(leeway)) {
		return refuse("nbf is in the future")
	}
	if i.MaxLifetime != nil {
		if !hasIAT {
			return refuse("no iat, and max_lifetime is set")
		}
		if exp.Sub(iat) > time.Duration(*i.MaxLifetime) {
			return refuse("the lifetime is above max_lifetime")
		}
	}
	if iss, ok := claims["iss"].(string); !ok || iss != i.Issuer {
		return refuse("iss is not the issuer")
	}
	if !audience(claims["aud"], i.Audience) {
		return refuse("aud does not contain the audience")
	}
	if sub, ok := claims["sub"].(string); !ok || sub == "" {
		return refuse("sub is missing")
	}
	return nil
}

// numericDate reads a NumericDate claim: the time, whether it is present, and an error
// when it is present and not a NumericDate.
func numericDate(claims map[string]any, name string) (time.Time, bool, error) {
	v, ok := claims[name]
	if !ok {
		return time.Time{}, false, nil
	}
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case json.Number:
		var err error
		if f, err = n.Float64(); err != nil {
			return time.Time{}, true, errNumericDate
		}
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	default:
		return time.Time{}, true, errNumericDate
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > maxNumericDate {
		return time.Time{}, true, errNumericDate
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true, nil
}

// errNumericDate is a time claim that is not a NumericDate.
var errNumericDate = errors.New("not a NumericDate")

// audience reports whether aud, a string or an array of strings, contains want. An
// array with a member that is not a string contains nothing.
func audience(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		found := false
		for _, v := range a {
			s, ok := v.(string)
			if !ok {
				return false
			}
			if s == want {
				found = true
			}
		}
		return found
	case []string:
		return slices.Contains(a, want)
	}
	return false
}
