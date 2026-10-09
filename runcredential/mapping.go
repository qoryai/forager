package runcredential

import (
	"slices"
	"strings"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/refusal"
	"github.com/qoryai/forager/server"
)

// Allowed reports whether a run credential's verified claims are in the issuer's
// scope, step 4 of the verification: the claim allow names is a string, one of the
// values it lists. An issuer without allow allows every run credential that passed
// the other steps.
func (i Issuer) Allowed(claims map[string]any) bool {
	if i.Allow == nil {
		return true
	}
	v, ok := claims[i.Allow.Claim].(string)
	return ok && slices.Contains(i.Allow.Values, v)
}

// Labels makes the run's labels from a run credential's verified claims: forge,
// repository and run_key, the three a run carries, and nothing else. A run's labels
// come from the run credential alone.
//
//   - forge is the constant, or the claim;
//   - repository is the constant, the claim, or the claims' values joined in order
//     with join;
//   - run_key is the claim sub.
//
// Each claim the mapping names is a non-empty string with no control character, as a
// value of details is ([Issuer.Details]); a claim of repository's claims holds no
// join, so two different targets never make one repository; and the labels pass
// [server.CheckLabels]. Every failure is [ErrRefused].
func (i Issuer) Labels(claims map[string]any) (map[string]string, error) {
	forge, err := i.LabelMapping.Forge.value(claims)
	if err != nil {
		return nil, err
	}
	repository, err := i.LabelMapping.Repository.value(claims)
	if err != nil {
		return nil, err
	}
	if i.LabelMapping.RunKey.Claim != "sub" {
		return nil, refuse("run_key is not the claim sub")
	}
	runKey, err := claimString(claims, "sub")
	if err != nil {
		return nil, err
	}
	labels := map[string]string{LabelForge: forge, LabelRepository: repository, LabelRunKey: runKey}
	if server.CheckLabels(labels) != nil {
		return nil, refuse("a label is beyond the label limits")
	}
	return labels, nil
}

// value is a label's value from the claims.
func (s Source) value(claims map[string]any) (string, error) {
	switch {
	case s.Value != "":
		return s.Value, nil
	case s.Claim != "":
		return claimString(claims, s.Claim)
	case len(s.Claims) > 0 && s.Join != "":
		parts := make([]string, len(s.Claims))
		for n, c := range s.Claims {
			v, err := claimString(claims, c)
			if err != nil {
				return "", err
			}
			if strings.Contains(v, s.Join) {
				return "", refuse("a claim of repository holds the join")
			}
			parts[n] = v
		}
		return strings.Join(parts, s.Join), nil
	}
	return "", refuse("the mapping names no source")
}

// claimString is a claim of a label: a non-empty string with no control character.
func claimString(claims map[string]any, name string) (string, error) {
	v, ok := claims[name].(string)
	if !ok || v == "" {
		return "", refuse("a claim the mapping names is missing or not a string")
	}
	if !plain(v) {
		return "", refuse("a claim of labels is not UTF-8 or holds a control character")
	}
	return v, nil
}

// Details makes the keys of about.details the run credential decides from its
// verified claims: for each key of the issuer's details whose claim the run credential
// carries, the value of that claim, a string with no control character. A key whose
// claim the run credential does not carry is not decided by it, and the session's own
// value stands. A claim that is present and not such a string is [ErrRefused]. The
// 8192 bytes of about.details are the session's and the gateway's check of the whole
// about, not this one's.
func (i Issuer) Details(claims map[string]any) (map[string]string, error) {
	if len(i.DetailMapping) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(i.DetailMapping))
	for key, c := range i.DetailMapping {
		raw, present := claims[c.Claim]
		if !present {
			continue
		}
		v, ok := raw.(string)
		if !ok {
			return nil, refuse("a claim of details is not a string")
		}
		if !plain(v) {
			return nil, refuse("a claim of details holds a control character")
		}
		out[key] = v
	}
	return out, nil
}

// Compare compares what a session sends beside its run credential, its labels and its
// about.details, with what the run credential decides, the labels and the details the
// mapping made, and returns the refusal of the run, or nil when every key the session
// sent and the run credential decides has the run credential's value.
//
//   - A session whose label forge or repository differs is
//     target_differs_from_credential, named labels.forge=<value> and
//     labels.repository=<value> for each that differs, the value being the run
//     credential's. It is returned before any other difference.
//   - A session that sends any other label the mapping sets, run_key, or a key of
//     about.details the mapping sets, with another value, is differs_from_credential,
//     named labels.<key>=<value> or about.details.<key>=<value> for each.
//
// A session's label the mapping does not set is ignored: a run's labels come from the
// run credential alone. A session's key of about.details the mapping does not set is
// kept: qory's flags fill the rest. That includes a key of the issuer's details whose
// claim the run credential does not carry, which [Issuer.Details] leaves out of
// credDetails. A key of about.details the session sends as other than a string differs
// from the run credential's string.
func Compare(sessionLabels map[string]string, sessionDetails map[string]any, credLabels, credDetails map[string]string) *accesskey.Refusal {
	var target, other []string
	for _, key := range []string{LabelForge, LabelRepository} {
		if v, ok := sessionLabels[key]; ok && v != credLabels[key] {
			target = append(target, "labels."+key+"="+credLabels[key])
		}
	}
	if len(target) > 0 {
		return refusal.New(refusal.TargetDiffersFromCredential, target,
			"the session's target differs from the run credential's")
	}
	for key, want := range credLabels {
		if key == LabelForge || key == LabelRepository {
			continue
		}
		if v, ok := sessionLabels[key]; ok && v != want {
			other = append(other, "labels."+key+"="+want)
		}
	}
	for key, want := range credDetails {
		if v, ok := sessionDetails[key]; ok {
			if s, isString := v.(string); !isString || s != want {
				other = append(other, "about.details."+key+"="+want)
			}
		}
	}
	if len(other) > 0 {
		return refusal.New(refusal.DiffersFromCredential, other,
			"the session sends a key the run credential decides with another value")
	}
	return nil
}
