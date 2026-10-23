package session

import (
	"maps"

	"github.com/qoryai/forager/mask"
)

// texts masks the strings of a session's events: the run's masker replaces the
// forwarders' passwords first, then the harness masker the harness's text. Either is
// nil for none.
type texts struct {
	secrets *mask.Masker
	harness *mask.Harness
}

// replace is s with both maskers' finds replaced, the passwords first.
func (t texts) replace(s string) string { return t.harness.Replace(t.secrets.Replace(s)) }

// maskedRecord is the data of an event mapped from an output or hook record with every
// string masked by t, map keys included: a printed environment in a tool's result
// contains the forwarder's password, and a tool's input or result the text of a hidden
// harness. With neither masker it returns data. The record's maps are left as they
// are; what changes is a copy.
func maskedRecord(t texts, data map[string]any) map[string]any {
	if t.secrets == nil && t.harness == nil || data == nil {
		return data
	}
	return maskedValue(t, data).(map[string]any)
}

// maskedValue is v with every string in it masked by t: a string, and the strings of
// the maps and slices encoding/json decodes into, at any depth. Every other value is
// returned as it is.
func maskedValue(t texts, v any) any {
	switch v := v.(type) {
	case string:
		return t.replace(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			out[t.replace(k)] = maskedValue(t, e)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = maskedValue(t, e)
		}
		return out
	}
	return v
}

// withSession is a copy of data, the data of an event mapped from a record, with n as
// session, the number of the session whose runtime wrote the record.
func withSession(data map[string]any, n int) map[string]any {
	out := make(map[string]any, len(data)+1)
	maps.Copy(out, data)
	out["session"] = n
	return out
}
