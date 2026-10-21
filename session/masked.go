package session

import "github.com/qoryai/forager/mask"

// maskedRecord is the data of an event mapped from an output or hook record with every
// string replaced by m, map keys included: a printed environment in a tool's result
// contains the forwarder's password. A nil m returns data. The record's maps are left
// as they are; what changes is a copy.
func maskedRecord(m *mask.Masker, data map[string]any) map[string]any {
	if m == nil || data == nil {
		return data
	}
	return maskedValue(m, data).(map[string]any)
}

// maskedValue is v with every string in it replaced by m: a string, and the strings of
// the maps and slices encoding/json decodes into, at any depth. Every other value is
// returned as it is.
func maskedValue(m *mask.Masker, v any) any {
	switch v := v.(type) {
	case string:
		return m.Replace(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			out[m.Replace(k)] = maskedValue(m, e)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = maskedValue(m, e)
		}
		return out
	}
	return v
}
