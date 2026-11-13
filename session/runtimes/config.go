package runtimes

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/qoryai/forager/accesskey"
)

// ConfigArgs are the arguments that pass settings to a runtime that reads them as TOML:
// c.Flag and key=value for each setting of c.Fixed and of set together, sorted by key,
// each value written by [TOMLValue]. A key of set that c.Fixed has too is an error, and
// so is a value TOMLValue returns an error for. Nil when there is no setting.
func ConfigArgs(c Config, set map[string]any) ([]string, error) {
	all := maps.Clone(c.Fixed)
	if all == nil {
		all = map[string]any{}
	}
	for k, v := range set {
		if _, ok := all[k]; ok {
			return nil, fmt.Errorf("remove %s from config.fixed: the session sets it", accesskey.ShownName(k, false))
		}
		all[k] = v
	}
	var out []string
	for _, k := range slices.Sorted(maps.Keys(all)) {
		v, err := TOMLValue(all[k])
		if err != nil {
			return nil, fmt.Errorf("give the setting %s a string in UTF-8, a bool or an integer: %w", accesskey.ShownName(k, false), err)
		}
		out = append(out, c.Flag, k+"="+v)
	}
	return out, nil
}

// TOMLValue is v as a TOML value: a string as a basic string, in quotes, with a quote,
// a backslash and every control character escaped, so the value is one line; a bool as
// true or false; an int or an int64 in decimal. A string that is not UTF-8 is an error,
// as TOML is UTF-8, and so is a value of any other type.
func TOMLValue(v any) (string, error) {
	switch v := v.(type) {
	case string:
		if !utf8.ValidString(v) {
			return "", fmt.Errorf("its value %s is not UTF-8, which TOML requires", accesskey.ShownValue(v, true))
		}
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range v {
			switch r {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\b':
				b.WriteString(`\b`)
			case '\t':
				b.WriteString(`\t`)
			case '\n':
				b.WriteString(`\n`)
			case '\f':
				b.WriteString(`\f`)
			case '\r':
				b.WriteString(`\r`)
			default:
				if r < 0x20 || r == 0x7f {
					fmt.Fprintf(&b, `\u%04X`, r)
					continue
				}
				b.WriteRune(r)
			}
		}
		b.WriteByte('"')
		return b.String(), nil
	case bool:
		return strconv.FormatBool(v), nil
	case int:
		return strconv.Itoa(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	}
	return "", fmt.Errorf("its value is a %T, not a string, a bool or an integer", v)
}

// ArgsChecker is implemented by a runtime that refuses launch arguments that override
// a setting the session passes. It is optional and checked by type assertion.
type ArgsChecker interface {
	// CheckArgs returns an error, whose message starts with the fix and contains no
	// value of args, when args set a setting the session passes.
	CheckArgs(args []string) error
}

// ArgsCheck refuses the arguments of a launch that set one of keys, the settings the
// session passes, through a flag of the runtime's that config.flag does not cover. Its
// error starts with the fix and contains no value of args.
type ArgsCheck func(args, keys []string) error

// SessionKey is the key of keys that a setting of key changes, and true: key itself,
// a key under it, such as model_providers.qory.base_url under model_providers.qory,
// or a key it is under, such as model_providers.qory for model_providers.qory.name,
// which replaces the whole table. Spaces around key do not count, as for Codex.
func SessionKey(key string, keys []string) (string, bool) {
	key = strings.TrimSpace(key)
	for _, k := range keys {
		if key == k || strings.HasPrefix(key, k+".") || strings.HasPrefix(k, key+".") {
			return k, true
		}
	}
	return "", false
}

// PairKey is the key of a key=value pair: what comes before the first =.
func PairKey(pair string) string {
	key, _, _ := strings.Cut(pair, "=")
	return key
}

// sessionKeys is the settings the session passes to the runtime: the keys of
// config.fixed in the descriptor's order and, for an endpoint in a setting, that
// setting. Nil without config.
func (r *described) sessionKeys() []string {
	if r.d.Config == nil {
		return nil
	}
	keys := slices.Clone(r.d.Config.Keys)
	if m := r.d.Model; m != nil && m.Endpoint.Setting != "" {
		keys = append(keys, m.Endpoint.Setting)
	}
	return keys
}

// CheckArgs refuses args that set a setting the session passes through config.flag,
// as "flag key=value" or "flag=key=value", up to an argument --, and then runs the
// runtime's ArgsCheck. A runtime without config passes every argument.
func (r *described) CheckArgs(args []string) error {
	keys := r.sessionKeys()
	if len(keys) == 0 {
		return nil
	}
	flag := r.d.Config.Flag
	for i := 0; i < len(args) && args[i] != "--"; i++ {
		var pair string
		switch {
		case args[i] == flag && i+1 < len(args):
			i++
			pair = args[i]
		case strings.HasPrefix(args[i], flag+"="):
			pair = strings.TrimPrefix(args[i], flag+"=")
		default:
			continue
		}
		if k, ok := SessionKey(PairKey(pair), keys); ok {
			return fmt.Errorf("remove the %s pair that sets %s from the launch's arguments: the session sets %s, and a later pair wins over it",
				accesskey.ShownName(flag, false), accesskey.ShownName(k, false), accesskey.ShownName(k, false))
		}
	}
	if r.check != nil {
		return r.check(args, keys)
	}
	return nil
}
