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
// so is a value TOMLValue refuses. Nil when there is no setting.
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
