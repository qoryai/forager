package session_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/qoryai/forager/session"
)

const engineProxyAddr = "127.0.0.1:3129"

var errOpen = errors.New("open failed")

// proxyHolder is a struct of a caller's that contains an EngineProxy as a value and
// as a pointer.
type proxyHolder struct {
	Name    string
	Proxy   session.EngineProxy
	Pointer *session.EngineProxy
}

// secretForms are the fake password as fmt prints it in plain text and under %x,
// %X, % x and % X.
func secretForms() []string {
	lower := hex.EncodeToString([]byte(enginePassword))
	var spaced []string
	for i := 0; i < len(lower); i += 2 {
		spaced = append(spaced, lower[i:i+2])
	}
	spacedLower := strings.Join(spaced, " ")
	return []string{
		enginePassword, lower, strings.ToUpper(lower), spacedLower, strings.ToUpper(spacedLower),
	}
}

// checkShown fails t when out contains the fake password in any of secretForms, or,
// when wantAddr is set, when out contains the address neither in plain text nor
// in hex.
func checkShown(t *testing.T, what, out string, wantAddr bool) {
	t.Helper()
	for _, secret := range secretForms() {
		if strings.Contains(out, secret) {
			t.Errorf("%s printed the engine proxy's password: %s", what, out)
		}
	}
	addr := hex.EncodeToString([]byte(engineProxyAddr))
	if wantAddr && !strings.Contains(out, engineProxyAddr) && !strings.Contains(out, addr) &&
		!strings.Contains(out, strings.ToUpper(addr)) {
		t.Errorf("%s printed no address %s: %s", what, engineProxyAddr, out)
	}
}

// TestAnEngineProxyPrintsItsAddressAlone pins EngineProxy under every fmt verb and
// flag: a value, a pointer and an OpenSpec that contains one show the address and
// never the password, so a %v of a run's spec in a log line leaks no secret.
//
// fmt calls no method of an argument under %w, since an EngineProxy is not an error,
// or under %p of a value that is not a pointer: it prints the fields as %v would with
// no methods (badVerb in fmt/print.go). Those two cases run for an OpenSpec alone,
// whose EngineProxy field is a pointer that fmt then prints as an address. The third
// case, a field that is not exported, is TestAnUnexportedEngineProxyPrintsItsFields.
func TestAnEngineProxyPrintsItsAddressAlone(t *testing.T) {
	p := session.EngineProxy{Addr: engineProxyAddr, Password: enginePassword}
	spec := session.OpenSpec{RunID: "run-1", EngineProxy: &p}
	// The verbs whose output contains the whole address, in plain text or in hex.
	full := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10v", "%-10s", "%#x", "%+q", "%#q", "%08v"}
	// The verbs that fmt rejects for a string, or that cut or space it.
	other := []string{"%t", "%b", "%o", "%O", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%.3s", "% x", "% X", "%z"}
	cases := []struct {
		name string
		arg  any
	}{
		{"a value", p},
		{"a pointer", &p},
		{"an OpenSpec", spec},
		{"a pointer to an OpenSpec", &spec},
		{"a struct", proxyHolder{Name: "n", Proxy: p, Pointer: &p}},
		{"a pointer to a struct", &proxyHolder{Name: "n", Proxy: p, Pointer: &p}},
	}
	for _, c := range cases {
		for _, verb := range full {
			checkShown(t, fmt.Sprintf("%s of %s", verb, c.name), fmt.Sprintf(verb, c.arg), true)
		}
		for _, verb := range other {
			checkShown(t, fmt.Sprintf("%s of %s", verb, c.name), fmt.Sprintf(verb, c.arg), false)
		}
	}
	for _, verb := range []string{"%w", "%p"} {
		for _, arg := range []any{spec, &spec} {
			checkShown(t, verb+" of an OpenSpec", fmt.Sprintf(verb, arg), false)
		}
	}
	checkShown(t, "fmt.Errorf of an OpenSpec", fmt.Errorf("open: %v: %w", spec, errOpen).Error(), true)
	for _, c := range []struct {
		name string
		out  string
	}{
		{"String of a value", p.String()},
		{"String of a pointer", (&p).String()},
		{"GoString of a value", p.GoString()},
		{"GoString of a pointer", (&p).GoString()},
		{"fmt.Sprint", fmt.Sprint(p, &p, spec)},
		{"fmt.Sprintln", fmt.Sprintln(p, &p, spec)},
	} {
		checkShown(t, c.name, c.out, true)
	}
	if got, want := fmt.Sprintf("%#v", p), `session.EngineProxy{Addr:"127.0.0.1:3129"}`; got != want {
		t.Errorf("%%#v printed %s, want %s", got, want)
	}
	if got, want := fmt.Sprintf("%+v", &p), "{Addr:127.0.0.1:3129}"; got != want {
		t.Errorf("%%+v of a pointer printed %s, want %s", got, want)
	}
	if got := fmt.Sprintf("%v", session.OpenSpec{}); strings.Contains(got, "PANIC") {
		t.Errorf("%%v of an OpenSpec with no EngineProxy printed %s", got)
	}
}

// TestAnEngineProxyLogsItsAddressAlone pins EngineProxy under log/slog's text and
// JSON handlers, as a value, as a pointer and nested in a struct.
func TestAnEngineProxyLogsItsAddressAlone(t *testing.T) {
	p := session.EngineProxy{Addr: engineProxyAddr, Password: enginePassword}
	for _, h := range []struct {
		name string
		new  func(*bytes.Buffer) slog.Handler
	}{
		{"text", func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
		{"JSON", func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
	} {
		for _, c := range []struct {
			name string
			arg  any
		}{
			{"a value", p},
			{"a pointer", &p},
			{"a struct", proxyHolder{Name: "n", Proxy: p, Pointer: &p}},
			{"a pointer to a struct", &proxyHolder{Name: "n", Proxy: p, Pointer: &p}},
		} {
			var b bytes.Buffer
			slog.New(h.new(&b)).Info("open", "proxy", c.arg)
			checkShown(t, fmt.Sprintf("the %s handler with %s", h.name, c.name), b.String(), true)
		}
	}
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("open", "proxy", &p)
	if !strings.Contains(b.String(), `"proxy":{"addr":"127.0.0.1:3129"}`) {
		t.Errorf("the JSON handler logged %s, want the group proxy.addr", b.String())
	}
}

// TestAnEngineProxyMarshalsItsAddressAlone pins EngineProxy under encoding/json: a
// value, a pointer and a nested one write {"Addr":...} and no other field.
func TestAnEngineProxyMarshalsItsAddressAlone(t *testing.T) {
	p := session.EngineProxy{Addr: engineProxyAddr, Password: enginePassword}
	want := `{"Addr":"127.0.0.1:3129"}`
	for _, c := range []struct {
		name string
		arg  any
		want string
	}{
		{"a value", p, want},
		{"a pointer", &p, want},
		{"a struct", proxyHolder{Name: "n", Proxy: p, Pointer: &p},
			`{"Name":"n","Proxy":` + want + `,"Pointer":` + want + `}`},
		{"a pointer to a struct", &proxyHolder{Name: "n", Proxy: p, Pointer: &p},
			`{"Name":"n","Proxy":` + want + `,"Pointer":` + want + `}`},
	} {
		out, err := json.Marshal(c.arg)
		if err != nil {
			t.Fatalf("json.Marshal of %s: %v", c.name, err)
		}
		if string(out) != c.want {
			t.Errorf("json.Marshal of %s wrote %s, want %s", c.name, out, c.want)
		}
		checkShown(t, "json.Marshal of "+c.name, string(out), true)
	}
}

// TestAnUnexportedEngineProxyPrintsItsFields pins the third case that the doc of
// EngineProxy lists: fmt calls no method of a value in a struct field that is not
// exported, and prints the password with the address, under %v and %+v and in
// log/slog's text handler. When fmt calls Format there, this test fails, and the doc
// and the CHANGELOG drop the case.
func TestAnUnexportedEngineProxyPrintsItsFields(t *testing.T) {
	type unexported struct {
		name  string
		proxy session.EngineProxy
	}
	held := unexported{name: "n", proxy: session.EngineProxy{Addr: engineProxyAddr, Password: enginePassword}}
	var b bytes.Buffer
	slog.New(slog.NewTextHandler(&b, nil)).Info("open", "config", held)
	for what, out := range map[string]string{
		"%v":                    fmt.Sprintf("%v", held),
		"%+v":                   fmt.Sprintf("%+v", held),
		"the slog text handler": b.String(),
	} {
		if !strings.Contains(out, enginePassword) {
			t.Errorf("%s of an unexported EngineProxy field printed %s, without the password the doc lists", what, out)
		}
	}
	// encoding/json writes no field that is not exported.
	if out, err := json.Marshal(held); err != nil || string(out) != "{}" {
		t.Errorf("json.Marshal of an unexported EngineProxy field wrote %s, %v", out, err)
	}
}
