package gateway

import (
	"fmt"
	"io"
	"log/slog"
)

// redacted is how a secret prints.
const redacted = "[redacted]"

// secretValue holds a secret of the gateway's, the link secret, a run's proxy secret
// or the run answer that holds it, so that printing it
// never shows it: its String, Format, GoString and LogValue are [redacted]. It is a
// func, which fmt prints as its address alone under every verb, so a copy of a struct
// that holds one, printed with %v, %+v, %#v or any other verb, never shows the bytes
// either: fmt calls no method of an unexported field.
type secretValue func() string

// newSecretValue holds s.
func newSecretValue(s string) secretValue { return func() string { return s } }

// reveal is the secret itself, for the one place that hands it on.
func (s secretValue) reveal() string {
	if s == nil {
		return ""
	}
	return s()
}

// String is [redacted].
func (s secretValue) String() string { return redacted }

// Format prints [redacted] under every verb and flag.
func (s secretValue) Format(f fmt.State, _ rune) { io.WriteString(f, redacted) }

// GoString is [redacted].
func (s secretValue) GoString() string { return redacted }

// LogValue is [redacted].
func (s secretValue) LogValue() slog.Value { return slog.StringValue(redacted) }
