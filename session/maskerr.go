package session

import (
	"errors"
	"slices"

	"github.com/qoryai/forager/mask"
)

// maskedError is an error whose text a masker replaced the run's secrets in, which
// [Open], [Run.Join], [Run.Close], [Run.Setup], [Run.FetchImage], [Run.StartStep],
// [Step.Log] and [Step.Exit] return: Error is the masked text, and Unwrap is the
// error, so errors.Is reaches what it wraps. errors.As gives a [*Refusal] in it as a
// copy with its text, detail and names masked and its code kept, when the masker
// changes one of them; any other type errors.As reaches has its text as it is.
type maskedError struct {
	text    string
	err     error
	refusal *Refusal
}

// Error is the masked text.
func (e *maskedError) Error() string { return e.text }

// Unwrap is the error the text was masked from.
func (e *maskedError) Unwrap() error { return e.err }

// As sets a **Refusal target to the masked copy of the refusal in the error.
func (e *maskedError) As(target any) bool {
	if t, ok := target.(**Refusal); ok && e.refusal != nil {
		*t = e.refusal
		return true
	}
	return false
}

// maskError is err with m applied to its text, as a [maskedError], when m changes the
// text or a refusal's members in it; err as it is otherwise, nil included. The masked
// text is made now, so a Clear of m after the call leaves it masked.
func maskError(m *mask.Masker, err error) error {
	if err == nil || m == nil {
		return err
	}
	text := err.Error()
	masked := m.Replace(text)
	var copied *Refusal
	if ref := (*Refusal)(nil); errors.As(err, &ref) {
		c := *ref
		if t := ref.Error(); m.Replace(t) != t {
			c.Text = m.Replace(t)
		}
		c.Detail = m.Replace(ref.Detail)
		c.Names = nil
		for _, n := range ref.Names {
			c.Names = append(c.Names, m.Replace(n))
		}
		if c.Text != ref.Text || c.Detail != ref.Detail || !slices.Equal(c.Names, ref.Names) {
			copied = &c
		}
	}
	if masked == text && copied == nil {
		return err
	}
	return &maskedError{text: masked, err: err, refusal: copied}
}
