package session

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/qoryai/forager/mask"
)

// TestAMaskedErrorKeepsIsAndAs pins maskError on a refusal wrapped with a sentinel: the
// text has *** in the value's place, errors.Is finds the sentinel, and errors.As gives a
// copy of the refusal with its code and status kept and its text and names masked; an
// error the masker changes nothing in is returned as it is.
func TestAMaskedErrorKeepsIsAndAs(t *testing.T) {
	const value = "fake-error-value-0123"
	m := mask.New()
	m.AddSecret([]byte(value))
	ref := &Refusal{Code: "example_refused", Status: 403, Names: []string{"EXAMPLE_" + value}, Text: "Remove " + value + " from the run"}
	err := maskError(m, fmt.Errorf("%w: %w", fs.ErrPermission, ref))
	if want := "permission denied: Remove *** from the run"; err.Error() != want {
		t.Errorf("Error: %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Error("errors.Is does not find the sentinel")
	}
	var got *Refusal
	if !errors.As(err, &got) {
		t.Fatal("errors.As finds no refusal")
	}
	if got.Code != "example_refused" || got.Status != 403 || got.Text != "Remove *** from the run" || len(got.Names) != 1 || got.Names[0] != "EXAMPLE_***" {
		t.Errorf("the refusal errors.As gives: %+v", got)
	}
	if ref.Text != "Remove "+value+" from the run" {
		t.Error("maskError changed the refusal it wraps")
	}
	plain := errors.New("nothing to mask")
	if maskError(m, plain) != plain {
		t.Error("maskError wrapped an error it changes nothing in")
	}
}
