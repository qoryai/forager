package session

import (
	"fmt"
	"slices"
	"testing"

	"github.com/qoryai/forager/mask"
)

// TestTheRunMasksServerValuesUpToTheMaskersCap pins the count bound of the run's masker
// on the server's values over a run: of 1025 different values, the first 1024 by name
// are masked and the last is a Report line with its variable's name; a value the run has
// masked already does not count again; a value under 8 characters is left out without a
// line. clearMaskers clears a masker the run made.
func TestTheRunMasksServerValuesUpToTheMaskersCap(t *testing.T) {
	var lines []string
	r := &Run{masker: mask.New(), madeMasker: true, passwords: &mask.Masker{}, open: OpenSpec{Report: func(l string) { lines = append(lines, l) }}}
	first := map[string]string{"SHORT": "short"}
	for i := range mask.MaxSecrets - 1 {
		first[fmt.Sprintf("EXAMPLE_%04d", i)] = fmt.Sprintf("fake-value-%04d", i)
	}
	r.addServerValues(first)
	r.addServerValues(map[string]string{"AGAIN": "fake-value-0000", "EXAMPLE_1023": "fake-value-1023", "EXAMPLE_1024": "fake-value-1024"})
	if got := r.masker.Replace("fake-value-0000 fake-value-1023 fake-value-1024 short"); got != "*** *** fake-value-1024 short" {
		t.Errorf("Replace: %q", got)
	}
	want := []string{"the server's variable EXAMPLE_1024 is not masked: the run's masker has 1024 values already"}
	if !slices.Equal(lines, want) {
		t.Errorf("the Report lines %q, want %q", lines, want)
	}
	r.clearMaskers()
	if r.masker.Replace("fake-value-0000") != "fake-value-0000" {
		t.Error("clearMaskers left a value")
	}
}

// TestClearMaskersLeavesTheCallersMasker pins a run with OpenSpec.Masker: clearMaskers
// clears the forwarders' passwords alone, and the caller's masker keeps its values.
func TestClearMaskersLeavesTheCallersMasker(t *testing.T) {
	m := mask.New()
	m.AddSecret([]byte("fake-caller-value"))
	r := &Run{masker: m, passwords: &mask.Masker{}}
	r.addPassword("fake-password-0123")
	r.clearMaskers()
	if got := m.Replace("fake-caller-value"); got != "***" {
		t.Errorf("the caller's masker after clearMaskers: %q", got)
	}
	if !r.passwords.Empty() {
		t.Error("clearMaskers left a forwarder's password")
	}
}
