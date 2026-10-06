// Package refusal is a run the runner refuses before it starts, with the refusal code
// of the contract, contracts/runner/v1, that says why, and the names it concerns.
//
// An [Error] reads as a sentence for the caller's user and contains names alone: a
// variable's name, a tool's, an image's, never a value.
package refusal

import (
	"fmt"
	"slices"
)

// The codes the runner decides.
const (
	// RunConfigurationInvalid is a run configuration the decoder, the schema or the
	// limits refuse, a fetched security_policy included.
	RunConfigurationInvalid = "run_configuration_invalid"
	// ToolUnknown is a tool the machine does not define, or one a server selects that
	// the node's policy leaves out.
	ToolUnknown = "tool_unknown"
	// ImageUnknown is an image the machine does not define, or a server's image other
	// than the one the node's policy selects.
	ImageUnknown = "image_unknown"
	// VariableReserved is a walled run whose environment passes a QORY_ variable, or a
	// variable a machine value is read from, into the enclosure.
	VariableReserved = "variable_reserved"
	// RuntimeSecretConflict is a walled run whose environment contains a variable the
	// run's runtime declares or reserves.
	RuntimeSecretConflict = "runtime_secret_conflict"
	// PlaceholderConflict is a run that passes a value for a placeholder.
	PlaceholderConflict = "placeholder_conflict"
)

// Error is a refused run.
type Error struct {
	// Code is the contract's refusal code.
	Code string
	// Names are what the refusal concerns, sorted, each once: variables, tools, images.
	// Nil when it concerns no name.
	Names []string
	// Err says why, for the caller's user.
	Err error
}

func (e *Error) Error() string { return e.Err.Error() }

// Unwrap returns the reason.
func (e *Error) Unwrap() error { return e.Err }

// New is a refusal with the code, the names and the reason written as fmt writes it.
func New(code string, names []string, format string, a ...any) *Error {
	var sorted []string
	if len(names) > 0 {
		sorted = slices.Clone(names)
		slices.Sort(sorted)
		sorted = slices.Compact(sorted)
	}
	return &Error{Code: code, Names: sorted, Err: fmt.Errorf(format, a...)}
}
