// Package refusal is a run the runner refuses before it starts, with the refusal code
// of the contract, contracts/runner/v1, that says why, and the names it concerns.
//
// A refusal is an [*accesskey.Refusal], the type of every refused run, the server's
// codes included. Its Detail reads as a sentence for the caller's user and contains
// names alone: a variable's name, a tool's, an image's, never a value.
package refusal

import (
	"fmt"
	"slices"

	"github.com/qoryai/runner/accesskey"
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
	// PlaceholderConflict is a run that passes a value for a placeholder.
	PlaceholderConflict = "placeholder_conflict"
)

// Decides reports whether the runner decides the code, one of this package's: a
// refusal of the run's own configuration rather than of an answer of the server's.
func Decides(code string) bool {
	switch code {
	case RunConfigurationInvalid, ToolUnknown, ImageUnknown, VariableReserved, PlaceholderConflict:
		return true
	}
	return false
}

// New is a refusal with the code, the names, sorted and each once, and the reason
// written as fmt writes it, as its Detail. It is an [*accesskey.Refusal], the one type
// of a run that does not start whatever decided it.
func New(code string, names []string, format string, a ...any) *accesskey.Refusal {
	var sorted []string
	if len(names) > 0 {
		sorted = slices.Clone(names)
		slices.Sort(sorted)
		sorted = slices.Compact(sorted)
	}
	return &accesskey.Refusal{Code: code, Names: sorted, Detail: fmt.Sprintf(format, a...)}
}
