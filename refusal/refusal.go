// Package refusal is a run the runner refuses before it starts, with the refusal code
// of the contract, contracts/forager/v1, that says why, and the names it concerns.
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
	// MountContainsForagerFiles is a walled run with a mount that is, contains or lies
	// inside one of the runner's files: its names are the mount and the file, in that
	// order.
	MountContainsForagerFiles = "mount_contains_forager_files"
	// MountModeConflict is a walled run with a mount, or the workspace, inside another
	// one, or the same, of the other mode, writable or read-only: its names are the
	// inner and the outer, in that order.
	MountModeConflict = "mount_mode_conflict"
	// MountSharedWithRun is a walled run with a bind inside, or reached through, a
	// writable bind of another walled run of this user's still going, a writable bind
	// that holds one of that run's binds or the way to one, a bind that is, holds or
	// lies inside that run's run directory, or one that lies inside a writable directory
	// that run's wall binds of its own: its names are this run's path, the other run's
	// id and its path.
	MountSharedWithRun = "mount_shared_with_run"
	// MountThroughLink is a walled run with a mount, or the workspace, whose path goes
	// through a link inside another of its places and does not resolve into that place:
	// its names are the place, the link and the other place, the place and the other
	// one as passed.
	MountThroughLink = "mount_through_link"
	// EngineUnreachable is a walled run that cannot ask the container engine whether
	// an earlier walled run, whose runner is gone, still has containers: its names are
	// the earlier run's id and the path of its entry in the registry.
	EngineUnreachable = "engine_unreachable"
)

// Decides reports whether the runner decides the code, one of this package's: a
// refusal of the run's own configuration rather than of an answer of the server's.
func Decides(code string) bool {
	switch code {
	case RunConfigurationInvalid, ToolUnknown, ImageUnknown, VariableReserved,
		PlaceholderConflict, MountContainsForagerFiles, MountModeConflict, MountSharedWithRun,
		MountThroughLink, EngineUnreachable:
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
