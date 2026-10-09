// Package refusal is a run Forager refuses before it starts, with the refusal code
// of the contract, contracts/forager/v1, that says why, and the names it concerns.
//
// A refusal is an [*accesskey.Refusal], the type of every refused run, the server's
// codes included. Its Detail reads as a sentence for the caller's user and contains
// names alone: a variable's name, a tool's, an image's, never a value.
//
// It also holds the codes a gateway that verifies a run credential decides, which
// Forager does not: a session reads them from the gateway's answer on the link,
// unsigned and authenticated by the transport, as it reads the server's refusal from
// the server's signed answer.
package refusal

import (
	"fmt"
	"slices"

	"github.com/qoryai/forager/accesskey"
)

// The codes Forager decides.
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
	// inside one of Forager's files: its names are the mount and the file, in that
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
	// EngineUnreachable is a walled run that cannot check with the container engine
	// whether an earlier walled run, whose session is gone, still has containers: its
	// names are the earlier run's id and the path of its entry in the registry.
	EngineUnreachable = "engine_unreachable"
)

// Decides reports whether Forager decides the code, one of this package's: a
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

// The codes a gateway that verifies a run credential, the one an issuer gives a run,
// decides.
const (
	// RunCredentialRefused is a run credential the gateway refuses, for any reason, and
	// a run key that already opened a run at this gateway: one opaque answer, with no
	// names.
	RunCredentialRefused = "run_credential_refused"
	// TargetDiffersFromCredential is a session whose label forge or repository, the
	// ones qory takes from the checkout, differs from the run credential's: its names
	// are each such member and the credential's value, labels.<key>=<value>.
	TargetDiffersFromCredential = "target_differs_from_credential"
	// DiffersFromCredential is a session that sends any other key the run credential
	// decides, a label or an about.details key, with another value: its names are each
	// such member and the credential's value, labels.<key>=<value> or
	// about.details.<key>=<value>.
	DiffersFromCredential = "differs_from_credential"
	// RunIDUsed is a run configuration request whose run_id already names a run at this
	// gateway: the session chooses the run id, and the gateway takes only an unused
	// one. It has no names. A run_id that is not a canonical lower-case UUID is
	// invalid_request.
	RunIDUsed = "run_id_used"
)

// GatewayDecides reports whether a gateway that verifies a run credential decides the
// code, one of this package's: a refusal of the run credential or of what the session
// sends beside it. Forager decides none of these, so [Decides] reports false for each.
func GatewayDecides(code string) bool {
	switch code {
	case RunCredentialRefused, TargetDiffersFromCredential, DiffersFromCredential, RunIDUsed:
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
