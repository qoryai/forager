// Package claude is Claude Code as a runtime of Forager: the contract's descriptor
// for it, and the one thing of it that takes code, the claude-settings installer. It
// puts the forwarder into the settings Claude Code reads its hooks from and, for an
// interactive session with the API key's stand-in, pre-approves the stand-in in the
// configuration Claude Code reads, which it otherwise waits for a person to approve.
package claude

import (
	"io/fs"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/session/runtimes"
)

// Name is the runtime's name.
const Name = "claude"

// descriptorPath is the descriptor in the contract.
const descriptorPath = "runtimes/claude/descriptor.yaml"

// New is Claude Code by the contract's descriptor.
func New() (runtimes.Runtime, error) {
	b, err := fs.ReadFile(contracts.FS, descriptorPath)
	if err != nil {
		return nil, err
	}
	return runtimes.Described(descriptorPath, b, map[string]runtimes.Installer{SettingsInstaller: Settings})
}
