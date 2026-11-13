// Package codex is Codex as a runtime of Forager: the contract's descriptor for it.
// Codex takes no hook, so nothing of it takes code: the session reads its standard
// output, and passes the descriptor's config as --config pairs.
package codex

import (
	"io/fs"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/session/runtimes"
)

// Name is the runtime's name.
const Name = "codex"

// descriptorPath is the descriptor in the contract.
const descriptorPath = "runtimes/codex/descriptor.yaml"

// New is Codex by the contract's descriptor.
func New() (runtimes.Runtime, error) {
	b, err := fs.ReadFile(contracts.FS, descriptorPath)
	if err != nil {
		return nil, err
	}
	return runtimes.Described(descriptorPath, b, nil)
}
