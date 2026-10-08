// Command runtimesjson writes contracts/runner/v1/runtimes.json from the descriptors
// the contract ships. go generate ./contracts runs it with the file's path; a test of
// package descriptor fails while the file in the repository differs from what it
// writes.
package main

import (
	"fmt"
	"os"

	"github.com/qoryai/runner/contracts"
	"github.com/qoryai/runner/session/internal/descriptor"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: runtimesjson <path of runtimes.json>")
		os.Exit(2)
	}
	b, err := descriptor.Runtimes(contracts.FS)
	if err == nil {
		err = os.WriteFile(os.Args[1], b, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "runtimesjson:", err)
		os.Exit(1)
	}
}
