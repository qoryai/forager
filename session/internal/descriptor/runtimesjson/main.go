// Command runtimesjson writes contracts/forager/v1/runtimes.json from the descriptors
// the contract ships. go generate ./contracts runs it with the file's path; a test of
// package descriptor fails while the file in the repository differs from what it
// writes.
package main

import (
	"fmt"
	"os"

	"github.com/qoryai/forager/contracts"
	"github.com/qoryai/forager/session/internal/descriptor"
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
