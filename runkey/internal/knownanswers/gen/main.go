// Command gen writes the known answers of a run through a gateway into the directory
// its argument names, as package knownanswers makes them. go generate ./runkey runs
// it.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/qoryai/forager/runkey/internal/knownanswers"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen <directory>")
		os.Exit(2)
	}
	files, err := knownanswers.Files()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(os.Args[1], name), b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
	}
}
