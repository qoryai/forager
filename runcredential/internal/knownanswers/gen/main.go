// Command gen writes the known answers of the run credential into the directory its
// one argument names, as package knownanswers makes them. go generate ./runcredential
// runs it.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/qoryai/forager/runcredential/internal/knownanswers"
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
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
	}
}
