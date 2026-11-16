//go:build !linux

package e2e

import (
	"fmt"
	"os"
)

// afterInspect is [modeAfterInspect]'s program; it runs in After's container, which is
// Linux.
func afterInspect() int {
	fmt.Fprintln(os.Stderr, "after-inspect: runs on Linux only")
	return 1
}
