//go:build !linux

package gateway

import (
	"fmt"
	"runtime"
)

// lockAll refuses: Forager locks the gateway's memory on Linux alone.
func lockAll() error {
	return fmt.Errorf("set gateway.lock_memory to false: Forager locks memory only on Linux, and this system is %s", runtime.GOOS)
}
