package gateway

// dumpable is -1 on macOS, which has no PR_GET_DUMPABLE.
func dumpable() int { return -1 }

// lockedKB is -1 on macOS, which has no VmLck.
func lockedKB() int64 { return -1 }
