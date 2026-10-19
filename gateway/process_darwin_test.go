package gateway

// dumpable is -1 on macOS, which has no PR_GET_DUMPABLE.
func dumpable() int { return -1 }

// statusField is -1 on macOS, which has no /proc/self/status.
func statusField(string) int64 { return -1 }
