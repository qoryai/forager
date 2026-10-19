//go:build !linux && !darwin

package gateway

// denyDumps does nothing on a system other than Linux and macOS: Forager makes none of
// their calls there, and the gateway's process may be dumped and debugged.
func denyDumps() error { return nil }
