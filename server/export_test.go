package server

import "time"

// SetPeerUID sets the user the local link's socket's peer must be, so a test sees the
// link refuse a peer of another user without one.
func SetPeerUID(k *Link, uid int) { k.uid = uid }

// SetOutcomeTimeout sets how long the outcome request waits, so a test sees the bound
// without waiting OutcomeTimeout; it returns a function that puts the default back.
func SetOutcomeTimeout(d time.Duration) func() {
	outcomeTimeout = d
	return func() { outcomeTimeout = OutcomeTimeout }
}
