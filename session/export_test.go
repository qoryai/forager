package session

// SetRegisterPause sets what a run calls between its check against the registry of
// walled runs and the writing of its entry, under the registry's lock; nil for nothing.
func SetRegisterPause(f func(runID string)) { registerPause = f }
