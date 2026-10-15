package accesskey

// InstanceIDOf returns the instance id [NewInstanceID] makes of the 16 bytes b.
func InstanceIDOf(b []byte) string { return instanceID(b) }
