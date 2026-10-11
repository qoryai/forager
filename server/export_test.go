package server

// SetPeerUID sets the user the local link's socket's peer must be, so a test sees the
// link refuse a peer of another user without one.
func SetPeerUID(k *Link, uid int) { k.uid = uid }
