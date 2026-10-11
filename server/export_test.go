package server

import "net/http"

// SetPeerUID sets the user the local link's socket's peer must be, so a test sees the
// link refuse a peer of another user without one.
func SetPeerUID(k *Link, uid int) { k.uid = uid }

// UsesNoProxy reports whether the link's transport has no proxy, of the environment or
// any other.
func UsesNoProxy(k *Link) bool {
	t, ok := k.http.Transport.(*http.Transport)
	return ok && t.Proxy == nil
}
