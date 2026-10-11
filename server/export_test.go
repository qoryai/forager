package server

import (
	"bufio"
	"net/http"
	"strings"

	"github.com/qoryai/forager/accesskey"
)

// BindingAccepted reports whether the session behind a separate gateway whose run key
// names keys accepts line as the gateway's answer to the binding on a connection whose
// exporter value is ekm.
func BindingAccepted(keys []accesskey.PublicKey, ekm []byte, line string) bool {
	g := &remoteGateway{keys: keys}
	return g.bound(bufio.NewReader(strings.NewReader(line)), ekm)
}

// LinkAnswerAccepted reports whether that session accepts an answer of status, body
// and digests, with signatures, to req, whose body is reqBody, on a connection whose
// exporter value is ekm.
func LinkAnswerAccepted(keys []accesskey.PublicKey, ekm []byte, req *http.Request, reqBody []byte, status int, body []byte, digests Digests, signatures []string) bool {
	g := &remoteGateway{keys: keys}
	return g.signed(&boundConn{ekm: ekm}, req, reqBody, &linkAnswer{status: status, body: body, digests: digests}, signatures)
}

// SetPeerUID sets the user the local link's socket's peer must be, so a test sees the
// link refuse a peer of another user without one.
func SetPeerUID(k *Link, uid int) { k.uid = uid }

// UsesNoProxy reports whether the link's transport has no proxy, of the environment or
// any other.
func UsesNoProxy(k *Link) bool {
	t, ok := k.http.Transport.(*http.Transport)
	return ok && t.Proxy == nil
}
