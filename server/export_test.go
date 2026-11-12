package server

import (
	"bufio"
	"net/http"
	"strings"
	"time"

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

// SetLinkWaits sets how long the link waits for an answer: each, for every request but
// the run request, and open, for the run request, in place of Timeout and OpenWait.
func SetLinkWaits(k *Link, each, open time.Duration) {
	k.http.Timeout, k.opening.Timeout = each, open
}

// LinkWaits are how long the link waits for an answer: to every request but the run
// request, and to the run request.
func LinkWaits(k *Link) (each, open time.Duration) { return k.http.Timeout, k.opening.Timeout }

// UsesNoProxy reports whether the link's transport has no proxy, of the environment or
// any other.
func UsesNoProxy(k *Link) bool {
	t, ok := k.http.Transport.(*http.Transport)
	return ok && t.Proxy == nil
}
