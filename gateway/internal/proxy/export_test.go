package proxy

import (
	"time"

	"github.com/qoryai/forager/policy"
)

// SetWait sets how long a connection to l has to send its preamble.
func (l *Listener) SetWait(d time.Duration) { l.wait.Store(int64(d)) }

// StoreRules replaces the mode and the allow list the proxy decides by, with no
// allow_first and no deny list, and closes no connection: what a request reads between
// [Proxy.SetPolicyOpening]'s store of the new rules and its pass over the open tunnels.
func (p *Proxy) StoreRules(mode policy.Mode, allow []string) {
	r := *p.rules.Load()
	r.mode, r.allow, r.first, r.deny = mode, allow, nil, nil
	p.rules.Store(&r)
}
