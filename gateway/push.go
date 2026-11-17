package gateway

import (
	"fmt"
	"slices"

	"github.com/qoryai/forager/event"
	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/gateway/internal/run"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/server"
)

// openPush makes the run's push proxy, for qory's push and the calls of its submit step,
// when the run configuration has a push credential ([run.Run.HasPush]); a run without
// one has none, and its run answer no push_proxy_secret. The push proxy is in enforce
// mode and allows the hosts of the push credentials' items alone, with no policy of the
// run's and no model key, at the run's limits with counters apart from the run's proxy.
// It ends TLS for those hosts with ca, the run's authority, sets each push credential on
// the paths of its items, with the branch guard of each item's push_ref, and returns a
// 403 for every other path of those hosts. It reports the pushes it passes as the
// run's proxy does ([proxy.Proxy.ObserveWrites]). Each decision is a
// dev.qory.run.egress with channel push ([pushEgress]). When guarded is true it is
// guarded as the run's proxy is, and a reload sets its guard's names as it sets the run's
// proxy's. It stays open until [linkRun.release] closes it at the run's end: qory pushes
// after each session. On the local link it is registered under a fresh
// secret, the run answer's push_proxy_secret, which no other proxy has; on the one
// address the run key opens it, after [link.PushPreamble].
func (lr *linkRun) openPush(guarded bool, ca *proxy.CA) error {
	if !lr.r.HasPush() {
		return nil
	}
	if ca == nil {
		return fmt.Errorf("Start a new run: the push proxy needs the run's certificate authority.\nRun %s has none.", lr.id)
	}
	uses := lr.r.PushUses()
	var hosts []string
	paths := map[string][]string{}
	for _, u := range uses {
		for _, h := range u.Hosts {
			if !slices.Contains(hosts, h) {
				hosts = append(hosts, h)
			}
			if u.Paths == nil {
				// An item without paths is alone on its hosts ([run.Run.checkPush]).
				paths[h] = append(paths[h], "/*")
				continue
			}
			paths[h] = append(paths[h], u.Paths...)
		}
	}
	px, err := proxy.New(policy.Enforce, hosts, nil, func(d proxy.Decision) { lr.st.Emit(event.RunEgress, pushEgress(d)) })
	if err != nil {
		return err
	}
	px.ReportPanics(routine.ForRun(lr.g.report, lr.id))
	if lr.g.cfg.upstreamRoots != nil {
		px.TrustUpstream(lr.g.cfg.upstreamRoots)
	}
	px.Terminate(ca, uses, paths, nil)
	if lr.writes != nil {
		px.ObserveWrites(lr.writes.observe)
	}
	px.SetLimits(proxy.Limits{Connections: lr.g.cfg.RunLimits.Connections, RequestsPerSecond: lr.g.cfg.RunLimits.RequestsPerSecond, Burst: lr.g.cfg.RunLimits.Burst})
	px.Unlisted(pushUnlisted)
	px.PathRefused(pushPathRefused)
	if guarded {
		px.Guard(lr.r.GuardNames())
	}
	lr.mu.Lock()
	lr.push = px
	lr.mu.Unlock()
	if lr.remote {
		return nil
	}
	secret, err := proxy.NewSecret()
	if err != nil {
		return err
	}
	lr.mu.Lock()
	lr.pushSecret = newSecretValue(secret)
	lr.mu.Unlock()
	return lr.g.proxies.Register(secret, px)
}

// pushProxy is the run's push proxy, nil for a run with no push credential and once
// [linkRun.closePush] closed it.
func (lr *linkRun) pushProxy() *proxy.Proxy {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return lr.push
}

// closePush closes the run's push proxy, once, at the run's end: it unregisters the
// secret, which opens nothing from then on, clears it, and closes every connection
// through the push proxy.
func (lr *linkRun) closePush() {
	lr.mu.Lock()
	px, secret := lr.push, lr.pushSecret
	lr.push, lr.pushSecret = nil, nil
	lr.mu.Unlock()
	if secret != nil {
		lr.g.proxies.Unregister(secret.reveal())
	}
	if px != nil {
		px.Close()
	}
}

// pushEgress is the data of the dev.qory.run.egress of one decision of a run's push
// proxy: [run.Egress] with channel push.
func pushEgress(d proxy.Decision) map[string]any {
	data := run.Egress(d)
	data["channel"] = "push"
	return data
}

// pushUnlisted is the body of the 403 a run's push proxy returns for a host that no
// push credential's item is for.
func pushUnlisted(host string, port int) string {
	return fmt.Sprintf("qory: send only the push and its pull request calls through the push proxy.\n"+
		"qory: egress to %s:%d denied by the gateway: no push credential of the run is for this host\n", host, port)
}

// pushPathRefused is the body of the 403 a run's push proxy returns for a request on a
// push credential's host whose path no item of a push credential covers.
func pushPathRefused(method, host, path string) string {
	return fmt.Sprintf("qory: send only the push and its pull request calls through the push proxy.\n"+
		"qory: %s %s%s denied by the gateway: no push credential of the run covers this path\n", method, host, path)
}

// pushApplied are the entries of dev.qory.run.policy_applied's credentials of the run
// configuration's push credentials, from uses, [run.Run.PushUses], in JSON's types as
// appliedOf's: one per item, with its hosts, scheme and paths and purpose push.
func pushApplied(uses []proxy.Credential) []any {
	var out []any
	for _, u := range uses {
		out = append(out, appliedItem(u, server.PurposePush))
	}
	return out
}
