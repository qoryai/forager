package session

import (
	"context"
	"fmt"

	"github.com/qoryai/forager/accesskey"
	"github.com/qoryai/forager/wall"
)

// relayRestarter is an enclosure whose relay can be removed and started again with a
// new token, which ends a window of unprivileged containers: the Docker wall's.
type relayRestarter interface {
	RestartRelay(ctx context.Context, l wall.Launch) error
}

// openWindow makes every connection of the wall's relay unprivileged, from before a step
// container or an unprivileged setup container starts until [Run.endWindow].
func (r *Run) openWindow() {
	r.wallFwd.mark()
	r.windowed = true
}

// endWindow ends the window of unprivileged containers, when one opened since the last
// end, before a privileged container starts: the agent's for a join, or a setup
// container without Unprivileged. The run's forwarder takes a new hop token and stops
// marking, in one step, so a connection the relay opens with the old token from then on
// is closed; then the wall removes the relay and starts it again with the new token, so
// no byte of the window reaches the proxy unmarked, however late it arrives. After a
// failed restart the window stays open to end: the next call tries again.
func (r *Run) endWindow(ctx context.Context) error {
	if !r.windowed {
		return nil
	}
	restarter, ok := r.enclosure.(relayRestarter)
	if !ok {
		return fmt.Errorf("Close the run: the %s wall cannot start its relay again after the steps.", accesskey.ShownName(r.open.Wall.Name(), false))
	}
	hop, err := newForwarderSecret()
	if err != nil {
		return err
	}
	r.wallFwd.swap(hop)
	r.relayToken = hop
	if err := restarter.RestartRelay(ctx, wall.Launch{Proxy: r.wallFwd.Addr(), ProxyToken: hop, ProxyPeer: r.route != nil}); err != nil {
		return fmt.Errorf("Run the join again, or close the run: the relay did not start again after the steps.\n%w", accesskey.ShownError(err))
	}
	r.windowed = false
	return nil
}
