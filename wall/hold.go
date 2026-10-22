package wall

import "context"

// Hold is the program the setup container runs: it keeps the container running, so the
// services that the setup commands start keep running, until ctx ends. The caller's
// binary runs it in a hidden mode, [Docker.HoldArgs], as it runs [Relay], with a
// context that ends at the signal that stops the container, SIGTERM, or at SIGINT. It
// returns nil.
func Hold(ctx context.Context) error {
	<-ctx.Done()
	return nil
}
