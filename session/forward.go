package session

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/qoryai/runner/session/internal/socket"
)

// Forward is the hook forwarder: it reads one JSON object from r, the hook's input,
// and sends it to the socket named by QORY_RUN_SOCKET in the environment as one record
// of the hooks source. The command the session installs as a hook calls it and exits 0
// with no output whatever happened, so the runtime never sees a decision; an error is
// for the command's own log. No socket in the environment is an error.
func Forward(ctx context.Context, r io.Reader) error {
	path := os.Getenv(EnvSocket)
	if path == "" {
		return errors.New(EnvSocket + " is not set; not running under qory run")
	}
	return socket.Forward(ctx, path, r)
}
