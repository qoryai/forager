package socket_test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/session/internal/socket"
)

// TestAForwardPrintsAPhraseForASecretInTheSocket pins the error of a hook's forward to
// a socket whose path contains qrk_: a phrase, the *net.OpError still found by
// errors.As.
func TestAForwardPrintsAPhraseForASecretInTheSocket(t *testing.T) {
	err := socket.Forward(context.Background(), filepath.Join(t.TempDir(), "qrk_FAKE", "sock"), strings.NewReader(`{"a":1}`))
	if err == nil {
		t.Fatal("a forward to a missing socket succeeded")
	}
	if strings.Contains(strings.ToLower(err.Error()), "qrk_") {
		t.Errorf("the forward's error %v contains the prefix", err)
	}
	if oe := (*net.OpError)(nil); !errors.As(err, &oe) {
		t.Errorf("the forward's error %v does not wrap a *net.OpError", err)
	}
}
