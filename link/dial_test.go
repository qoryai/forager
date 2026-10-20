package link_test

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qoryai/forager/link"
)

// TestALocalDialPrintsAPhraseForASecretInTheSocket pins the error of a dial to a
// socket whose path contains qak_: a phrase, the *net.OpError still found by
// errors.As.
func TestALocalDialPrintsAPhraseForASecretInTheSocket(t *testing.T) {
	_, err := link.Local{Socket: filepath.Join(t.TempDir(), "qak_FAKE", "sock")}.DialContext(context.Background())
	if err == nil {
		t.Fatal("a dial to a missing socket succeeded")
	}
	if strings.Contains(strings.ToLower(err.Error()), "qak_") {
		t.Errorf("the dial's error %v contains the prefix", err)
	}
	if oe := (*net.OpError)(nil); !errors.As(err, &oe) {
		t.Errorf("the dial's error %v does not wrap a *net.OpError", err)
	}
}
