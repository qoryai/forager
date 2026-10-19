package socket_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/session/internal/descriptor"
	"github.com/qoryai/forager/session/internal/socket"
)

// TestALineThatIsNoRecordPrintsAPhraseForASecret pins the error of a line that is not
// a record: a line that contains qak_ or qrk_ is the phrase, and a clean one prints as
// before, cut at 80 characters.
func TestALineThatIsNoRecordPrintsAPhraseForASecret(t *testing.T) {
	l, err := socket.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var bad []string
	go l.Serve(func(descriptor.Record) {}, func(err error) { mu.Lock(); bad = append(bad, err.Error()); mu.Unlock() })
	long := `{"source":"transcript","record":{"text":"` + strings.Repeat("x", 100) + `"}}`
	conn, err := net.Dial("unix", l.Path())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte(`{"source":"transcript","record":{"key":"qak_x"}}` + "\n" + `{"source":"QRK_y"}` + "\n" + long + "\n"))
	conn.Close()
	want := []string{
		"not a record: (a value that contains an access key secret)",
		"not a record: (a value that contains a run key)",
		"not a record: " + long[:80],
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(bad)
		mu.Unlock()
		if n == len(want) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.Close()
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(bad, "\n") != strings.Join(want, "\n") {
		t.Errorf("bad lines %q, want %q", bad, want)
	}
}

// TestATransportPrintsAPhraseForASecret pins the error of an address whose scheme is
// no transport of the forwarder's: a scheme that contains qak_ or qrk_ is the phrase,
// and a clean one prints as before.
func TestATransportPrintsAPhraseForASecret(t *testing.T) {
	for addr, want := range map[string]string{
		"QRK_y:relay:1": "QORY_RUN_SOCKET names the transport (a value that contains a run key), which this forwarder does not have",
		"tcp:relay:1":   `QORY_RUN_SOCKET names the transport "tcp", which this forwarder does not have`,
	} {
		if err := socket.Forward(context.Background(), addr, strings.NewReader(`{"a":1}`)); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", addr, err, want)
		}
	}
}
