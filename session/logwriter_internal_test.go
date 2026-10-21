package session

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qoryai/forager/mask"
	"github.com/qoryai/forager/session/internal/chunk"
)

// fakeProxyPassword stands in for a forwarder's password; it is no real one.
const fakeProxyPassword = "fakeproxypasswordforthisexampleonly01234567"

// chunks is what a stream's log emitted, chunk by chunk.
type chunks struct {
	mu  sync.Mutex
	got []string
}

func (c *chunks) emit(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, string(b))
}

// TestTheLogWriterMasksAPasswordAtEverySplit writes a proxy URL with the fake password
// in two writes, split at every place of the password: on pipes; on a terminal with a
// pause longer than the gap between the writes; and on a terminal cut between them, as
// a resize cuts it. No chunk contains the password, and the chunks joined are the URL
// with qory-proxy-password.
func TestTheLogWriterMasksAPasswordAtEverySplit(t *testing.T) {
	const before, after = "HTTP_PROXY=http://qory:", "@127.0.0.1:41853\n"
	input := before + fakeProxyPassword + after
	want := before + mask.ProxyPassword + after
	for _, way := range []string{"pipes", "terminal", "resize"} {
		for i := 0; i <= len(fakeProxyPassword); i++ {
			t.Run(fmt.Sprintf("%s %d", way, i), func(t *testing.T) {
				t.Parallel()
				c := &chunks{}
				p := &process{logs: func(string) func([]byte) { return c.emit }, masker: mask.Proxy(proxyUser, fakeProxyPassword)}
				l := p.logWriter("stream", way != "pipes")
				at := len(before) + i
				l.Write([]byte(input[:at]))
				switch way {
				case "terminal":
					time.Sleep(chunk.Gap + 30*time.Millisecond)
				case "resize":
					l.cut()
				}
				l.Write([]byte(input[at:]))
				l.Flush()
				c.mu.Lock()
				defer c.mu.Unlock()
				for _, g := range c.got {
					if strings.Contains(g, fakeProxyPassword) {
						t.Errorf("a chunk contains the password: %q", g)
					}
				}
				if got := strings.Join(c.got, ""); got != want {
					t.Errorf("the chunks %q, want %q", c.got, want)
				}
			})
		}
	}
}

// TestARecordIsMaskedAtEveryDepth pins the strings of an output or hook record's
// event: a value, a key, and a string inside a list and a map; every other value is
// as it was, and the record's maps are left as they were.
func TestARecordIsMaskedAtEveryDepth(t *testing.T) {
	m := mask.Proxy(proxyUser, fakeProxyPassword)
	inner := map[string]any{"env": "HTTP_PROXY=http://qory:" + fakeProxyPassword + "@127.0.0.1:1"}
	data := map[string]any{
		"result":          fakeProxyPassword,
		fakeProxyPassword: true,
		"list":            []any{"a " + fakeProxyPassword, 1.5, nil},
		"tool":            inner,
	}
	got := fmt.Sprint(maskedRecord(m, data))
	want := fmt.Sprint(map[string]any{
		"result":           mask.ProxyPassword,
		mask.ProxyPassword: true,
		"list":             []any{"a " + mask.ProxyPassword, 1.5, nil},
		"tool":             map[string]any{"env": "HTTP_PROXY=http://qory:" + mask.ProxyPassword + "@127.0.0.1:1"},
	})
	if got != want {
		t.Errorf("the masked record %s, want %s", got, want)
	}
	if !strings.Contains(inner["env"].(string), fakeProxyPassword) {
		t.Error("the record's map was changed")
	}
	if maskedRecord(nil, data)["result"] != fakeProxyPassword {
		t.Error("a nil masker changed the record")
	}
}
