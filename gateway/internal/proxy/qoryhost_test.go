package proxy_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/qoryai/forager/gateway/internal/proxy"
	"github.com/qoryai/forager/link"
	"github.com/qoryai/forager/policy"
)

// TestTheProxyDeniesTheRoutesHostWhateverThePolicySays pins the proxy's denial of
// link.QoryHost, whose requests a session's forwarder serves: a plain request, one to
// the name with a trailing dot or in upper case, and a CONNECT, under observe and under
// enforce, with the host in allow_first and in the allow list, each get a 403 that
// starts with the fix and are observed denied with the rule wall:qory-host. Nothing is
// dialled.
func TestTheProxyDeniesTheRoutesHostWhateverThePolicySays(t *testing.T) {
	for _, mode := range []policy.Mode{policy.Observe, policy.Enforce} {
		var o observer
		p, err := proxy.Listen("", mode, []string{link.QoryHost, "*.qory.invalid"}, nil, o.observe)
		if err != nil {
			t.Fatal(err)
		}
		p.AllowFirst([]string{link.QoryHost})
		c := through(t, p, nil)
		for _, target := range []string{link.QoryHostURL + "/tests", "http://" + link.QoryHost + "./tests", "http://HOST.QORY.INVALID/tests"} {
			resp, err := c.Get(target)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || !strings.HasPrefix(string(b), "qory: send requests for "+link.QoryHost+" as plain http:// requests to QORY_HOST_URL") {
				t.Errorf("%s under %s: %d %q", target, mode, resp.StatusCode, b)
			}
			if d := o.last(t); d.Allowed || d.Rule != proxy.QoryHostRule || d.Outcome != proxy.Refused || d.Host != link.QoryHost || d.Method != "HTTP" {
				t.Errorf("%s under %s: %+v", target, mode, d)
			}
		}
		if resp, err := c.Get("https://" + link.QoryHost + "/tests"); err == nil {
			resp.Body.Close()
			t.Errorf("a CONNECT under %s opened", mode)
		}
		if d := o.last(t); d.Allowed || d.Rule != proxy.QoryHostRule || d.Outcome != proxy.Refused || d.Method != "CONNECT" {
			t.Errorf("the CONNECT under %s: %+v", mode, d)
		}
		p.Close()
	}
}
