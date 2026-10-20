package gateway

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/qoryai/forager/gateway/internal/routine"
	"github.com/qoryai/forager/policy"
	"github.com/qoryai/forager/server"
)

// TestAReloadThatPanicsLetsTheNextAnswerReload pins that a reload pass that panics is
// reported under the run's id, and that the next answer whose digest differs starts
// another pass: the reload is no longer running once the pass that panicked ended.
func TestAReloadThatPanicsLetsTheNextAnswerReload(t *testing.T) {
	reports := make(chan string, 4)
	// Without a client, a pass panics as it discovers the configuration again.
	l := newLive(context.Background(), nil, &server.Configuration{}, "sha256=start", "run-a", func(line string) { reports <- line })
	defer l.stop()
	l.start(func(*policy.Loaded) error { return nil })
	for i := range 2 {
		l.digests(server.Digests{Configuration: fmt.Sprintf("sha256=%d", i)})
		select {
		case got := <-reports:
			if first, _, _ := strings.Cut(got, "\n"); first != "run run-a: "+routine.Panicked {
				t.Errorf("answer %d: the report's first line is %q", i, first)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("answer %d started no reload pass", i)
		}
	}
}
